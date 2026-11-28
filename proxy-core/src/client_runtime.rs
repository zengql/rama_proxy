use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rama::{
    bytes::BytesMut,
    net::{address::HostWithPort, user::credentials::Basic},
    proxy::socks5::proto::{Command, ReplyKind, SocksMethod, client, server, udp::UdpHeader},
    utils::str::NonEmptyStr,
};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpStream, UdpSocket},
};
use tracing::{debug, info, warn};

use crate::{
    config::{ClientConfigFile, UserConfig},
    error::AppError,
    local_listener::bind_local_listener,
    tls::build_client_tls_context,
    tunnel::{
        TunnelPool, TunnelPoolSnapshot, opcode_is_close, opcode_is_ping, opcode_is_pong,
        opcode_is_udp_packet, read_opcode, read_response, read_response_message, read_udp_packet,
        resolve_client_id, run_heartbeat, write_close, write_open_connect, write_open_udp,
        write_ping, write_pong, write_udp_packet,
    },
};

const SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const TUNNEL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
const TUNNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(5);
/// Close idle TCP relay streams after this long with zero data transfer in either
/// direction so abandoned HTTP keep-alive sockets do not hold tunnel leases indefinitely.
const TCP_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(3 * 60);
static NEXT_HEARTBEAT_ID: AtomicU64 = AtomicU64::new(1_000_000);

pub async fn run(config: ClientConfigFile) -> Result<(), AppError> {
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    run_with_shutdown(config, shutdown_rx).await
}

/// Runs the local SOCKS5 client service until `shutdown` receives `true` or
/// its sender is dropped. This entry point is intended for embedded clients
/// such as the Tauri mobile application.
pub async fn run_with_shutdown(
    config: ClientConfigFile,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), AppError> {
    run_with_shutdown_ready(config, shutdown, None).await
}

/// Like [`run_with_shutdown`], but reports the bound SOCKS5 address once all
/// startup work has completed. The caller can use this to avoid exposing a
/// running state before the port is actually available.
pub async fn run_with_shutdown_ready(
    config: ClientConfigFile,
    shutdown: tokio::sync::watch::Receiver<bool>,
    ready: Option<tokio::sync::oneshot::Sender<Result<SocketAddr, String>>>,
) -> Result<(), AppError> {
    run_with_shutdown_ready_and_pool_stats(config, shutdown, ready, None).await
}

/// Like [`run_with_shutdown_ready`], and periodically publishes a tunnel pool
/// snapshot for embedded clients that expose diagnostics in their UI.
pub async fn run_with_shutdown_ready_and_pool_stats(
    config: ClientConfigFile,
    shutdown: tokio::sync::watch::Receiver<bool>,
    ready: Option<tokio::sync::oneshot::Sender<Result<SocketAddr, String>>>,
    pool_stats: Option<tokio::sync::watch::Sender<Option<TunnelPoolSnapshot>>>,
) -> Result<(), AppError> {
    run_with_shutdown_ready_pool_stats_and_network_events(config, shutdown, ready, pool_stats, None)
        .await
}

/// Like [`run_with_shutdown_ready_and_pool_stats`], and accepts an optional
/// notification handle that the host OS can trigger whenever network connectivity
/// becomes available or switches interfaces.
pub async fn run_with_shutdown_ready_pool_stats_and_network_events(
    config: ClientConfigFile,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    ready: Option<tokio::sync::oneshot::Sender<Result<SocketAddr, String>>>,
    pool_stats: Option<tokio::sync::watch::Sender<Option<TunnelPoolSnapshot>>>,
    network_events: Option<std::sync::Arc<tokio::sync::Notify>>,
) -> Result<(), AppError> {
    let prepared = async {
        let bind_ip = parse_bind_ip(&config.socks5.bind)?;
        let listen_addr = SocketAddr::new(bind_ip, config.socks5.port);
        let listener = bind_local_listener(listen_addr)?;
        let tls = build_client_tls_context(&config.tls)?;
        let pool = TunnelPool::new(&config.client, tls)?;
        Ok::<_, AppError>((listen_addr, listener, pool))
    }
    .await;

    let (listen_addr, listener, pool, ready) = match prepared {
        Ok((listen_addr, listener, pool)) => (listen_addr, listener, pool, ready),
        Err(err) => {
            if let Some(ready) = ready {
                let _ = ready.send(Err(err.to_string()));
            }
            return Err(err);
        }
    };

    let maintainer = pool.spawn_maintainer();
    let mut heartbeat_enabled = pool.subscribe_heartbeat_enabled();
    let network_listener = network_events.clone().map(|events| {
        let pool = pool.clone();
        tokio::spawn(async move {
            loop {
                events.notified().await;
                if !pool.is_dormant() {
                    info!(
                        "host network connectivity change notified; probing and refilling tunnel pool"
                    );
                }
                pool.notify_network_available().await;
            }
        })
    });
    let stats_sender = pool_stats.clone();
    let stats_task = pool_stats.map(|sender| {
        let pool = pool.clone();
        let notify = pool.state_notify();
        tokio::spawn(async move {
            loop {
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                let snapshot = pool.snapshot().await;
                let is_active = snapshot.active > 0;
                let has_recent_traffic = snapshot.last_traffic_age_secs.is_some_and(|age| age < 12);
                let has_backoff = snapshot.next_refill_allowed_in_secs.is_some();
                sender.send_if_modified(|current| {
                    if current.as_ref() != Some(&snapshot) {
                        *current = Some(snapshot);
                        true
                    } else {
                        false
                    }
                });
                // Event-driven wakeup on tunnel state changes, with a low-power fallback timer:
                // - 2s while traffic is actively flowing or cooling down (10s lock window)
                // - 5s during refill backoff so countdown UI updates
                // - None (purely event-driven) once idle so the runtime stays dormant
                let interval = if is_active || has_recent_traffic {
                    Some(Duration::from_secs(2))
                } else if has_backoff {
                    Some(Duration::from_secs(5))
                } else {
                    None
                };
                match interval {
                    Some(interval) => {
                        tokio::select! {
                            _ = &mut notified => {}
                            _ = tokio::time::sleep(interval) => {}
                        }
                    }
                    None => {
                        notified.await;
                    }
                }
            }
        })
    });
    let heartbeat_config = config.clone();
    let heartbeat_network_events = network_events;
    let heartbeat = tokio::spawn(async move {
        if heartbeat_config.client.heartbeat_interval_secs == 0 {
            debug!("client heartbeat channel is disabled (heartbeat_interval_secs = 0)");
            return;
        }
        let server_addr = match heartbeat_config.client.server_addr.parse() {
            Ok(addr) => addr,
            Err(err) => {
                warn!(error = %err, "heartbeat server address is invalid");
                return;
            }
        };
        loop {
            while !*heartbeat_enabled.borrow_and_update() {
                if heartbeat_enabled.changed().await.is_err() {
                    return;
                }
            }
            let tls_config = heartbeat_config.tls.clone();
            let client_config = heartbeat_config.client.clone();
            let network_events = heartbeat_network_events.clone();
            let run_loop = async {
                let mut consecutive_failures = 0u32;
                loop {
                    let started = Instant::now();
                    let result = match build_client_tls_context(&tls_config) {
                        Ok(tls) => {
                            run_heartbeat(
                                server_addr,
                                &client_config.shared_secret,
                                &resolve_client_id(&client_config.client_id),
                                Duration::from_secs(client_config.connect_timeout_secs.max(1)),
                                tls,
                                NEXT_HEARTBEAT_ID.fetch_add(1, Ordering::Relaxed),
                                // The server pushes one heartbeat per interval, so waiting only
                                // `heartbeat_timeout_secs` between pushes would drop and redial the
                                // channel every cycle. Allow a full interval plus the timeout.
                                Duration::from_secs(
                                    client_config.heartbeat_interval_secs.max(1)
                                        + client_config.heartbeat_timeout_secs.max(1),
                                ),
                            )
                            .await
                        }
                        Err(err) => Err(err),
                    };
                    if started.elapsed() >= Duration::from_secs(30) {
                        consecutive_failures = 0;
                    }
                    match result {
                        Ok(()) => {
                            consecutive_failures = 0;
                        }
                        Err(err) => {
                            consecutive_failures = consecutive_failures.saturating_add(1);
                            let shift = consecutive_failures.saturating_sub(1).min(5);
                            let retry_secs = (10u64 << shift).min(300);
                            warn!(
                                error = %err,
                                consecutive_failures,
                                retry_secs,
                                "heartbeat channel unavailable; backing off before retry"
                            );
                            if let Some(events) = network_events.as_ref() {
                                tokio::select! {
                                    _ = tokio::time::sleep(Duration::from_secs(retry_secs)) => {}
                                    _ = events.notified() => {
                                        consecutive_failures = 0;
                                    }
                                }
                            } else {
                                tokio::time::sleep(Duration::from_secs(retry_secs)).await;
                            }
                        }
                    }
                }
            };
            tokio::select! {
                _ = run_loop => {}
                changed = async {
                    loop {
                        if heartbeat_enabled.changed().await.is_err() {
                            return false;
                        }
                        if !*heartbeat_enabled.borrow_and_update() {
                            return true;
                        }
                    }
                } => {
                    if !changed {
                        return;
                    }
                    debug!("heartbeat channel suspended during dormancy");
                }
            }
        }
    });

    info!(
        bind = %listen_addr,
        server_addr = %config.client.server_addr,
        udp_enabled = config.udp.enabled,
        pool_size = config.client.pool_size,
        tls_enabled = config.tls.enabled,
        "client socks5 listener started"
    );

    tokio::task::yield_now().await;
    if let Some(ready) = ready {
        let _ = ready.send(Ok(listen_addr));
    }

    let mut sessions = tokio::task::JoinSet::new();
    let result = loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if !*shutdown.borrow() => continue,
                    _ => break Ok(()),
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(connection) => connection,
                    Err(err) => break Err(AppError::from(err)),
                };
                let socket = socket2::SockRef::from(&stream);
                let keepalive = socket2::TcpKeepalive::new()
                    .with_time(Duration::from_secs(config.socks5.tcp_keepalive_secs.max(1)));
                if let Err(err) = socket.set_tcp_keepalive(&keepalive) {
                    warn!(client = %peer, error = %err, "failed to configure socks5 keepalive");
                }
                let config = config.clone();
                let pool = pool.clone();
                sessions.spawn(async move {
                    if let Err(err) = handle_client(stream, peer, &config, &pool).await {
                        warn!(client = %peer, error = %err, "local socks5 session ended with error");
                    }
                });
            }
            joined = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(err)) = joined {
                    warn!(error = %err, "local socks5 session task failed");
                }
            }
        }
    };

    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
    maintainer.abort();
    heartbeat.abort();
    if let Some(network_listener) = network_listener {
        network_listener.abort();
        let _ = network_listener.await;
    }
    if let Some(stats_task) = stats_task {
        stats_task.abort();
        let _ = stats_task.await;
    }
    let _ = maintainer.await;
    let _ = heartbeat.await;
    if let Some(sender) = stats_sender {
        let _ = sender.send(None);
    }
    info!(bind = %listen_addr, "client socks5 listener stopped");
    result
}

async fn handle_client(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: &ClientConfigFile,
    pool: &TunnelPool,
) -> Result<(), AppError> {
    stream.set_nodelay(true)?;
    debug!(client = %peer, "accepted local socks5 session");

    let header = tokio::time::timeout(
        SOCKS_HANDSHAKE_TIMEOUT,
        client::Header::read_from(&mut stream),
    )
    .await
    .map_err(|_| AppError::Boxed(format!("read socks5 header timed out for {peer}")))?
    .map_err(|err| AppError::Boxed(format!("read socks5 header failed: {err}")))?;

    let method = negotiate_method(&header, config)?;
    server::Header::new(method).write_to(&mut stream).await?;

    if method == SocksMethod::NoAcceptableMethods {
        return Err(AppError::InvalidConfig(format!(
            "client does not support configured auth method: {peer}"
        )));
    }

    if method == SocksMethod::UsernamePassword {
        tokio::time::timeout(SOCKS_HANDSHAKE_TIMEOUT, authorize_user(&mut stream, config))
            .await
            .map_err(|_| {
                AppError::Boxed(format!("authorize socks5 user timed out for {peer}"))
            })??;
    }

    let request = tokio::time::timeout(
        SOCKS_HANDSHAKE_TIMEOUT,
        client::Request::read_from(&mut stream),
    )
    .await
    .map_err(|_| AppError::Boxed(format!("read socks5 request timed out for {peer}")))?
    .map_err(|err| AppError::Boxed(format!("read socks5 request failed: {err}")))?;
    debug!(client = %peer, command = ?request.command, destination = %request.destination, "received socks5 request");

    match request.command {
        Command::Connect => serve_connect(stream, peer, request.destination, pool).await,
        Command::UdpAssociate => {
            if !config.udp.enabled {
                server::Reply::error_reply(ReplyKind::CommandNotSupported)
                    .write_to(&mut stream)
                    .await?;
                return Err(AppError::InvalidConfig("udp relay is disabled".to_string()));
            }
            serve_udp_associate(stream, peer, config, pool).await
        }
        _ => {
            server::Reply::error_reply(ReplyKind::CommandNotSupported)
                .write_to(&mut stream)
                .await?;
            Err(AppError::InvalidConfig(format!(
                "unsupported socks5 command from {peer}: {:?}",
                request.command
            )))
        }
    }
}

fn negotiate_method(
    header: &client::Header,
    config: &ClientConfigFile,
) -> Result<SocksMethod, AppError> {
    let wants_password = config.auth.mode == "password";
    let method = if wants_password {
        if header.methods.contains(&SocksMethod::UsernamePassword) {
            SocksMethod::UsernamePassword
        } else {
            SocksMethod::NoAcceptableMethods
        }
    } else if header
        .methods
        .contains(&SocksMethod::NoAuthenticationRequired)
    {
        SocksMethod::NoAuthenticationRequired
    } else {
        SocksMethod::NoAcceptableMethods
    };
    Ok(method)
}

async fn authorize_user(stream: &mut TcpStream, config: &ClientConfigFile) -> Result<(), AppError> {
    let request = client::UsernamePasswordRequest::read_from(stream)
        .await
        .map_err(|err| AppError::Boxed(format!("read socks5 auth request failed: {err}")))?;
    let authorized = config.auth.users.iter().any(|user| {
        request.basic.username() == user.username.as_str()
            && request
                .basic
                .password()
                .map(|password| password == user.password.as_str())
                .unwrap_or(false)
    });

    if authorized {
        server::UsernamePasswordResponse::new_success()
            .write_to(stream)
            .await?;
        Ok(())
    } else {
        server::UsernamePasswordResponse::new_invalid_credentails()
            .write_to(stream)
            .await?;
        Err(AppError::InvalidConfig(
            "invalid local socks5 credentials".to_string(),
        ))
    }
}

async fn serve_connect(
    mut stream: TcpStream,
    peer: SocketAddr,
    destination: HostWithPort,
    pool: &TunnelPool,
) -> Result<(), AppError> {
    let started = Instant::now();
    let mut tunnel = tokio::time::timeout(TUNNEL_ACQUIRE_TIMEOUT, pool.acquire())
        .await
        .map_err(|_| AppError::Boxed(format!("acquire tunnel timed out for {peer} -> {destination}")))
        .and_then(|result| result)
        .inspect_err(|err| {
            warn!(target = %destination, acquire_ms = started.elapsed().as_millis() as u64, error = %err, "SOCKS5 tunnel acquire failed");
        })?;
    let acquire_ms = started.elapsed().as_millis() as u64;
    let (tunnel_id, source) = tunnel.log_context();
    let open_started = Instant::now();
    write_open_connect(&mut tunnel, &destination).await.inspect_err(|err| {
        warn!(target = %destination, tunnel_id, pool = source, acquire_ms, open_ms = open_started.elapsed().as_millis() as u64, error = %err, "SOCKS5 CONNECT write failed");
    })?;
    let response =
        tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, read_response_message(&mut tunnel)).await;
    let open_ms = open_started.elapsed().as_millis() as u64;
    let total_ms = started.elapsed().as_millis() as u64;
    let message = match response {
        Ok(Ok(message)) => message,
        Ok(Err(err)) => {
            warn!(target = %destination, tunnel_id, pool = source, acquire_ms, open_ms, total_ms, error = %err, "SOCKS5 CONNECT rejected");
            server::Reply::error_reply(ReplyKind::GeneralServerFailure)
                .write_to(&mut stream)
                .await?;
            return Err(err);
        }
        Err(_) => {
            warn!(target = %destination, tunnel_id, pool = source, acquire_ms, open_ms, total_ms, "SOCKS5 CONNECT timed out");
            return Err(AppError::Boxed(format!(
                "tunnel CONNECT timed out for {peer} -> {destination}"
            )));
        }
    };
    let mut server_connection_id = None;
    let mut target_dial_ms = None;
    for field in message.split_ascii_whitespace() {
        if let Some(id) = field.strip_prefix("id=") {
            server_connection_id = id.parse::<u64>().ok();
        } else if let Some(ms) = field.strip_prefix("dial_ms=") {
            target_dial_ms = ms.parse::<u64>().ok();
        }
    }
    info!(target = %destination, tunnel_id, pool = source, acquire_ms, open_ms, target_dial_ms, server_connection_id, total_ms, "SOCKS5 CONNECT ready");

    server::Reply::new(HostWithPort::default_ipv4(0))
        .write_to(&mut stream)
        .await?;

    let result = tokio::select! {
        copied = copy_bidirectional(&mut stream, &mut tunnel) => copied,
        _ = wait_for_tcp_relay_idle(pool) => {
            debug!(
                client = %peer,
                destination = %destination,
                idle_timeout_secs = TCP_RELAY_IDLE_TIMEOUT.as_secs(),
                "closing idle tcp socks5 session"
            );
            let _ = tokio::time::timeout(Duration::from_secs(1), tunnel.shutdown()).await;
            Ok((0, 0))
        }
    };
    match result {
        Ok((up_bytes, down_bytes)) => {
            debug!(
                client = %peer,
                destination = %destination,
                up_bytes,
                down_bytes,
                "tcp socks5 session finished"
            );
            Ok(())
        }
        Err(err) => {
            warn!(client = %peer, destination = %destination, error = %err, "tcp relay failed after connect");
            Err(AppError::Io(err))
        }
    }
}

async fn wait_for_tcp_relay_idle(pool: &TunnelPool) {
    let check_interval = Duration::from_secs(30);
    loop {
        tokio::time::sleep(check_interval).await;
        if pool
            .snapshot()
            .await
            .last_traffic_age_secs
            .is_some_and(|age| age >= TCP_RELAY_IDLE_TIMEOUT.as_secs())
        {
            return;
        }
    }
}

async fn serve_udp_associate(
    mut tcp_stream: TcpStream,
    peer: SocketAddr,
    config: &ClientConfigFile,
    pool: &TunnelPool,
) -> Result<(), AppError> {
    let mut tunnel = tokio::time::timeout(TUNNEL_ACQUIRE_TIMEOUT, pool.acquire())
        .await
        .map_err(|_| AppError::Boxed(format!("acquire udp tunnel timed out for {peer}")))?
        .map_err(|err| {
            warn!(client = %peer, error = %err, "acquire udp tunnel failed");
            err
        })?;
    write_open_udp(&mut tunnel).await?;
    if let Err(err) = tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, read_response(&mut tunnel))
        .await
        .map_err(|_| AppError::Boxed(format!("wait udp tunnel response timed out for {peer}")))?
    {
        warn!(client = %peer, error = %err, "tunnel open udp failed");
        server::Reply::error_reply(ReplyKind::GeneralServerFailure)
            .write_to(&mut tcp_stream)
            .await?;
        return Err(err);
    }
    info!(client = %peer, "udp tunnel connected");

    let udp_bind = SocketAddr::new(parse_bind_ip(&config.socks5.bind)?, 0);
    let udp_socket = UdpSocket::bind(udp_bind).await?;
    let reply_addr = HostWithPort::from(udp_socket.local_addr()?);
    server::Reply::new(reply_addr)
        .write_to(&mut tcp_stream)
        .await?;

    let idle_timeout = Duration::from_secs(config.udp.idle_timeout_secs.max(5));
    let mut udp_buf = vec![0u8; 65535];
    let mut last_activity = Instant::now();
    let mut client_udp_addr: Option<SocketAddr> = None;

    let mut drain_sink = tokio::io::sink();
    loop {
        tokio::select! {
            read = udp_socket.recv_from(&mut udp_buf) => {
                let (n, from) = read?;
                if from.ip() != peer.ip() {
                    warn!(client = %peer, udp_from = %from, "ignored udp packet from unexpected source ip");
                    continue;
                }
                if client_udp_addr.map(|addr| addr != from).unwrap_or(false) {
                    warn!(client = %peer, udp_from = %from, "ignored udp packet from unexpected source port");
                    continue;
                }
                client_udp_addr.get_or_insert(from);

                let (target, payload) = parse_socks5_udp_datagram(&udp_buf[..n])?;
                write_udp_packet(&mut tunnel, &target, payload).await?;
                last_activity = Instant::now();
            }
            opcode = read_opcode(&mut tunnel) => {
                let opcode = opcode?;
                if opcode_is_udp_packet(opcode) {
                    let (source, payload) = read_udp_packet(&mut tunnel).await?;
                    if let Some(client_udp_addr) = client_udp_addr {
                        let packet = build_socks5_udp_datagram(&source, &payload);
                        udp_socket.send_to(&packet, client_udp_addr).await?;
                        last_activity = Instant::now();
                    }
                } else if opcode_is_close(opcode) {
                    info!(client = %peer, "udp tunnel closed by server");
                    return Ok(());
                } else if opcode_is_ping(opcode) {
                    write_pong(&mut tunnel).await?;
                    last_activity = Instant::now();
                } else if opcode_is_pong(opcode) {
                    last_activity = Instant::now();
                } else {
                    return Err(AppError::InvalidConfig(format!(
                        "unexpected tunnel opcode during udp associate: {opcode}"
                    )));
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                if last_activity.elapsed() >= idle_timeout {
                    let _ = write_close(&mut tunnel).await;
                    let _ = tokio::time::timeout(Duration::from_secs(1), tunnel.shutdown()).await;
                    info!(client = %peer, "udp associate idle timeout reached");
                    return Ok(());
                }
                if last_activity.elapsed() >= Duration::from_secs(15) {
                    let _ = write_ping(&mut tunnel).await;
                }
            }
            read = tokio::io::copy(&mut tcp_stream, &mut drain_sink) => {
                let _ = read?;
                let _ = write_close(&mut tunnel).await;
                let _ = tokio::time::timeout(Duration::from_secs(1), tunnel.shutdown()).await;
                info!(client = %peer, "udp associate tcp control stream closed");
                return Ok(());
            }
        }
    }
}

pub(crate) fn parse_socks5_udp_datagram(packet: &[u8]) -> Result<(HostWithPort, &[u8]), AppError> {
    let mut cursor = Cursor::new(packet);
    let header = UdpHeader::read_from_sync(&mut cursor)
        .map_err(|err| AppError::Boxed(format!("parse socks5 udp header failed: {err}")))?;
    if header.fragment_number != 0 {
        return Err(AppError::InvalidConfig(
            "udp fragmentation is not supported".to_string(),
        ));
    }
    let offset = cursor.position() as usize;
    Ok((header.destination, &packet[offset..]))
}

pub(crate) fn build_socks5_udp_datagram(source: &HostWithPort, payload: &[u8]) -> Vec<u8> {
    let header = UdpHeader {
        fragment_number: 0,
        destination: source.clone(),
    };
    let mut buf = BytesMut::with_capacity(payload.len() + 512);
    header.write_to_buf(&mut buf);
    buf.extend_from_slice(payload);
    buf.to_vec()
}

fn parse_bind_ip(bind: &str) -> Result<IpAddr, AppError> {
    bind.parse()
        .map_err(|_| AppError::InvalidConfig("bind must be a valid IP address".to_string()))
}

#[allow(dead_code)]
fn build_basic(user: &UserConfig) -> Result<Basic, AppError> {
    let username = NonEmptyStr::try_from(user.username.clone())
        .map_err(|err| AppError::InvalidConfig(format!("invalid username: {err}")))?;
    let password = NonEmptyStr::try_from(user.password.clone())
        .map_err(|err| AppError::InvalidConfig(format!("invalid password: {err}")))?;
    Ok(Basic::new(username, password))
}
