use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use rama::{
    dns::{DnsResolver, GlobalDnsResolver},
    extensions::Extensions,
    net::{
        address::{Domain, HostWithPort},
        mode::{ConnectIpMode, DnsResolveIpMode},
    },
    proxy::socks5::proto::Command,
    tcp::client::tcp_connect,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket, lookup_host},
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
};
use tracing::{debug, error, info, warn};

use crate::{
    client_runtime::{build_socks5_udp_datagram, parse_socks5_udp_datagram},
    config::ServerConfigFile,
    error::AppError,
    server_stats::{ServerStatsRegistry, spawn_stats_server},
    tls::{ServerTlsAcceptor, build_server_tls_acceptor},
    tunnel::{
        opcode_is_close, opcode_is_connect, opcode_is_heartbeat_open, opcode_is_ping,
        opcode_is_pong, opcode_is_udp, opcode_is_udp_packet, read_connect_target, read_heartbeat,
        read_opcode, read_udp_packet, server_handshake, status_connect_failed,
        status_resolve_failed, write_close, write_heartbeat, write_ping, write_pong,
        write_response, write_udp_packet,
    },
};

use std::time::{Duration, Instant};

mod relay;
mod upstream;

const OUTBOUND_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const DEFAULT_UPSTREAM_CONNECT_TIMEOUT_SECS: u64 = 10;
const TCP_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const TLS_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const SLOW_TARGET_DIAL_MS: u64 = 500;
const UDP_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
const UDP_SELECT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

pub async fn run(config: ServerConfigFile, stats_socket: PathBuf) -> Result<(), AppError> {
    let bind_ip = parse_bind_ip(&config.server.bind)?;
    let listen_addr = SocketAddr::new(bind_ip, config.server.port);
    let listener = bind_listener(listen_addr).await?;
    let tls_acceptor = build_server_tls_acceptor(&config.tls)?;
    let stats = ServerStatsRegistry::new();
    let handshake_limiter = std::sync::Arc::new(Semaphore::new(config.server.max_handshakes));
    spawn_stats_server(stats.clone(), stats_socket.clone());

    info!(
        bind = %listen_addr,
        outbound_ip_mode = %config.server.outbound_ip_mode,
        upstream_socks5 = ?config.upstream.as_ref().map(|proxy| &proxy.address),
        tls_enabled = config.tls.enabled,
        handshake_timeout_secs = config.server.handshake_timeout_secs,
        max_handshakes = config.server.max_handshakes,
        udp_idle_timeout_secs = config.server.udp_idle_timeout_secs,
        stats_socket = %stats_socket.display(),
        "tunnel server started"
    );

    loop {
        let (stream, peer) = accept_with_retry(&listener, &stats).await?;
        let config = config.clone();
        let tls_acceptor = tls_acceptor.clone();
        let stats = stats.clone();
        let handshake_limiter = handshake_limiter.clone();
        let handshake_permit = match handshake_limiter.try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                stats.record_handshake_rejection();
                warn!(
                    client = %peer,
                    max_handshakes = config.server.max_handshakes,
                    "rejecting tunnel connection because handshake limit is reached"
                );
                drop(stream);
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(err) = handle_connection(
                stream,
                peer,
                config,
                tls_acceptor,
                stats.clone(),
                handshake_permit,
            )
            .await
            {
                debug!(client = %peer, error = %err, "tunnel connection task ended");
            }
        });
    }
}

async fn bind_listener(addr: SocketAddr) -> Result<TcpListener, AppError> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    Ok(socket.listen(4096)?)
}

async fn accept_with_retry(
    listener: &TcpListener,
    stats: &ServerStatsRegistry,
) -> Result<(TcpStream, SocketAddr), AppError> {
    loop {
        match listener.accept().await {
            Ok(conn) => return Ok(conn),
            Err(err) if is_retryable_accept_error(&err) => {
                if matches!(err.raw_os_error(), Some(24) | Some(10024)) {
                    stats.record_emfile();
                }
                warn!(
                    error = %err,
                    raw_os_error = err.raw_os_error(),
                    "accept failed; backing off before retry"
                );
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Err(err) => return Err(AppError::Io(err)),
        }
    }
}

fn is_retryable_accept_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
    ) || matches!(err.raw_os_error(), Some(24) | Some(10024))
}

fn configure_tcp_stream(
    stream: &TcpStream,
    keepalive_secs: u64,
    connection_id: u64,
    addr: SocketAddr,
) {
    if let Err(err) = stream.set_nodelay(true) {
        warn!(connection_id, %addr, error = %err, "failed to enable TCP_NODELAY");
    }
    let interval = Duration::from_secs(keepalive_secs.max(1));
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(interval)
        .with_interval(interval);
    if let Err(err) = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive) {
        warn!(connection_id, %addr, error = %err, "failed to enable TCP keepalive");
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    config: ServerConfigFile,
    tls_acceptor: Option<ServerTlsAcceptor>,
    stats: ServerStatsRegistry,
    handshake_permit: OwnedSemaphorePermit,
) -> Result<(), AppError> {
    let (connection_id, close) = stats.register_connection(peer.to_string()).await;
    configure_tcp_stream(
        &stream,
        config.server.tcp_keepalive_secs,
        connection_id,
        peer,
    );
    let started_at = Instant::now();
    info!(
        connection_id,
        client = %peer,
        "tunnel connection accepted"
    );
    let result = match tls_acceptor {
        Some(acceptor) => {
            async {
                let mut stream = acceptor.accept(stream);
                let mut stream = tokio::time::timeout(
                    std::time::Duration::from_secs(config.server.handshake_timeout_secs.max(1)),
                    &mut stream,
                )
                .await
                .map_err(|_| {
                    stats.record_handshake_timeout();
                    AppError::Boxed("tls handshake timed out".to_string())
                })?
                .map_err(|err| AppError::Boxed(format!("tls accept failed: {err}")))?;
                info!(
                    connection_id,
                    client = %peer,
                    "tls handshake completed"
                );
                let io_result = handle_connection_io(
                    &mut stream,
                    peer,
                    config,
                    &stats,
                    connection_id,
                    &close,
                    handshake_permit,
                )
                .await;
                let _ = tokio::time::timeout(TLS_SHUTDOWN_TIMEOUT, stream.shutdown()).await;
                io_result
            }
            .await
        }
        None => {
            let mut stream = stream;
            handle_connection_io(
                &mut stream,
                peer,
                config,
                &stats,
                connection_id,
                &close,
                handshake_permit,
            )
            .await
        }
    };
    let duration_ms = started_at.elapsed().as_millis() as u64;
    match &result {
        Ok(()) => info!(
            connection_id,
            client = %peer,
            duration_ms,
            "tunnel connection closed"
        ),
        Err(err) => warn!(
            connection_id,
            client = %peer,
            duration_ms,
            error = %err,
            "tunnel connection closed with error"
        ),
    }
    stats.remove_connection(connection_id).await;
    result
}

async fn handle_connection_io<S>(
    stream: &mut S,
    peer: SocketAddr,
    config: ServerConfigFile,
    stats: &ServerStatsRegistry,
    connection_id: u64,
    close: &Notify,
    handshake_permit: OwnedSemaphorePermit,
) -> Result<(), AppError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let handshake = server_handshake(
        stream,
        &config.auth.shared_secret,
        config.auth.require_client_id,
    );
    let client_id = tokio::time::timeout(
        std::time::Duration::from_secs(config.server.handshake_timeout_secs.max(1)),
        handshake,
    )
    .await
    .map_err(|_| {
        stats.record_handshake_timeout();
        AppError::Boxed("tunnel handshake timed out".to_string())
    })?
    .map_err(|err| AppError::Boxed(format!("tunnel handshake failed: {err}")))?;
    drop(handshake_permit);
    stats.set_client_id(connection_id, client_id.clone()).await;
    stats.mark_idle(connection_id).await;
    info!(
        connection_id,
        client = %peer,
        client_id = %client_id,
        "tunnel client authenticated"
    );

    loop {
        let opcode = tokio::select! {
            result = read_opcode(stream) => result?,
            _ = close.notified() => return Ok(()),
        };
        if opcode_is_heartbeat_open(opcode) {
            return tokio::select! {
                _ = close.notified() => Ok(()),
                result = serve_heartbeat_control(stream, peer, client_id, &config, stats, connection_id) => result,
            };
        }
        if opcode_is_ping(opcode) {
            stats.touch(connection_id).await;
            write_pong(stream).await?;
            continue;
        }
        if opcode_is_connect(opcode) {
            let target = read_connect_target(stream).await?;
            stats.mark_active_tcp(connection_id, target.clone()).await;
            return tokio::select! {
                _ = close.notified() => Ok(()),
                result = serve_tcp_tunnel(stream, peer, target, &config, stats, connection_id) => result,
            };
        }
        if opcode_is_udp(opcode) {
            stats.mark_active_udp(connection_id).await;
            return serve_udp_tunnel(stream, peer, &config, stats, connection_id, close).await;
        }
        error!(client = %peer, opcode, "received unknown tunnel opcode");
        return Err(AppError::InvalidConfig(format!(
            "unknown tunnel opcode from client {peer}: {opcode}"
        )));
    }
}

async fn serve_heartbeat_control<S>(
    stream: &mut S,
    peer: SocketAddr,
    client_id: String,
    config: &ServerConfigFile,
    stats: &ServerStatsRegistry,
    connection_id: u64,
) -> Result<(), AppError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    if let Some(previous_id) = stats.register_heartbeat(&client_id, connection_id).await {
        if previous_id != connection_id {
            stats.close_connection(previous_id).await;
        }
    }
    info!(
        connection_id,
        client = %peer,
        client_id = %client_id,
        "heartbeat control channel established"
    );
    let interval = Duration::from_secs(config.server.heartbeat_interval_secs.max(1));
    let timeout = Duration::from_secs(config.server.heartbeat_timeout_secs.max(1));
    loop {
        let ids = stats.client_tunnel_ids(&client_id).await;
        info!(
            connection_id,
            client = %peer,
            client_id = %client_id,
            tunnel_count = ids.len(),
            tunnel_ids = ?ids,
            "heartbeat tunnel snapshot sent"
        );
        write_heartbeat(stream, &ids).await?;
        let (opcode, ack_ids) = tokio::time::timeout(timeout, read_heartbeat(stream))
            .await
            .map_err(|_| AppError::Boxed(format!("heartbeat ack timed out from {peer}")))??;
        if !crate::tunnel::opcode_is_heartbeat_ack(opcode) {
            return Err(AppError::InvalidConfig(format!(
                "invalid heartbeat ack from {peer}"
            )));
        }
        for id in ack_ids
            .iter()
            .filter(|id| **id != connection_id && !ids.contains(id))
        {
            warn!(
                connection_id,
                client = %peer,
                client_id = %client_id,
                channel_id = *id,
                "heartbeat reported an invalid channel id; closing that channel"
            );
            if !stats
                .close_client_connection_if_exists(&client_id, *id)
                .await
            {
                debug!(
                    connection_id,
                    client = %peer,
                    client_id = %client_id,
                    channel_id = *id,
                    "heartbeat reported a channel that was already closed; ignoring"
                );
            }
        }
        if ack_ids.len() != ids.len() {
            warn!(
                connection_id,
                client = %peer,
                client_id = %client_id,
                expected_channels = ids.len(),
                reported_channels = ack_ids.len(),
                "heartbeat channel list differs from server snapshot"
            );
        }
        stats.mark_heartbeat(connection_id).await;
        tokio::time::sleep(interval).await;
    }
}

async fn serve_tcp_tunnel<S>(
    tunnel: &mut S,
    peer: SocketAddr,
    target: HostWithPort,
    config: &ServerConfigFile,
    stats: &ServerStatsRegistry,
    connection_id: u64,
) -> Result<(), AppError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let extensions = build_outbound_extensions(&config.server.outbound_ip_mode)?;
    let dns = TimedDnsResolver::default();
    let started = Instant::now();
    let dial_target = config
        .upstream
        .as_ref()
        .map_or(&target, |proxy| &proxy.address);
    let connect_timeout = outbound_connect_timeout(config);
    let connect_result = tokio::time::timeout(connect_timeout, async {
        let (conn, addr) = tcp_connect(&extensions, dial_target.clone(), dns.clone(), ())
            .await
            .map_err(|err| AppError::Boxed(err.to_string()))?;
        let mut stream = conn.stream;
        configure_tcp_stream(
            &stream,
            config.server.tcp_keepalive_secs,
            connection_id,
            addr,
        );
        if let Some(proxy) = &config.upstream {
            upstream::request(&mut stream, proxy, Command::Connect, &target).await?;
        }
        Ok::<_, AppError>((stream, addr))
    })
    .await;
    let ended = Instant::now();
    let dial_ms = (ended - started).as_millis() as u64;
    let dns_ms = |completion: &OnceLock<Instant>| {
        completion
            .get()
            .filter(|finished| **finished <= ended)
            .map(|finished| (*finished - started).as_millis() as u64)
    };
    let dns_ipv4_ms = dns_ms(&dns.0.ipv4);
    let dns_ipv6_ms = dns_ms(&dns.0.ipv6);
    match connect_result {
        Ok(Ok((mut upstream, addr))) => {
            let dns_ms = if addr.is_ipv4() {
                dns_ipv4_ms
            } else {
                dns_ipv6_ms
            }
            .unwrap_or(0);
            // Time after the winning address family's lookup, including scheduling and retries.
            let tcp_phase_ms = dial_ms.saturating_sub(dns_ms);
            if dial_ms >= SLOW_TARGET_DIAL_MS {
                info!(target: "proxy_core::server_runtime::dial", connection_id, target = %target, upstream = %addr, dns_ms, tcp_phase_ms, dial_ms, "Target connected");
            } else {
                debug!(target: "proxy_core::server_runtime::dial", connection_id, target = %target, upstream = %addr, dns_ms, tcp_phase_ms, dial_ms, "Target connected");
            }
            stats.set_upstream_addr(connection_id, addr).await;
            // Older clients consume and ignore the successful response message.
            let message = format!("ok id={connection_id} dial_ms={dial_ms}");
            write_response(tunnel, 0, &message).await?;
            let Some((up_bytes, down_bytes)) =
                relay::copy_with_idle_timeout(tunnel, &mut upstream, TCP_RELAY_IDLE_TIMEOUT)
                    .await?
            else {
                debug!(connection_id, target = %target, idle_timeout_secs = TCP_RELAY_IDLE_TIMEOUT.as_secs(), "tcp tunnel idle timeout reached");
                return Ok(());
            };
            stats
                .add_tcp_bytes(connection_id, up_bytes, down_bytes)
                .await;
            debug!(connection_id, client = %peer, target = %target, up_bytes, down_bytes, "tcp tunnel finished");
            Ok(())
        }
        Ok(Err(err)) => {
            let (status, message) = status_connect_failed(&err.to_string());
            warn!(connection_id, target = %target, dial_ms, dns_ipv4_ms, dns_ipv6_ms, error = %err, "Target connection failed");
            write_response(tunnel, status, &message).await?;
            Err(AppError::Boxed(format!(
                "connect target {target} failed: {err}"
            )))
        }
        Err(_) => {
            let message = format!(
                "connect target {target} timed out after {}s",
                connect_timeout.as_secs()
            );
            warn!(connection_id, target = %target, dial_ms, dns_ipv4_ms, dns_ipv6_ms, "Target connection timed out");
            let (status, response_message) = status_connect_failed(&message);
            write_response(tunnel, status, &response_message).await?;
            Err(AppError::Boxed(message))
        }
    }
}

async fn serve_udp_tunnel<S>(
    tunnel: &mut S,
    peer: SocketAddr,
    config: &ServerConfigFile,
    stats: &ServerStatsRegistry,
    connection_id: u64,
    close: &Notify,
) -> Result<(), AppError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (udp, mut upstream_control) = if let Some(proxy) = &config.upstream {
        let connect_timeout = outbound_connect_timeout(config);
        let association = tokio::time::timeout(
            connect_timeout,
            upstream::associate_udp(
                proxy,
                &config.server.outbound_ip_mode,
                config.server.tcp_keepalive_secs,
                connection_id,
            ),
        )
        .await
        .unwrap_or_else(|_| {
            Err(AppError::Boxed(format!(
                "upstream SOCKS5 UDP association timed out after {}s",
                connect_timeout.as_secs()
            )))
        });
        match association {
            Ok((udp, control)) => (udp, Some(control)),
            Err(err) => {
                warn!(
                    connection_id,
                    client = %peer,
                    upstream = %proxy.address,
                    error = %err,
                    "upstream SOCKS5 UDP association failed"
                );
                let (status, message) = status_connect_failed(&err.to_string());
                write_response(tunnel, status, &message).await?;
                return Err(err);
            }
        }
    } else {
        let bind_ip = parse_bind_ip(&config.server.bind)?;
        (UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?, None)
    };
    let upstream_relay = upstream_control
        .as_ref()
        .map(|_| udp.peer_addr())
        .transpose()?;
    write_response(tunnel, 0, "ok").await?;

    let mut recv_buf = vec![0u8; 65535];
    let idle_timeout = std::time::Duration::from_secs(config.server.udp_idle_timeout_secs.max(5));
    let mut last_activity = std::time::Instant::now();
    loop {
        tokio::select! {
            opcode = read_opcode(tunnel) => {
                let opcode = opcode?;
                if opcode_is_udp_packet(opcode) {
                    if last_activity.elapsed() >= idle_timeout {
                        warn!(
                            client = %peer,
                            idle_timeout_secs = idle_timeout.as_secs(),
                            "udp frame read exceeded idle timeout"
                        );
                        let _ = write_close(tunnel).await;
                        return Ok(());
                    }
                    let read_timeout = idle_timeout.saturating_sub(last_activity.elapsed());
                    let (target, payload) = match tokio::time::timeout(
                        read_timeout,
                        read_udp_packet(tunnel),
                    )
                    .await
                    {
                        Ok(result) => result?,
                        Err(_) => {
                            warn!(
                                client = %peer,
                                idle_timeout_secs = idle_timeout.as_secs(),
                                "udp frame read timed out"
                            );
                            let _ = write_close(tunnel).await;
                            return Ok(());
                        }
                    };
                    let remote = if let Some(relay) = upstream_relay {
                        let datagram = build_socks5_udp_datagram(&target, &payload);
                        if let Err(err) = udp.send(&datagram).await {
                            if is_ignorable_udp_io_error(&err) {
                                warn!(
                                    connection_id,
                                    client = %peer,
                                    target = %target,
                                    error = %err,
                                    "dropping udp packet due to transient upstream send error"
                                );
                                continue;
                            }
                            return Err(err.into());
                        }
                        relay
                    } else {
                        let remote = resolve_udp_target(&target, &config.server.outbound_ip_mode).await?;
                        udp.send_to(&payload, remote).await?;
                        remote
                    };
                    stats
                        .add_udp_client_bytes(connection_id, target, remote, payload.len() as u64)
                        .await;
                    last_activity = std::time::Instant::now();
                } else if opcode_is_ping(opcode) {
                    stats.touch(connection_id).await;
                    write_pong(tunnel).await?;
                    last_activity = std::time::Instant::now();
                } else if opcode_is_pong(opcode) {
                    stats.touch(connection_id).await;
                    last_activity = std::time::Instant::now();
                } else if opcode_is_close(opcode) {
                    debug!(client = %peer, "udp tunnel closed by client");
                    return Ok(());
                } else {
                    error!(client = %peer, opcode, "unexpected udp tunnel opcode");
                    return Err(AppError::InvalidConfig(format!(
                        "unexpected udp tunnel opcode from {peer}: {opcode}"
                    )));
                }
            }
            recv = udp.recv_from(&mut recv_buf) => {
                let (n, remote) = match recv {
                    Ok(result) => result,
                    Err(err) if is_transient_udp_recv_error(&err) => {
                        debug!(
                            connection_id,
                            client = %peer,
                            error = %err,
                            "ignoring transient udp recv error"
                        );
                        continue;
                    }
                    Err(err) => return Err(err.into()),
                };
                let (source, payload) = if upstream_relay.is_some() {
                    match parse_socks5_udp_datagram(&recv_buf[..n]) {
                        Ok(packet) => packet,
                        Err(err) => {
                            debug!(connection_id, error = %err, "invalid upstream SOCKS5 UDP datagram");
                            continue;
                        }
                    }
                } else {
                    (HostWithPort::from(remote), &recv_buf[..n])
                };
                stats
                    .add_udp_target_bytes(connection_id, remote, payload.len() as u64)
                    .await;
                write_udp_packet(tunnel, &source, payload).await?;
                last_activity = std::time::Instant::now();
            }
            result = async {
                match upstream_control.as_mut() {
                    Some(control) => control.read(&mut [0]).await,
                    None => std::future::pending().await,
                }
            } => {
                match result {
                    Ok(0) => {
                        debug!(
                            connection_id,
                            client = %peer,
                            "upstream SOCKS5 UDP control connection closed"
                        );
                    }
                    Ok(bytes) => {
                        warn!(
                            connection_id,
                            client = %peer,
                            bytes,
                            "unexpected data on upstream SOCKS5 UDP control connection; closing udp tunnel"
                        );
                    }
                    Err(err) => {
                        warn!(
                            connection_id,
                            client = %peer,
                            error = %err,
                            "upstream SOCKS5 UDP control connection failed"
                        );
                    }
                }
                let _ = write_close(tunnel).await;
                return Ok(());
            }
            _ = tokio::time::sleep(UDP_SELECT_INTERVAL) => {
                if last_activity.elapsed() >= idle_timeout {
                    warn!(
                        client = %peer,
                        idle_timeout_secs = idle_timeout.as_secs(),
                        "udp tunnel idle timeout reached"
                    );
                    let _ = write_close(tunnel).await;
                    return Ok(());
                }
                if last_activity.elapsed() >= UDP_HEARTBEAT_INTERVAL {
                    write_ping(tunnel).await?;
                }
            }
            _ = close.notified() => {
                let _ = write_close(tunnel).await;
                return Ok(());
            }
        }
    }
}

#[derive(Clone, Default)]
struct TimedDnsResolver(Arc<DnsCompletion>);

#[derive(Default)]
struct DnsCompletion {
    ipv4: OnceLock<Instant>,
    ipv6: OnceLock<Instant>,
}

impl DnsResolver for TimedDnsResolver {
    type Error = <GlobalDnsResolver as DnsResolver>::Error;

    async fn ipv4_lookup(&self, domain: Domain) -> Result<Vec<Ipv4Addr>, Self::Error> {
        let result = GlobalDnsResolver::new().ipv4_lookup(domain).await;
        let _ = self.0.ipv4.set(Instant::now());
        result
    }

    async fn ipv6_lookup(&self, domain: Domain) -> Result<Vec<Ipv6Addr>, Self::Error> {
        let result = GlobalDnsResolver::new().ipv6_lookup(domain).await;
        let _ = self.0.ipv6.set(Instant::now());
        result
    }

    async fn txt_lookup(&self, domain: Domain) -> Result<Vec<Vec<u8>>, Self::Error> {
        GlobalDnsResolver::new().txt_lookup(domain).await
    }
}

fn build_outbound_extensions(mode: &str) -> Result<Extensions, AppError> {
    let mut extensions = Extensions::default();
    let (connect_mode, dns_mode) = match mode {
        "dual" => (ConnectIpMode::Dual, DnsResolveIpMode::Dual),
        "ipv4" => (ConnectIpMode::Ipv4, DnsResolveIpMode::SingleIpV4),
        "ipv6" => (ConnectIpMode::Ipv6, DnsResolveIpMode::SingleIpV6),
        "dual-prefer-ipv4" => (ConnectIpMode::Dual, DnsResolveIpMode::DualPreferIpV4),
        other => {
            return Err(AppError::InvalidConfig(format!(
                "unsupported outbound_ip_mode: {other}"
            )));
        }
    };
    extensions.insert(connect_mode);
    extensions.insert(dns_mode);
    Ok(extensions)
}

async fn resolve_udp_target(target: &HostWithPort, mode: &str) -> Result<SocketAddr, AppError> {
    if let Some(addr) = crate::tunnel::host_to_socket_addr(target) {
        return Ok(addr);
    }

    let host = target.host.to_string();
    let mut addrs = lookup_host((host.as_str(), target.port)).await?;
    let chosen = addrs.find(|addr| match mode {
        "ipv4" => addr.is_ipv4(),
        "ipv6" => addr.is_ipv6(),
        _ => true,
    });

    chosen.ok_or_else(|| {
        let (_, msg) = status_resolve_failed(&format!("no address resolved for {target}"));
        AppError::InvalidConfig(msg)
    })
}

fn parse_bind_ip(bind: &str) -> Result<IpAddr, AppError> {
    bind.parse()
        .map_err(|_| AppError::InvalidConfig("bind must be a valid IP address".to_string()))
}

fn outbound_connect_timeout(config: &ServerConfigFile) -> Duration {
    match &config.upstream {
        Some(proxy) => Duration::from_secs(
            proxy
                .connect_timeout_secs
                .unwrap_or(DEFAULT_UPSTREAM_CONNECT_TIMEOUT_SECS)
                .max(1),
        ),
        None => OUTBOUND_CONNECT_TIMEOUT,
    }
}

fn is_transient_udp_recv_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
    ) || matches!(err.raw_os_error(), Some(10054))
}

fn is_ignorable_udp_io_error(err: &std::io::Error) -> bool {
    is_transient_udp_recv_error(err)
        || matches!(err.raw_os_error(), Some(90) | Some(40) | Some(10040))
}

#[cfg(test)]
mod tests;
