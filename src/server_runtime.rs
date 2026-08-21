use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use rama::{
    extensions::Extensions,
    net::{
        address::HostWithPort,
        mode::{ConnectIpMode, DnsResolveIpMode},
        stream::Socket,
    },
    tcp::client::default_tcp_connect,
};
use tokio::{
    io::copy_bidirectional,
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket, lookup_host},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tracing::{debug, error, info, warn};

use crate::{
    config::ServerConfigFile,
    error::AppError,
    server_stats::{ServerStatsRegistry, spawn_stats_server},
    tls::{ServerTlsAcceptor, build_server_tls_acceptor},
    tunnel::{
        opcode_is_close, opcode_is_connect, opcode_is_ping, opcode_is_pong, opcode_is_udp,
        opcode_is_udp_packet, read_connect_target, read_opcode, read_udp_packet, server_handshake,
        status_connect_failed, status_resolve_failed, write_close, write_ping, write_pong,
        write_response, write_udp_packet,
    },
};

const OUTBOUND_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
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
            if let Err(err) =
                handle_connection(stream, peer, config, tls_acceptor, stats, handshake_permit).await
            {
                warn!(client = %peer, error = %err, "tunnel connection ended with error");
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

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    config: ServerConfigFile,
    tls_acceptor: Option<ServerTlsAcceptor>,
    stats: ServerStatsRegistry,
    handshake_permit: OwnedSemaphorePermit,
) -> Result<(), AppError> {
    stream.set_nodelay(true)?;
    let connection_id = stats.register_connection(peer.to_string()).await;

    let result = match tls_acceptor {
        Some(acceptor) => {
            let mut stream = acceptor.accept(stream);
            let mut stream = tokio::time::timeout(
                std::time::Duration::from_secs(config.server.handshake_timeout_secs.max(1)),
                &mut stream,
            )
            .await
            .map_err(|_| {
                stats.record_handshake_timeout();
                warn!(client = %peer, "tls handshake timed out");
                AppError::Boxed("tls handshake timed out".to_string())
            })?
            .map_err(|err| AppError::Boxed(format!("tls accept failed: {err}")))?;
            handle_connection_io(
                &mut stream,
                peer,
                config,
                &stats,
                connection_id,
                handshake_permit,
            )
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
                handshake_permit,
            )
            .await
        }
    };
    stats.remove_connection(connection_id).await;
    result
}

async fn handle_connection_io<S>(
    stream: &mut S,
    peer: SocketAddr,
    config: ServerConfigFile,
    stats: &ServerStatsRegistry,
    connection_id: u64,
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
        warn!(client = %peer, "tunnel handshake timed out");
        AppError::Boxed("tunnel handshake timed out".to_string())
    })?
    .map_err(|err| {
        warn!(client = %peer, error = %err, "tunnel handshake failed");
        err
    })?;
    drop(handshake_permit);
    stats.set_client_id(connection_id, client_id.clone()).await;
    stats.mark_idle(connection_id).await;
    debug!(client = %peer, client_id = %client_id, "tunnel client authenticated");

    loop {
        let opcode = read_opcode(stream).await?;
        if opcode_is_ping(opcode) {
            stats.touch(connection_id).await;
            write_pong(stream).await?;
            continue;
        }
        if opcode_is_connect(opcode) {
            let target = read_connect_target(stream).await?;
            stats
                .mark_active_tcp(connection_id, target.to_string())
                .await;
            return serve_tcp_tunnel(stream, peer, target, &config, stats, connection_id).await;
        }
        if opcode_is_udp(opcode) {
            stats.mark_active_udp(connection_id).await;
            return serve_udp_tunnel(stream, peer, &config, stats, connection_id).await;
        }
        error!(client = %peer, opcode, "received unknown tunnel opcode");
        return Err(AppError::InvalidConfig(format!(
            "unknown tunnel opcode from client {peer}: {opcode}"
        )));
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
    let connect_result = tokio::time::timeout(
        OUTBOUND_CONNECT_TIMEOUT,
        default_tcp_connect(&extensions, target.clone()),
    )
    .await;
    match connect_result {
        Ok(Ok((mut upstream, _addr))) => {
            if let Ok(addr) = upstream.peer_addr() {
                stats
                    .set_upstream_addr(connection_id, addr.to_string())
                    .await;
            }
            write_response(tunnel, 0, "ok").await?;
            let result = copy_bidirectional(tunnel, &mut upstream).await;
            match result {
                Ok((up_bytes, down_bytes)) => {
                    stats
                        .add_tcp_bytes(connection_id, up_bytes, down_bytes)
                        .await;
                    debug!(
                        client = %peer,
                        target = %target,
                        up_bytes,
                        down_bytes,
                        "tcp tunnel finished"
                    );
                    Ok(())
                }
                Err(err) => Err(AppError::Io(err)),
            }
        }
        Ok(Err(err)) => {
            let (status, message) = status_connect_failed(&err.to_string());
            warn!(client = %peer, target = %target, error = %err, "connect target failed");
            write_response(tunnel, status, &message).await?;
            Err(AppError::Boxed(format!(
                "connect target {target} failed: {err}"
            )))
        }
        Err(_) => {
            let message = format!(
                "connect target {target} timed out after {}s",
                OUTBOUND_CONNECT_TIMEOUT.as_secs()
            );
            warn!(client = %peer, target = %target, timeout_secs = OUTBOUND_CONNECT_TIMEOUT.as_secs(), "outbound tcp connect timed out");
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
) -> Result<(), AppError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let bind_ip = parse_bind_ip(&config.server.bind)?;
    let udp = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
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
                    let remote = resolve_udp_target(&target, &config.server.outbound_ip_mode).await?;
                    stats
                        .add_udp_client_bytes(connection_id, target.to_string(), payload.len() as u64)
                        .await;
                    stats
                        .set_upstream_addr(connection_id, remote.to_string())
                        .await;
                    udp.send_to(&payload, remote).await?;
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
                let (n, remote) = recv?;
                let source = HostWithPort::from(remote);
                stats
                    .add_udp_target_bytes(connection_id, remote.to_string(), n as u64)
                    .await;
                write_udp_packet(tunnel, &source, &recv_buf[..n]).await?;
                last_activity = std::time::Instant::now();
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
        }
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
