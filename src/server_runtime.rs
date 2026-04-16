use std::net::{IpAddr, SocketAddr};

use rama::{
    extensions::Extensions,
    net::{
        address::HostWithPort,
        mode::{ConnectIpMode, DnsResolveIpMode},
    },
    tcp::client::default_tcp_connect,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    io::copy_bidirectional,
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket, lookup_host},
};
use tracing::{debug, info, warn};

use crate::{
    config::ServerConfigFile,
    error::AppError,
    tls::{ServerTlsAcceptor, build_server_tls_acceptor},
    tunnel::{
        opcode_is_close, opcode_is_connect, opcode_is_ping, opcode_is_udp, opcode_is_udp_packet,
        read_connect_target, read_opcode, read_udp_packet, server_handshake,
        status_connect_failed, status_resolve_failed, write_pong, write_response, write_udp_packet,
    },
};

pub async fn run(config: ServerConfigFile) -> Result<(), AppError> {
    let bind_ip = parse_bind_ip(&config.server.bind)?;
    let listen_addr = SocketAddr::new(bind_ip, config.server.port);
    let listener = bind_listener(listen_addr).await?;
    let tls_acceptor = build_server_tls_acceptor(&config.tls)?;

    info!(
        bind = %listen_addr,
        outbound_ip_mode = %config.server.outbound_ip_mode,
        tls_enabled = config.tls.enabled,
        "tunnel server started"
    );

    loop {
        let (stream, peer) = accept_with_retry(&listener).await?;
        let config = config.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, peer, config, tls_acceptor).await {
                debug!(client = %peer, error = %err, "tunnel connection ended with error");
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

async fn accept_with_retry(listener: &TcpListener) -> Result<(TcpStream, SocketAddr), AppError> {
    loop {
        match listener.accept().await {
            Ok(conn) => return Ok(conn),
            Err(err) if is_retryable_accept_error(&err) => {
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
) -> Result<(), AppError> {
    stream.set_nodelay(true)?;

    match tls_acceptor {
        Some(acceptor) => {
            let mut stream = acceptor
                .accept(stream)
                .await
                .map_err(|err| AppError::Boxed(format!("tls accept failed: {err}")))?;
            handle_connection_io(&mut stream, peer, config).await
        }
        None => {
            let mut stream = stream;
            handle_connection_io(&mut stream, peer, config).await
        }
    }
}

async fn handle_connection_io<S>(
    stream: &mut S,
    peer: SocketAddr,
    config: ServerConfigFile,
) -> Result<(), AppError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    server_handshake(stream, &config.auth.shared_secret).await?;
    debug!(client = %peer, "tunnel client authenticated");

    loop {
        let opcode = read_opcode(stream).await?;
        if opcode_is_ping(opcode) {
            write_pong(stream).await?;
            continue;
        }
        if opcode_is_connect(opcode) {
            let target = read_connect_target(stream).await?;
            return serve_tcp_tunnel(stream, peer, target, &config).await;
        }
        if opcode_is_udp(opcode) {
            return serve_udp_tunnel(stream, peer, &config).await;
        }
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
) -> Result<(), AppError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let extensions = build_outbound_extensions(&config.server.outbound_ip_mode)?;
    match default_tcp_connect(&extensions, target.clone()).await {
        Ok((mut upstream, _addr)) => {
            write_response(tunnel, 0, "ok").await?;
            let result = copy_bidirectional(tunnel, &mut upstream).await;
            match result {
                Ok((up_bytes, down_bytes)) => {
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
        Err(err) => {
            let (status, message) = status_connect_failed(&err.to_string());
            write_response(tunnel, status, &message).await?;
            Err(AppError::Boxed(format!("connect target {target} failed: {err}")))
        }
    }
}

async fn serve_udp_tunnel<S>(
    tunnel: &mut S,
    peer: SocketAddr,
    config: &ServerConfigFile,
) -> Result<(), AppError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let bind_ip = parse_bind_ip(&config.server.bind)?;
    let udp = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    write_response(tunnel, 0, "ok").await?;

    let mut recv_buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            opcode = read_opcode(tunnel) => {
                let opcode = opcode?;
                if opcode_is_udp_packet(opcode) {
                    let (target, payload) = read_udp_packet(tunnel).await?;
                    let remote = resolve_udp_target(&target, &config.server.outbound_ip_mode).await?;
                    udp.send_to(&payload, remote).await?;
                } else if opcode_is_close(opcode) {
                    debug!(client = %peer, "udp tunnel closed by client");
                    return Ok(());
                } else {
                    return Err(AppError::InvalidConfig(format!(
                        "unexpected udp tunnel opcode from {peer}: {opcode}"
                    )));
                }
            }
            recv = udp.recv_from(&mut recv_buf) => {
                let (n, remote) = recv?;
                let source = HostWithPort::from(remote);
                write_udp_packet(tunnel, &source, &recv_buf[..n]).await?;
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
