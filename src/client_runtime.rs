use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rama::{
    bytes::BytesMut,
    net::{
        address::HostWithPort,
        user::credentials::Basic,
    },
    proxy::socks5::proto::{
        Command, ReplyKind, SocksMethod, client, server,
        udp::UdpHeader,
    },
    utils::str::NonEmptyStr,
};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
};
use tracing::{debug, info, warn};

use crate::{
    config::{ClientConfigFile, UserConfig},
    error::AppError,
    tunnel::{
        TunnelPool, opcode_is_close, opcode_is_pong, opcode_is_udp_packet, read_opcode,
        read_response, read_udp_packet, write_close, write_open_connect, write_open_udp,
        write_ping, write_udp_packet,
    },
};

pub async fn run(config: ClientConfigFile) -> Result<(), AppError> {
    let bind_ip = parse_bind_ip(&config.socks5.bind)?;
    let listen_addr = SocketAddr::new(bind_ip, config.socks5.port);
    let listener = bind_listener(listen_addr).await?;

    let pool = TunnelPool::new(&config.client)?;
    pool.spawn_maintainer();

    info!(
        bind = %listen_addr,
        server_addr = %config.client.server_addr,
        udp_enabled = config.udp.enabled,
        pool_size = config.client.pool_size,
        "client socks5 listener started"
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let config = config.clone();
        let pool = pool.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, peer, &config, &pool).await {
                debug!(client = %peer, error = %err, "local socks5 session ended with error");
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

async fn handle_client(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: &ClientConfigFile,
    pool: &TunnelPool,
) -> Result<(), AppError> {
    stream.set_nodelay(true)?;

    let header = client::Header::read_from(&mut stream)
        .await
        .map_err(|err| AppError::Boxed(format!("read socks5 header failed: {err}")))?;

    let method = negotiate_method(&header, config)?;
    server::Header::new(method).write_to(&mut stream).await?;

    if method == SocksMethod::NoAcceptableMethods {
        return Err(AppError::InvalidConfig(format!(
            "client does not support configured auth method: {peer}"
        )));
    }

    if method == SocksMethod::UsernamePassword {
        authorize_user(&mut stream, config).await?;
    }

    let request = client::Request::read_from(&mut stream)
        .await
        .map_err(|err| AppError::Boxed(format!("read socks5 request failed: {err}")))?;

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

fn negotiate_method(header: &client::Header, config: &ClientConfigFile) -> Result<SocksMethod, AppError> {
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
        Err(AppError::InvalidConfig("invalid local socks5 credentials".to_string()))
    }
}

async fn serve_connect(
    mut stream: TcpStream,
    peer: SocketAddr,
    destination: HostWithPort,
    pool: &TunnelPool,
) -> Result<(), AppError> {
    let mut tunnel = pool.acquire().await?;
    write_open_connect(&mut tunnel, &destination).await?;
    if let Err(err) = read_response(&mut tunnel).await {
        server::Reply::error_reply(ReplyKind::GeneralServerFailure)
            .write_to(&mut stream)
            .await?;
        return Err(err);
    }

    server::Reply::new(HostWithPort::default_ipv4(0))
        .write_to(&mut stream)
        .await?;

    let result = copy_bidirectional(&mut stream, &mut tunnel).await;
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
        Err(err) => Err(AppError::Io(err)),
    }
}

async fn serve_udp_associate(
    mut tcp_stream: TcpStream,
    peer: SocketAddr,
    config: &ClientConfigFile,
    pool: &TunnelPool,
) -> Result<(), AppError> {
    let mut tunnel = pool.acquire().await?;
    write_open_udp(&mut tunnel).await?;
    if let Err(err) = read_response(&mut tunnel).await {
        server::Reply::error_reply(ReplyKind::GeneralServerFailure)
            .write_to(&mut tcp_stream)
            .await?;
        return Err(err);
    }

    let udp_bind = SocketAddr::new(parse_bind_ip(&config.socks5.bind)?, 0);
    let udp_socket = UdpSocket::bind(udp_bind).await?;
    let reply_addr = HostWithPort::from(udp_socket.local_addr()?);
    server::Reply::new(reply_addr).write_to(&mut tcp_stream).await?;

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
                    debug!(client = %peer, "udp tunnel closed by server");
                    return Ok(());
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
                    debug!(client = %peer, "udp associate idle timeout reached");
                    return Ok(());
                }
                if last_activity.elapsed() >= Duration::from_secs(15) {
                    let _ = write_ping(&mut tunnel).await;
                }
            }
            read = tokio::io::copy(&mut tcp_stream, &mut drain_sink) => {
                let _ = read?;
                let _ = write_close(&mut tunnel).await;
                debug!(client = %peer, "udp associate tcp control stream closed");
                return Ok(());
            }
        }
    }
}

fn parse_socks5_udp_datagram(packet: &[u8]) -> Result<(HostWithPort, &[u8]), AppError> {
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

fn build_socks5_udp_datagram(source: &HostWithPort, payload: &[u8]) -> Vec<u8> {
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
