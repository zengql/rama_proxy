use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rama::{
    dns::GlobalDnsResolver,
    net::{address::HostWithPort, user::credentials::Basic},
    proxy::socks5::proto::{Command, ProtocolError, ReplyKind, SocksMethod, client, server},
    tcp::client::tcp_connect,
    utils::str::NonEmptyStr,
};
use tokio::net::{TcpStream, UdpSocket};

use crate::{config::UpstreamSocks5Config, error::AppError};

use super::{build_outbound_extensions, configure_tcp_stream, resolve_udp_target};

pub(super) async fn request(
    stream: &mut TcpStream,
    proxy: &UpstreamSocks5Config,
    command: Command,
    target: &HostWithPort,
) -> Result<HostWithPort, AppError> {
    let credentials = proxy.username.as_ref().zip(proxy.password.as_ref());
    let method = if credentials.is_some() {
        SocksMethod::UsernamePassword
    } else {
        SocksMethod::NoAuthenticationRequired
    };
    client::Header::new(std::slice::from_ref(&method))
        .write_to(stream)
        .await?;
    let selected = server::Header::read_from(stream)
        .await
        .map_err(protocol_error)?;
    if selected.method != method {
        return Err(AppError::Boxed(format!(
            "upstream SOCKS5 selected an unexpected authentication method: {:?}",
            selected.method
        )));
    }
    if let Some((username, password)) = credentials {
        let username = NonEmptyStr::try_from(username.clone())
            .map_err(|_| AppError::InvalidConfig("invalid upstream username".to_string()))?;
        let password = NonEmptyStr::try_from(password.clone())
            .map_err(|_| AppError::InvalidConfig("invalid upstream password".to_string()))?;
        client::UsernamePasswordRequest::new(Basic::new(username, password))
            .write_to(stream)
            .await?;
        let reply = server::UsernamePasswordResponse::read_from(stream)
            .await
            .map_err(protocol_error)?;
        if !reply.success() {
            return Err(AppError::Boxed(
                "upstream SOCKS5 rejected username/password authentication".to_string(),
            ));
        }
    }

    client::RequestRef::new(command, target)
        .write_to(stream)
        .await?;
    let reply = server::Reply::read_from(stream)
        .await
        .map_err(protocol_error)?;
    if reply.reply != ReplyKind::Succeeded {
        return Err(AppError::Boxed(format!(
            "upstream SOCKS5 rejected {command:?}: {:?}",
            reply.reply
        )));
    }

    Ok(reply.bind_address)
}

fn protocol_error(err: ProtocolError) -> AppError {
    AppError::Boxed(format!("upstream SOCKS5 protocol error: {err}"))
}

pub(super) async fn associate_udp(
    proxy: &UpstreamSocks5Config,
    ip_mode: &str,
    keepalive_secs: u64,
    connection_id: u64,
) -> Result<(UdpSocket, TcpStream), AppError> {
    let extensions = build_outbound_extensions(ip_mode)?;
    let (conn, peer) = tcp_connect(
        &extensions,
        proxy.address.clone(),
        GlobalDnsResolver::new(),
        (),
    )
    .await
    .map_err(|err| AppError::Boxed(format!("connect to upstream SOCKS5 failed: {err}")))?;
    let mut control = conn.stream;
    configure_tcp_stream(&control, keepalive_secs, connection_id, peer);
    let unspecified = if peer.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    // A zero endpoint lets the upstream learn the actual UDP source, including behind NAT.
    let bind_address = request(
        &mut control,
        proxy,
        Command::UdpAssociate,
        &HostWithPort::from((unspecified, 0)),
    )
    .await?;
    let mut relay = resolve_udp_target(&bind_address, ip_mode).await?;
    if relay.port() == 0 {
        return Err(AppError::Boxed(
            "upstream SOCKS5 returned a zero UDP relay port".to_string(),
        ));
    }
    if relay.ip().is_unspecified() {
        relay.set_ip(peer.ip());
    }
    let bind_ip = if relay.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let udp = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    udp.connect(relay).await?;
    Ok((udp, control))
}
