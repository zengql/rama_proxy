use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rama::{
    Layer, Service,
    error::BoxError,
    extensions::ExtensionsRef,
    graceful,
    layer::AddInputExtensionLayer,
    net::{
        address::SocketAddress,
        conn::is_connection_error,
        mode::{ConnectIpMode, DnsResolveIpMode},
        proxy::ProxyRequest,
        socket::{SocketOptions, opts::TcpKeepAlive},
        stream::Socket,
        user::credentials::Basic,
    },
    proxy::socks5::{
        Socks5Acceptor,
        server::{Connector as Socks5Connector, DefaultUdpRelay},
    },
    service::service_fn,
    tcp::{
        TcpStream,
        client::{TcpStreamConnector, service::TcpConnector},
        server::TcpListener,
    },
    utils::str::NonEmptyStr,
};
use tracing::{debug, info, warn};

use crate::config::{ProxyConfig, UserConfig};
use crate::error::AppError;

pub async fn run(config: ProxyConfig) -> Result<(), AppError> {
    let graceful = graceful::Shutdown::new(tokio::signal::ctrl_c());

    if config.socks5.enabled {
        spawn_socks5(&graceful, &config).await?;
    }

    info!(
        socks5_enabled = config.socks5.enabled,
        udp_enabled = config.udp.enabled,
        "proxy runtime started"
    );

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .map_err(|err| AppError::InvalidConfig(format!("graceful shutdown failed: {err}")))?;

    Ok(())
}

async fn spawn_socks5(graceful: &graceful::Shutdown, config: &ProxyConfig) -> Result<(), AppError> {
    let bind = SocketAddr::new(parse_bind_ip(&config.server.bind)?, config.socks5.port);
    let tcp_service = bind_listener(bind).await?;
    let outbound_mode = outbound_mode_layers(config)?;

    let udp_relay = if config.udp.enabled {
        Some(build_udp_relay(config)?)
    } else {
        None
    };

    match (config.auth.mode.as_str(), udp_relay) {
        ("password", Some(udp_relay)) => {
            let user = primary_user(&config.auth.users)?;
            let service = Socks5Acceptor::new()
                .with_connector(
                    Socks5Connector::default()
                        .with_connector(TcpConnector::new().with_connector(build_keepalive_stream_connector()))
                        .with_service(service_fn(logged_proxy_stream)),
                )
                .with_authorizer(build_basic(user)?.into_authorizer())
                .with_udp_associator(udp_relay);
            spawn_socks5_listener(graceful, tcp_service, outbound_mode, service);
        }
        ("password", None) => {
            let user = primary_user(&config.auth.users)?;
            let service = Socks5Acceptor::new()
                .with_connector(
                    Socks5Connector::default()
                        .with_connector(TcpConnector::new().with_connector(build_keepalive_stream_connector()))
                        .with_service(service_fn(logged_proxy_stream)),
                )
                .with_authorizer(build_basic(user)?.into_authorizer());
            spawn_socks5_listener(graceful, tcp_service, outbound_mode, service);
        }
        (_, Some(udp_relay)) => {
            let service = Socks5Acceptor::new()
                .with_connector(
                    Socks5Connector::default()
                        .with_connector(TcpConnector::new().with_connector(build_keepalive_stream_connector()))
                        .with_service(service_fn(logged_proxy_stream)),
                )
                .with_udp_associator(udp_relay);
            spawn_socks5_listener(graceful, tcp_service, outbound_mode, service);
        }
        (_, None) => {
            let service = Socks5Acceptor::new().with_connector(
                Socks5Connector::default()
                    .with_connector(TcpConnector::new().with_connector(build_keepalive_stream_connector()))
                    .with_service(service_fn(logged_proxy_stream)),
            );
            spawn_socks5_listener(graceful, tcp_service, outbound_mode, service);
        }
    }

    info!(
        bind = %bind,
        auth_mode = %config.auth.mode,
        udp_enabled = config.udp.enabled,
        outbound_ip_mode = %config.server.outbound_ip_mode,
        "socks5 listener configured"
    );

    Ok(())
}

fn primary_user(users: &[UserConfig]) -> Result<&UserConfig, AppError> {
    let user = users
        .first()
        .ok_or_else(|| AppError::InvalidConfig("auth.users must not be empty".to_string()))?;

    if users.len() > 1 {
        warn!("multiple auth users configured; current implementation uses only the first entry");
    }

    Ok(user)
}

fn build_basic(user: &UserConfig) -> Result<Basic, AppError> {
    let username = NonEmptyStr::try_from(user.username.clone())
        .map_err(|err| AppError::InvalidConfig(format!("invalid username: {err}")))?;
    let password = NonEmptyStr::try_from(user.password.clone())
        .map_err(|err| AppError::InvalidConfig(format!("invalid password: {err}")))?;

    Ok(Basic::new(username, password))
}

fn build_udp_relay(config: &ProxyConfig) -> Result<DefaultUdpRelay, AppError> {
    let udp_bind_ip = parse_bind_ip(&config.server.bind)?;

    Ok(DefaultUdpRelay::default()
        .with_bind_interface(SocketAddress::new(udp_bind_ip, 0))
        .with_relay_timeout(Duration::from_secs(config.udp.idle_timeout_secs)))
}

fn parse_bind_ip(bind: &str) -> Result<IpAddr, AppError> {
    bind.parse().map_err(|_| {
        AppError::InvalidConfig("server.bind must be a valid IP address".to_string())
    })
}

async fn bind_listener(bind: SocketAddr) -> Result<TcpListener, AppError> {
    let mut opts = match bind {
        SocketAddr::V4(_) => SocketOptions::default_tcp(),
        SocketAddr::V6(_) => SocketOptions::default_tcp_v6(),
    };
    opts.address = Some(bind.into());
    opts.keep_alive = Some(true);
    opts.tcp_keep_alive = Some(default_tcp_keepalive());

    TcpListener::bind(opts)
        .await
        .map_err(|err| AppError::Boxed(err.to_string()))
}

fn build_keepalive_stream_connector() -> impl TcpStreamConnector<Error = BoxError> {
    move |addr| async move {
        let opts = keepalive_socket_options_for_addr(addr);
        let stream = Arc::<SocketOptions>::new(opts)
            .connect(addr)
            .await
            .map_err(|err| Box::new(err) as BoxError)?;
        Ok::<_, BoxError>(stream)
    }
}

fn keepalive_socket_options_for_addr(addr: SocketAddr) -> SocketOptions {
    let mut opts = match addr {
        SocketAddr::V4(_) => SocketOptions::default_tcp(),
        SocketAddr::V6(_) => SocketOptions::default_tcp_v6(),
    };
    opts.keep_alive = Some(true);
    opts.tcp_keep_alive = Some(default_tcp_keepalive());
    opts
}

fn default_tcp_keepalive() -> TcpKeepAlive {
    let mut keepalive = TcpKeepAlive::default();
    keepalive.time = Some(Duration::from_secs(30));
    #[cfg(not(any(
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "nto",
        target_os = "espidf",
        target_os = "vita",
        target_os = "haiku",
    )))]
    {
        keepalive.interval = Some(Duration::from_secs(10));
    }
    #[cfg(not(any(
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "windows",
        target_os = "nto",
        target_os = "espidf",
        target_os = "vita",
        target_os = "haiku",
    )))]
    {
        keepalive.retries = Some(3);
    }
    keepalive
}

fn spawn_socks5_listener<S>(
    graceful: &graceful::Shutdown,
    tcp_service: TcpListener,
    outbound_mode: (ConnectIpMode, DnsResolveIpMode),
    service: S,
) where
    S: Service<TcpStream> + Clone + Send + Sync + 'static,
    S::Error: std::fmt::Debug,
{
    let service = (
        AddInputExtensionLayer::new(outbound_mode.0),
        AddInputExtensionLayer::new(outbound_mode.1),
    )
        .into_layer(service);

    let logged_service = service_fn(move |stream: TcpStream| {
        let service = service.clone();
        async move {
            let socket_info = stream
                .extensions()
                .get::<rama::net::stream::SocketInfo>()
                .cloned();
            debug!(
                client = socket_info
                    .as_ref()
                    .map(|info| info.peer_addr().to_string())
                    .unwrap_or_default(),
                local = socket_info
                    .as_ref()
                    .and_then(|info| info.local_addr().map(|addr| addr.to_string()))
                    .unwrap_or_default(),
                "accepted socks5 client connection"
            );
            if let Err(err) = service.serve(stream).await {
                tracing::error!(error = ?err, "socks5 connection failed");
            } else {
                debug!("socks5 client connection finished");
            }
            Ok::<_, Infallible>(())
        }
    });

    graceful.spawn_task_fn(move |shutdown_guard| {
        tcp_service.serve_graceful(shutdown_guard, logged_service)
    });
}

fn outbound_mode_layers(
    config: &ProxyConfig,
) -> Result<(ConnectIpMode, DnsResolveIpMode), AppError> {
    match config.server.outbound_ip_mode.as_str() {
        "dual" => Ok((ConnectIpMode::Dual, DnsResolveIpMode::Dual)),
        "ipv4" => Ok((ConnectIpMode::Ipv4, DnsResolveIpMode::SingleIpV4)),
        "ipv6" => Ok((ConnectIpMode::Ipv6, DnsResolveIpMode::SingleIpV6)),
        "dual-prefer-ipv4" => Ok((ConnectIpMode::Dual, DnsResolveIpMode::DualPreferIpV4)),
        other => Err(AppError::InvalidConfig(format!(
            "unsupported server.outbound_ip_mode: {other}"
        ))),
    }
}

async fn logged_proxy_stream(req: ProxyRequest<TcpStream, TcpStream>) -> Result<(), BoxError> {
    let ProxyRequest {
        mut source,
        mut target,
    } = req;

    let source_peer = source.peer_addr().map(|addr| addr.to_string()).unwrap_or_default();
    let source_local = source.local_addr().map(|addr| addr.to_string()).unwrap_or_default();
    let target_peer = target.peer_addr().map(|addr| addr.to_string()).unwrap_or_default();
    let target_local = target.local_addr().map(|addr| addr.to_string()).unwrap_or_default();
    let started = tokio::time::Instant::now();

    debug!(
        client = %source_peer,
        client_local = %source_local,
        upstream = %target_peer,
        upstream_local = %target_local,
        "start socks5 stream proxy"
    );

    match tokio::io::copy_bidirectional(&mut source, &mut target).await {
        Ok((bytes_from_client, bytes_from_target)) => {
            debug!(
                client = %source_peer,
                upstream = %target_peer,
                bytes_from_client,
                bytes_from_target,
                elapsed_ms = started.elapsed().as_millis(),
                "socks5 stream proxy finished"
            );
            Ok(())
        }
        Err(err) if is_connection_error(&err) => {
            debug!(
                client = %source_peer,
                upstream = %target_peer,
                elapsed_ms = started.elapsed().as_millis(),
                error = ?err,
                "socks5 stream proxy ended with connection error"
            );
            Ok(())
        }
        Err(err) => {
            debug!(
                client = %source_peer,
                upstream = %target_peer,
                elapsed_ms = started.elapsed().as_millis(),
                error = ?err,
                "socks5 stream proxy failed"
            );
            Err(err.into())
        }
    }
}
