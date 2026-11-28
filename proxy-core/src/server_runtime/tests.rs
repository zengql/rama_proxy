use super::*;
use crate::{
    config::UpstreamSocks5Config,
    tunnel::{client_handshake, read_response, write_open_connect, write_open_udp},
};
use rama::proxy::socks5::proto::{ReplyKind, SocksMethod, client, server};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

async fn start_tunnel(
    config: ServerConfigFile,
    stats: &ServerStatsRegistry,
    tls: Option<ServerTlsAcceptor>,
) -> (TcpStream, JoinHandle<Result<(), AppError>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, peer) = listener.accept().await.unwrap();
    let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let task = tokio::spawn(handle_connection(
        stream,
        peer,
        config,
        tls,
        stats.clone(),
        permit,
    ));
    (client, task)
}

async fn connect_target(client: &mut TcpStream, config: &ServerConfigFile, addr: SocketAddr) {
    client_handshake(client, &config.auth.shared_secret, "test-client")
        .await
        .unwrap();
    write_open_connect(client, &addr.to_string().parse().unwrap())
        .await
        .unwrap();
    read_response(client).await.unwrap();
}

#[tokio::test]
async fn tcp_tunnel_relays_response_after_client_half_close() {
    timeout(TEST_TIMEOUT, async {
        let stats = ServerStatsRegistry::new();
        let config = ServerConfigFile::default();
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (mut client, server) = start_tunnel(config.clone(), &stats, None).await;
        connect_target(&mut client, &config, origin.local_addr().unwrap()).await;
        let (mut upstream, _) = origin.accept().await.unwrap();

        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        upstream.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        upstream.write_all(b"response after EOF").await.unwrap();
        upstream.shutdown().await.unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response after EOF");
        server.await.unwrap().unwrap();
        assert_eq!(stats.snapshot().await.summary.total_connections, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn closing_one_active_tcp_tunnel_leaves_other_tunnels_running() {
    timeout(TEST_TIMEOUT, async {
        let stats = ServerStatsRegistry::new();
        let config = ServerConfigFile::default();
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = origin.local_addr().unwrap();
        let (mut client_a, server_a) = start_tunnel(config.clone(), &stats, None).await;
        connect_target(&mut client_a, &config, target).await;
        let (_upstream_a, _) = origin.accept().await.unwrap();
        let id_a = stats.snapshot().await.connections[0].id;

        let (mut client_b, server_b) = start_tunnel(config.clone(), &stats, None).await;
        connect_target(&mut client_b, &config, target).await;
        let (mut upstream_b, _) = origin.accept().await.unwrap();

        assert!(
            stats
                .close_client_connection_if_exists("test-client", id_a)
                .await
        );
        assert_eq!(client_a.read(&mut [0]).await.unwrap(), 0);
        server_a.await.unwrap().unwrap();
        client_b.write_all(b"ping").await.unwrap();
        let mut request = [0; 4];
        upstream_b.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        upstream_b.write_all(b"pong").await.unwrap();
        let mut response = [0; 4];
        client_b.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        client_b.shutdown().await.unwrap();
        upstream_b.shutdown().await.unwrap();
        server_b.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

async fn upstream_listener() -> (ServerConfigFile, TcpListener) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let config = ServerConfigFile {
        upstream: Some(UpstreamSocks5Config {
            address: listener.local_addr().unwrap().into(),
            username: None,
            password: None,
            connect_timeout_secs: None,
        }),
        ..ServerConfigFile::default()
    };
    (config, listener)
}

#[tokio::test]
async fn tcp_tunnel_connects_to_authenticated_upstream_with_original_hostname() {
    timeout(TEST_TIMEOUT, async {
        let stats = ServerStatsRegistry::new();
        let (mut config, upstream) = upstream_listener().await;
        let proxy = config.upstream.as_mut().unwrap();
        proxy.username = Some("proxy-user".to_string());
        proxy.password = Some("proxy-password".to_string());
        let target: HostWithPort = "only-at-upstream.invalid:443".parse().unwrap();
        let expected_target = target.clone();
        let mock = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let header = client::Header::read_from(&mut stream).await.unwrap();
            assert_eq!(header.methods.as_slice(), &[SocksMethod::UsernamePassword]);
            server::Header::new(SocksMethod::UsernamePassword)
                .write_to(&mut stream)
                .await
                .unwrap();
            let auth = client::UsernamePasswordRequest::read_from(&mut stream)
                .await
                .unwrap();
            assert_eq!(auth.basic.username(), "proxy-user");
            assert_eq!(auth.basic.password(), Some("proxy-password"));
            server::UsernamePasswordResponse::new_success()
                .write_to(&mut stream)
                .await
                .unwrap();
            let request = client::Request::read_from(&mut stream).await.unwrap();
            assert_eq!(request.command, Command::Connect);
            assert_eq!(request.destination, expected_target);
            server::Reply::new(HostWithPort::from((Ipv4Addr::UNSPECIFIED, 0)))
                .write_to(&mut stream)
                .await
                .unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let (mut tunnel, server) = start_tunnel(config.clone(), &stats, None).await;
        client_handshake(&mut tunnel, &config.auth.shared_secret, "test-client")
            .await
            .unwrap();
        write_open_connect(&mut tunnel, &target).await.unwrap();
        read_response(&mut tunnel).await.unwrap();
        tunnel.write_all(b"ping").await.unwrap();
        let mut payload = [0; 4];
        tunnel.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"pong");
        tunnel.shutdown().await.unwrap();
        mock.await.unwrap();
        server.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn upstream_rejections_do_not_fall_back_to_direct_tcp_or_udp() {
    timeout(TEST_TIMEOUT, async {
        let stats = ServerStatsRegistry::new();
        let (config, upstream) = upstream_listener().await;
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = HostWithPort::from(origin.local_addr().unwrap());
        let mock = tokio::spawn(async move {
            for command in [Command::Connect, Command::UdpAssociate] {
                let (mut stream, _) = upstream.accept().await.unwrap();
                let header = client::Header::read_from(&mut stream).await.unwrap();
                assert_eq!(
                    header.methods.as_slice(),
                    &[SocksMethod::NoAuthenticationRequired]
                );
                server::Header::new(SocksMethod::NoAuthenticationRequired)
                    .write_to(&mut stream)
                    .await
                    .unwrap();
                let request = client::Request::read_from(&mut stream).await.unwrap();
                assert_eq!(request.command, command);
                server::Reply::error_reply(ReplyKind::CommandNotSupported)
                    .write_to(&mut stream)
                    .await
                    .unwrap();
            }
        });

        for command in [Command::Connect, Command::UdpAssociate] {
            let (mut tunnel, server) = start_tunnel(config.clone(), &stats, None).await;
            client_handshake(&mut tunnel, &config.auth.shared_secret, "test-client")
                .await
                .unwrap();
            if command == Command::Connect {
                write_open_connect(&mut tunnel, &target).await.unwrap();
            } else {
                write_open_udp(&mut tunnel).await.unwrap();
            }
            let err = read_response(&mut tunnel).await.unwrap_err();
            assert!(err.to_string().contains("CommandNotSupported"), "{err}");
            assert!(server.await.unwrap().is_err());
        }
        mock.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn udp_tunnel_relays_datagrams_and_closes_with_upstream_control() {
    timeout(TEST_TIMEOUT, async {
        let stats = ServerStatsRegistry::new();
        let (config, upstream) = upstream_listener().await;
        let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target: HostWithPort = "only-at-upstream.invalid:53".parse().unwrap();
        let expected_target = target.clone();
        let answer: HostWithPort = "192.0.2.8:53".parse().unwrap();
        let source = answer.clone();
        let (close_tx, close_rx) = tokio::sync::oneshot::channel();
        let mock = tokio::spawn(async move {
            let (mut control, _) = upstream.accept().await.unwrap();
            client::Header::read_from(&mut control).await.unwrap();
            server::Header::new(SocksMethod::NoAuthenticationRequired)
                .write_to(&mut control)
                .await
                .unwrap();
            let request = client::Request::read_from(&mut control).await.unwrap();
            assert_eq!(request.command, Command::UdpAssociate);
            assert_eq!(
                request.destination,
                HostWithPort::from((Ipv4Addr::UNSPECIFIED, 0))
            );
            let bind =
                HostWithPort::from((Ipv4Addr::UNSPECIFIED, relay.local_addr().unwrap().port()));
            server::Reply::new(bind)
                .write_to(&mut control)
                .await
                .unwrap();

            let mut buf = [0; 512];
            let (n, from) = relay.recv_from(&mut buf).await.unwrap();
            let (destination, payload) = parse_socks5_udp_datagram(&buf[..n]).unwrap();
            assert_eq!(destination, expected_target);
            assert_eq!(payload, b"dns request");
            relay
                .send_to(&build_socks5_udp_datagram(&source, b"dns response"), from)
                .await
                .unwrap();
            close_rx.await.unwrap();
        });

        let (mut tunnel, server) = start_tunnel(config.clone(), &stats, None).await;
        client_handshake(&mut tunnel, &config.auth.shared_secret, "test-client")
            .await
            .unwrap();
        write_open_udp(&mut tunnel).await.unwrap();
        read_response(&mut tunnel).await.unwrap();
        write_udp_packet(&mut tunnel, &target, b"dns request")
            .await
            .unwrap();
        assert!(opcode_is_udp_packet(
            read_opcode(&mut tunnel).await.unwrap()
        ));
        let (source, payload) = read_udp_packet(&mut tunnel).await.unwrap();
        assert_eq!(source, answer);
        assert_eq!(payload, b"dns response");
        close_tx.send(()).unwrap();
        assert!(opcode_is_close(read_opcode(&mut tunnel).await.unwrap()));
        mock.await.unwrap();
        server.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn upstream_auth_failure_and_unreachable_do_not_fall_back_to_direct() {
    timeout(TEST_TIMEOUT, async {
        let stats = ServerStatsRegistry::new();
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = HostWithPort::from(origin.local_addr().unwrap());

        // Case 1 & 2: NoAcceptableMethods and UsernamePassword auth rejection
        let (mut config, upstream) = upstream_listener().await;
        let proxy = config.upstream.as_mut().unwrap();
        proxy.username = Some("proxy-user".to_string());
        proxy.password = Some("wrong-password".to_string());
        let mock = tokio::spawn(async move {
            // Case 1: reject auth method
            let (mut stream, _) = upstream.accept().await.unwrap();
            let header = client::Header::read_from(&mut stream).await.unwrap();
            assert_eq!(header.methods.as_slice(), &[SocksMethod::UsernamePassword]);
            server::Header::new(SocksMethod::NoAcceptableMethods)
                .write_to(&mut stream)
                .await
                .unwrap();

            // Case 2: accept method, reject credentials (RFC 1929 status = 0x01)
            let (mut stream, _) = upstream.accept().await.unwrap();
            client::Header::read_from(&mut stream).await.unwrap();
            server::Header::new(SocksMethod::UsernamePassword)
                .write_to(&mut stream)
                .await
                .unwrap();
            client::UsernamePasswordRequest::read_from(&mut stream)
                .await
                .unwrap();
            stream.write_all(&[0x01, 0x01]).await.unwrap();
        });

        let (mut tunnel, server) = start_tunnel(config.clone(), &stats, None).await;
        client_handshake(&mut tunnel, &config.auth.shared_secret, "test-client")
            .await
            .unwrap();
        write_open_connect(&mut tunnel, &target).await.unwrap();
        let err = read_response(&mut tunnel).await.unwrap_err();
        assert!(
            err.to_string().contains("unexpected authentication method"),
            "{err}"
        );
        assert!(server.await.unwrap().is_err());

        let (mut tunnel, server) = start_tunnel(config.clone(), &stats, None).await;
        client_handshake(&mut tunnel, &config.auth.shared_secret, "test-client")
            .await
            .unwrap();
        write_open_connect(&mut tunnel, &target).await.unwrap();
        let err = read_response(&mut tunnel).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("rejected username/password authentication"),
            "{err}"
        );
        assert!(server.await.unwrap().is_err());
        mock.await.unwrap();

        // Case 3: upstream port is closed / unreachable
        let (closed_config, closed_listener) = upstream_listener().await;
        drop(closed_listener);
        let (mut tunnel, server) = start_tunnel(closed_config.clone(), &stats, None).await;
        client_handshake(
            &mut tunnel,
            &closed_config.auth.shared_secret,
            "test-client",
        )
        .await
        .unwrap();
        write_open_connect(&mut tunnel, &target).await.unwrap();
        assert!(read_response(&mut tunnel).await.is_err());
        assert!(server.await.unwrap().is_err());

        // Ensure local origin never received any direct fallback connection.
        assert!(
            timeout(Duration::from_millis(50), origin.accept())
                .await
                .is_err()
        );
    })
    .await
    .unwrap();
}

#[test]
fn upstream_toml_is_optional_and_validates_credentials_and_port() {
    let direct = toml::from_str::<ServerConfigFile>("").unwrap();
    assert!(direct.upstream.is_none());
    direct.validate().unwrap();
    let upstream = toml::from_str::<ServerConfigFile>(
        "[upstream]\naddress = \"proxy.example.com:1080\"\nconnect_timeout_secs = 15",
    )
    .unwrap();
    upstream.validate().unwrap();

    let too_long = "a".repeat(256);
    let long_user_toml = format!(
        "[upstream]\naddress = \"proxy.example.com:1080\"\nusername = \"{too_long}\"\npassword = \"pass\""
    );
    let long_pass_toml = format!(
        "[upstream]\naddress = \"proxy.example.com:1080\"\nusername = \"user\"\npassword = \"{too_long}\""
    );

    for invalid in [
        "[upstream]\naddress = \"proxy.example.com:0\"",
        "[upstream]\naddress = \"proxy.example.com:1080\"\nconnect_timeout_secs = 0",
        "[upstream]\naddress = \"proxy.example.com:1080\"\nusername = \"only-user\"",
        "[upstream]\naddress = \"proxy.example.com:1080\"\nusername = \"user\"\npassword = \"\"",
        long_user_toml.as_str(),
        long_pass_toml.as_str(),
    ] {
        assert!(
            toml::from_str::<ServerConfigFile>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    assert!(
        toml::from_str::<ServerConfigFile>(
            "[upstream]\naddress = \"proxy.example.com:1080\"\nunknown_field = true"
        )
        .is_err()
    );
}

#[derive(Debug)]
struct NoCertificate;

impl rustls::server::ResolvesServerCert for NoCertificate {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }
}

#[tokio::test]
async fn failed_and_timed_out_tls_handshakes_remove_connection_records() {
    let stats = ServerStatsRegistry::new();
    let mut config = ServerConfigFile::default();
    config.server.handshake_timeout_secs = 1;
    let tls = ServerTlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertificate)),
    ));

    let (mut invalid, failed) = start_tunnel(config.clone(), &stats, Some(tls.clone())).await;
    invalid.write_all(b"not TLS").await.unwrap();
    assert!(
        timeout(TEST_TIMEOUT, failed)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let after_failure = stats.snapshot().await;
    assert_eq!(after_failure.summary.total_connections, 0);
    assert_eq!(after_failure.handshake_timeouts, 0);

    let (_idle, timed_out) = start_tunnel(config, &stats, Some(tls)).await;
    assert!(
        timeout(TEST_TIMEOUT, timed_out)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let after_timeout = stats.snapshot().await;
    assert_eq!(after_timeout.summary.total_connections, 0);
    assert_eq!(after_timeout.handshake_timeouts, 1);
}

#[tokio::test]
async fn tcp_relay_expires_when_a_half_closed_peer_stops_responding() {
    timeout(TEST_TIMEOUT, async {
        let (mut client, mut tunnel) = tokio::io::duplex(64);
        let (mut upstream, mut target) = tokio::io::duplex(64);
        let relay = tokio::spawn(async move {
            relay::copy_with_idle_timeout(&mut tunnel, &mut upstream, Duration::from_millis(250))
                .await
                .unwrap()
        });

        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        target.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");

        assert_eq!(relay.await.unwrap(), None);
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
        assert!(target.write_all(b"late reply").await.is_err());
    })
    .await
    .unwrap();
}
