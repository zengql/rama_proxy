use super::*;
use crate::tunnel::{client_handshake, read_response, write_open_connect};
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
