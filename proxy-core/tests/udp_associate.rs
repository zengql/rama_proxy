use std::{
    error::Error,
    fs::{self, File},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const TEST_SECRET: &str = "udp-associate-e2e-secret";

#[test]
fn socks5_udp_associate_relays_datagrams_end_to_end() -> Result<(), Box<dyn Error>> {
    let temp_dir = TestDir::new("rama-proxy-udp-associate")?;
    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    echo_socket.set_read_timeout(Some(IO_TIMEOUT))?;
    let echo_addr = echo_socket.local_addr()?;
    let echo_thread = thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; 65535];
        let (len, peer) = echo_socket.recv_from(&mut buf)?;
        echo_socket.send_to(&buf[..len], peer)?;
        Ok(())
    });

    let server_port = unused_tcp_port(None)?;
    let socks5_port = unused_tcp_port(Some(server_port))?;

    let server_config_path = temp_dir.path().join("server.toml");
    let stats_socket_path = temp_dir.path().join("server.stats.sock");
    write_server_config(&server_config_path, server_port, 30)?;

    let mut server_command = Command::new(env!("CARGO_BIN_EXE_proxy-core"));
    server_command
        .arg("server")
        .arg("--config")
        .arg(&server_config_path)
        .arg("--stats-socket")
        .arg(&stats_socket_path);
    let mut server = TestProcess::spawn("server", server_command, temp_dir.path())?;
    wait_for_tcp(
        &mut server,
        SocketAddr::from((Ipv4Addr::LOCALHOST, server_port)),
    );

    let client_config_path = temp_dir.path().join("client.toml");
    write_client_config(&client_config_path, server_port, socks5_port, 2, true, 30)?;

    let mut client_command = Command::new(env!("CARGO_BIN_EXE_proxy-core"));
    client_command
        .arg("client")
        .arg("--config")
        .arg(&client_config_path);
    let mut client = TestProcess::spawn("client", client_command, temp_dir.path())?;
    wait_for_tcp(
        &mut client,
        SocketAddr::from((Ipv4Addr::LOCALHOST, socks5_port)),
    );

    let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, socks5_port))?;
    control.set_read_timeout(Some(IO_TIMEOUT))?;
    control.set_write_timeout(Some(IO_TIMEOUT))?;

    control.write_all(&[0x05, 0x01, 0x00])?;
    let mut method_reply = [0u8; 2];
    control.read_exact(&mut method_reply)?;
    assert_eq!(
        method_reply,
        [0x05, 0x00],
        "SOCKS5 no-auth negotiation failed"
    );

    control.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
    let mut associate_reply = [0u8; 4];
    control.read_exact(&mut associate_reply)?;
    assert_eq!(associate_reply[0], 0x05, "unexpected SOCKS5 version");
    assert_eq!(associate_reply[1], 0x00, "UDP ASSOCIATE was rejected");
    assert_eq!(associate_reply[2], 0x00, "unexpected SOCKS5 reserved byte");
    let relay_addr = read_socks5_address(&mut control, associate_reply[3])?;

    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    udp_client.set_read_timeout(Some(IO_TIMEOUT))?;
    udp_client.set_write_timeout(Some(IO_TIMEOUT))?;

    let payload = b"rama-proxy udp associate end-to-end";
    let datagram = build_socks5_udp_datagram(echo_addr, payload);
    udp_client.send_to(&datagram, relay_addr)?;

    let mut response = [0u8; 65535];
    let (len, response_from) = udp_client.recv_from(&mut response)?;
    assert_eq!(
        response_from, relay_addr,
        "UDP response did not come from the SOCKS5 relay"
    );

    let (source, response_payload) = parse_socks5_udp_datagram(&response[..len])?;
    assert_eq!(source, echo_addr, "UDP response source address mismatch");
    assert_eq!(response_payload, payload, "UDP response payload mismatch");

    drop(control);
    echo_thread
        .join()
        .map_err(|_| io::Error::other("UDP echo thread panicked"))??;

    server.ensure_running();
    client.ensure_running();
    Ok(())
}

#[test]
fn tcp_pool_warms_without_udp_associate() -> Result<(), Box<dyn Error>> {
    const POOL_SIZE: usize = 3;
    let temp_dir = TestDir::new("rama-proxy-pool-warmup")?;
    let server_port = unused_tcp_port(None)?;
    let socks5_port = unused_tcp_port(Some(server_port))?;

    let server_config_path = temp_dir.path().join("server.toml");
    let stats_socket_path = temp_dir.path().join("server.stats.sock");
    write_server_config(&server_config_path, server_port, 1)?;

    let mut server_command = Command::new(env!("CARGO_BIN_EXE_proxy-core"));
    server_command
        .arg("server")
        .arg("--config")
        .arg(&server_config_path)
        .arg("--stats-socket")
        .arg(&stats_socket_path);
    let mut server = TestProcess::spawn("server", server_command, temp_dir.path())?;
    wait_for_tcp(
        &mut server,
        SocketAddr::from((Ipv4Addr::LOCALHOST, server_port)),
    );

    let client_config_path = temp_dir.path().join("client.toml");
    write_client_config(
        &client_config_path,
        server_port,
        socks5_port,
        POOL_SIZE,
        false,
        1,
    )?;

    let mut client_command = Command::new(env!("CARGO_BIN_EXE_proxy-core"));
    client_command
        .arg("client")
        .arg("--config")
        .arg(&client_config_path);
    let mut client = TestProcess::spawn("client", client_command, temp_dir.path())?;
    wait_for_tcp(
        &mut client,
        SocketAddr::from((Ipv4Addr::LOCALHOST, socks5_port)),
    );

    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        server.ensure_running();
        client.ensure_running();

        let client_logs = client.logs();
        let server_logs = server.logs();
        let created = count_occurrences(&client_logs, "idle tunnel added to pool");
        let expected_count = format!("tunnel_count={POOL_SIZE}");
        let snapshot_has_pool = server_logs
            .lines()
            .filter(|line| line.contains("heartbeat tunnel snapshot sent"))
            .any(|line| line.contains(&expected_count));

        if created >= POOL_SIZE && snapshot_has_pool {
            return Ok(());
        }
        if Instant::now() >= deadline {
            panic!(
                "tcp pool did not warm without UDP ASSOCIATE: created={created}, expected={POOL_SIZE}\nclient:\n{client_logs}\nserver:\n{server_logs}"
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> io::Result<Self> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct TestProcess {
    name: &'static str,
    child: Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl TestProcess {
    fn spawn(name: &'static str, mut command: Command, temp_dir: &Path) -> io::Result<Self> {
        let stdout_path = temp_dir.join(format!("{name}.stdout.log"));
        let stderr_path = temp_dir.join(format!("{name}.stderr.log"));
        let stdout = File::create(&stdout_path)?;
        let stderr = File::create(&stderr_path)?;
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        Ok(Self {
            name,
            child,
            stdout_path,
            stderr_path,
        })
    }

    fn ensure_running(&mut self) {
        match self.child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => panic!(
                "{} exited unexpectedly with {status}\n{}",
                self.name,
                self.logs()
            ),
            Err(err) => panic!(
                "failed to inspect {} process: {err}\n{}",
                self.name,
                self.logs()
            ),
        }
    }

    fn logs(&self) -> String {
        let stdout = fs::read_to_string(&self.stdout_path).unwrap_or_default();
        let stderr = fs::read_to_string(&self.stderr_path).unwrap_or_default();
        format!("stdout:\n{stdout}\nstderr:\n{stderr}")
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_for_tcp(process: &mut TestProcess, addr: SocketAddr) {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        if let Ok(Some(status)) = process.child.try_wait() {
            panic!(
                "{} exited before listening on {addr} with {status}\n{}",
                process.name,
                process.logs()
            );
        }
        if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            drop(stream);
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "{} did not listen on {addr} within {}s\n{}",
                process.name,
                IO_TIMEOUT.as_secs(),
                process.logs()
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn unused_tcp_port(exclude: Option<u16>) -> io::Result<u16> {
    loop {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        if exclude != Some(port) {
            return Ok(port);
        }
    }
}

fn write_server_config(path: &Path, port: u16, heartbeat_interval_secs: u64) -> io::Result<()> {
    let content = format!(
        r#"[server]
bind = "127.0.0.1"
port = {port}
outbound_ip_mode = "ipv4"
workers = 0
handshake_timeout_secs = 5
max_handshakes = 64
udp_idle_timeout_secs = 30
tcp_keepalive_secs = 30
heartbeat_interval_secs = {heartbeat_interval_secs}
heartbeat_timeout_secs = 10

[auth]
shared_secret = "{TEST_SECRET}"
require_client_id = false

[tls]
enabled = false

[log]
level = "info"
format = "text"
"#
    );
    fs::write(path, content)
}

fn write_client_config(
    path: &Path,
    server_port: u16,
    socks5_port: u16,
    pool_size: usize,
    udp_enabled: bool,
    heartbeat_interval_secs: u64,
) -> io::Result<()> {
    let content = format!(
        r#"[client]
server_addr = "127.0.0.1:{server_port}"
shared_secret = "{TEST_SECRET}"
client_id = "udp-associate-e2e"
pool_size = {pool_size}
connect_timeout_secs = 5
heartbeat_interval_secs = {heartbeat_interval_secs}
heartbeat_timeout_secs = 10

[socks5]
bind = "127.0.0.1"
port = {socks5_port}
tcp_keepalive_secs = 30

[http_connect]
bind = "127.0.0.1"

[udp]
enabled = {udp_enabled}
idle_timeout_secs = 15

[auth]
mode = "none"
users = []

[tls]
enabled = false

[log]
level = "info"
format = "text"
"#
    );
    fs::write(path, content)
}

fn build_socks5_udp_datagram(destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(payload.len() + 10);
    packet.extend_from_slice(&[0x00, 0x00, 0x00]);
    match destination.ip() {
        IpAddr::V4(ip) => {
            packet.push(0x01);
            packet.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.push(0x04);
            packet.extend_from_slice(&ip.octets());
        }
    }
    packet.extend_from_slice(&destination.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn parse_socks5_udp_datagram(packet: &[u8]) -> Result<(SocketAddr, &[u8]), io::Error> {
    if packet.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 UDP datagram is too short",
        ));
    }
    if packet[0] != 0x00 || packet[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 UDP datagram has non-zero reserved bytes",
        ));
    }
    if packet[2] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected fragmented SOCKS5 UDP datagram",
        ));
    }
    parse_socks5_address(&packet[3..])
}

fn read_socks5_address<R: Read>(reader: &mut R, atyp: u8) -> Result<SocketAddr, io::Error> {
    let mut header = Vec::new();
    header.push(atyp);
    match atyp {
        0x01 => {
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes)?;
            header.extend_from_slice(&bytes);
        }
        0x03 => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len)?;
            header.push(len[0]);
            let mut domain = vec![0u8; len[0] as usize];
            reader.read_exact(&mut domain)?;
            header.extend_from_slice(&domain);
        }
        0x04 => {
            let mut bytes = [0u8; 16];
            reader.read_exact(&mut bytes)?;
            header.extend_from_slice(&bytes);
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 address type: {other}"),
            ));
        }
    }
    let mut port = [0u8; 2];
    reader.read_exact(&mut port)?;
    header.extend_from_slice(&port);
    parse_socks5_address(&header).map(|(addr, _)| addr)
}

fn parse_socks5_address(bytes: &[u8]) -> Result<(SocketAddr, &[u8]), io::Error> {
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing SOCKS5 address type",
        ));
    }
    match bytes[0] {
        0x01 if bytes.len() >= 7 => {
            let ip = Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]);
            let port = u16::from_be_bytes([bytes[5], bytes[6]]);
            Ok((SocketAddr::new(IpAddr::V4(ip), port), &bytes[7..]))
        }
        0x03 if bytes.len() >= 2 => {
            let len = bytes[1] as usize;
            if bytes.len() < 2 + len + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated SOCKS5 domain address",
                ));
            }
            let host = std::str::from_utf8(&bytes[2..2 + len])
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            let port = u16::from_be_bytes([bytes[2 + len], bytes[3 + len]]);
            let addr = format!("{host}:{port}")
                .parse::<SocketAddr>()
                .map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("SOCKS5 domain address is not an IP: {err}"),
                    )
                })?;
            Ok((addr, &bytes[2 + len + 2..]))
        }
        0x04 if bytes.len() >= 19 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[1..17]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([bytes[17], bytes[18]]);
            Ok((SocketAddr::new(IpAddr::V6(ip), port), &bytes[19..]))
        }
        0x01 | 0x03 | 0x04 => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated SOCKS5 address",
        )),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported SOCKS5 address type: {other}"),
        )),
    }
}
