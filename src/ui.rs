use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::cli::UiCommand;
use crate::error::AppError;
use crate::server_stats::ServerStatsSnapshot;

#[cfg(unix)]
use crate::server_stats::query_snapshot as query_server_stats_snapshot;

pub async fn run(cmd: UiCommand) -> Result<(), AppError> {
    if !cfg!(target_os = "linux") {
        return Err(AppError::InvalidConfig(
            "ui mode currently supports Linux /proc only".to_string(),
        ));
    }

    let bind_ip = IpAddr::from_str(&cmd.bind)
        .map_err(|_| AppError::InvalidConfig("ui --bind must be a valid IP address".to_string()))?;
    let listen_addr = SocketAddr::new(bind_ip, cmd.port);
    let pid_file = absolutize_path(&cmd.pid_file)?;
    let stats_socket = absolutize_path(&cmd.stats_socket)?;

    let state = Arc::new(AppState {
        snapshot: RwLock::new(None),
    });

    let poller_state = state.clone();
    let poller_pid_file = pid_file.clone();
    let poller_stats_socket = stats_socket.clone();
    let poller_interval = Duration::from_millis(cmd.interval_ms.max(500));
    tokio::spawn(async move {
        let mut poller = Poller::new(poller_pid_file, poller_stats_socket, poller_interval);
        poller.run(poller_state).await;
    });

    let listener = TcpListener::bind(listen_addr).await?;
    info!(bind = %listen_addr, pid_file = %pid_file.display(), stats_socket = %stats_socket.display(), "ui server started");

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_http(stream, state).await {
                debug!(client = %peer, error = %err, "ui request failed");
            }
        });
    }
}

struct AppState {
    snapshot: RwLock<Option<UiSnapshot>>,
}

struct Poller {
    pid_file: PathBuf,
    stats_socket: PathBuf,
    interval: Duration,
    fd_seen: HashMap<u32, Instant>,
    socket_seen: HashMap<u64, Instant>,
}

impl Poller {
    fn new(pid_file: PathBuf, stats_socket: PathBuf, interval: Duration) -> Self {
        Self {
            pid_file,
            stats_socket,
            interval,
            fd_seen: HashMap::new(),
            socket_seen: HashMap::new(),
        }
    }

    async fn run(&mut self, state: Arc<AppState>) {
        loop {
            let snapshot = self.collect_snapshot().await;
            match snapshot {
                Ok(snapshot) => {
                    *state.snapshot.write().await = Some(snapshot);
                }
                Err(err) => {
                    warn!("ui sampling failed: {err}");
                    *state.snapshot.write().await = Some(UiSnapshot::error(
                        self.pid_file.display().to_string(),
                        err.to_string(),
                    ));
                }
            }
            tokio::time::sleep(self.interval).await;
        }
    }

    async fn collect_snapshot(&mut self) -> Result<UiSnapshot, AppError> {
        let pid = read_pid(&self.pid_file)?;
        let process = read_process_info(pid, &self.pid_file)?;
        let socket_map = read_socket_table_map()?;
        let mut fd_entries = read_fd_entries(pid, &self.fd_seen, &socket_map)?;
        let listen_ports = detect_server_listen_ports(&fd_entries);
        let live_stats = self.query_live_stats().await;
        let mut sockets = Vec::new();
        let mut summary = Summary::default();

        let now = now_unix_secs();
        for fd in &mut fd_entries {
            self.fd_seen.entry(fd.fd).or_insert_with(Instant::now);
            summary.total_fds += 1;
            match fd.kind.as_str() {
                "socket" => summary.socket_fds += 1,
                "anon_inode" => summary.anon_inode_fds += 1,
                "pipe" => summary.pipe_fds += 1,
                "file" => summary.file_fds += 1,
                _ => summary.other_fds += 1,
            }

            if let Some(socket) = &fd.socket {
                self.socket_seen
                    .entry(socket.inode)
                    .or_insert_with(Instant::now);
                let role = classify_socket_role(socket, &listen_ports);
                let entry = SocketEntry {
                    fd: fd.fd,
                    inode: socket.inode,
                    protocol: socket.protocol.clone(),
                    state: socket.state.clone(),
                    local_addr: socket.local_addr.clone(),
                    remote_addr: socket.remote_addr.clone(),
                    is_listener: socket.is_listener,
                    role: role.as_str().to_string(),
                    observed_secs: observed_secs(&self.socket_seen, socket.inode),
                };
                fd.role = role.as_str().to_string();
                classify_socket(&entry, &mut summary);
                sockets.push(entry);
            } else {
                fd.role = classify_non_socket_fd_role(&fd.kind).to_string();
            }

            classify_fd(fd, &mut summary);
        }

        let active_socket_inodes: HashMap<u64, ()> =
            sockets.iter().map(|s| (s.inode, ())).collect();
        self.socket_seen
            .retain(|inode, _| active_socket_inodes.contains_key(inode));
        let active_fd_map: HashMap<u32, ()> = fd_entries.iter().map(|f| (f.fd, ())).collect();
        self.fd_seen.retain(|fd, _| active_fd_map.contains_key(fd));

        fd_entries.sort_by_key(|fd| fd.fd);
        sockets.sort_by(|a, b| a.fd.cmp(&b.fd));

        let (live_stats, live_stats_error) = match live_stats {
            Ok(stats) => (Some(stats), None),
            Err(err) => (None, Some(err.to_string())),
        };

        Ok(UiSnapshot {
            ok: true,
            error: None,
            collected_at_unix_secs: now,
            pid_file: self.pid_file.display().to_string(),
            stats_socket: self.stats_socket.display().to_string(),
            process: Some(process),
            summary,
            sockets,
            fds: fd_entries,
            live_stats,
            live_stats_error,
        })
    }

    async fn query_live_stats(&self) -> Result<ServerStatsSnapshot, AppError> {
        #[cfg(unix)]
        {
            query_server_stats_snapshot(&self.stats_socket).await
        }
        #[cfg(not(unix))]
        {
            Err(AppError::InvalidConfig(
                "ui live stats requires unix stats socket support".to_string(),
            ))
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct UiSnapshot {
    ok: bool,
    error: Option<String>,
    collected_at_unix_secs: u64,
    pid_file: String,
    stats_socket: String,
    process: Option<ProcessInfo>,
    summary: Summary,
    sockets: Vec<SocketEntry>,
    fds: Vec<FdEntry>,
    live_stats: Option<ServerStatsSnapshot>,
    live_stats_error: Option<String>,
}

impl UiSnapshot {
    fn error(pid_file: String, message: String) -> Self {
        Self {
            ok: false,
            error: Some(message),
            collected_at_unix_secs: now_unix_secs(),
            pid_file,
            stats_socket: "unknown".to_string(),
            process: None,
            summary: Summary::default(),
            sockets: Vec::new(),
            fds: Vec::new(),
            live_stats: None,
            live_stats_error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
struct Summary {
    total_fds: usize,
    socket_fds: usize,
    anon_inode_fds: usize,
    pipe_fds: usize,
    file_fds: usize,
    other_fds: usize,
    listener_sockets: usize,
    established_sockets: usize,
    tcp_sockets: usize,
    udp_sockets: usize,
    client_srv_sockets: usize,
    srv_external_sockets: usize,
    srv_internal_sockets: usize,
    client_srv_fds: usize,
    srv_external_fds: usize,
    srv_internal_fds: usize,
    loopback_peer_sockets: usize,
    external_peer_sockets: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ProcessInfo {
    pid: u32,
    name: String,
    cmdline: String,
    start_time_unix_secs: Option<u64>,
    uptime_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct FdEntry {
    fd: u32,
    kind: String,
    role: String,
    target: String,
    inode: Option<u64>,
    observed_secs: Option<u64>,
    socket: Option<SocketDetails>,
}

#[derive(Debug, Clone, Serialize)]
struct SocketEntry {
    fd: u32,
    inode: u64,
    protocol: String,
    state: String,
    local_addr: String,
    remote_addr: String,
    is_listener: bool,
    role: String,
    observed_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct SocketDetails {
    inode: u64,
    protocol: String,
    state: String,
    local_addr: String,
    remote_addr: String,
    is_listener: bool,
}

#[derive(Debug, Clone)]
struct SocketMeta {
    inode: u64,
    protocol: String,
    state: String,
    local_addr: String,
    remote_addr: String,
    is_listener: bool,
}

fn read_pid(pid_file: &Path) -> Result<u32, AppError> {
    let raw = fs::read_to_string(pid_file)?;
    raw.trim()
        .parse::<u32>()
        .map_err(|_| AppError::InvalidConfig(format!("invalid pid in {}", pid_file.display())))
}

fn read_process_info(pid: u32, pid_file: &Path) -> Result<ProcessInfo, AppError> {
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));
    if !proc_dir.exists() {
        return Err(AppError::InvalidConfig(format!(
            "target pid {pid} from {} does not exist",
            pid_file.display()
        )));
    }

    let name = fs::read_to_string(proc_dir.join("comm"))
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();
    let cmdline = fs::read(proc_dir.join("cmdline"))
        .map(|bytes| {
            bytes
                .split(|b| *b == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();

    let start_time_unix_secs = read_process_start_time_unix_secs(pid).ok();
    let uptime_secs = start_time_unix_secs.map(|start| now_unix_secs().saturating_sub(start));

    Ok(ProcessInfo {
        pid,
        name,
        cmdline,
        start_time_unix_secs,
        uptime_secs,
    })
}

fn read_process_start_time_unix_secs(pid: u32) -> Result<u64, AppError> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| AppError::InvalidConfig(format!("invalid /proc/{pid}/stat format")))?;
    let rest = stat
        .get(close + 2..)
        .ok_or_else(|| AppError::InvalidConfig(format!("invalid /proc/{pid}/stat fields")))?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() <= 19 {
        return Err(AppError::InvalidConfig(format!(
            "not enough fields in /proc/{pid}/stat"
        )));
    }

    let start_ticks = fields[19]
        .parse::<u64>()
        .map_err(|_| AppError::InvalidConfig(format!("invalid start time in /proc/{pid}/stat")))?;
    let uptime = fs::read_to_string("/proc/uptime")?;
    let uptime_secs = uptime
        .split_whitespace()
        .next()
        .ok_or_else(|| AppError::InvalidConfig("invalid /proc/uptime".to_string()))?
        .parse::<f64>()
        .map_err(|_| AppError::InvalidConfig("invalid /proc/uptime value".to_string()))?;
    let ticks_per_sec = 100_u64;
    let start_since_boot_secs = start_ticks / ticks_per_sec;
    let proc_uptime_secs = uptime_secs.max(0.0) as u64;
    let now = now_unix_secs();
    Ok(now
        .saturating_sub(proc_uptime_secs)
        .saturating_add(start_since_boot_secs))
}

fn read_fd_entries(
    pid: u32,
    seen: &HashMap<u32, Instant>,
    socket_map: &HashMap<u64, SocketMeta>,
) -> Result<Vec<FdEntry>, AppError> {
    let fd_dir = PathBuf::from(format!("/proc/{pid}/fd"));
    let mut entries = Vec::new();

    for item in fs::read_dir(fd_dir)? {
        let item = item?;
        let fd_name = item.file_name().to_string_lossy().to_string();
        let fd = match fd_name.parse::<u32>() {
            Ok(fd) => fd,
            Err(_) => continue,
        };
        let target = fs::read_link(item.path())
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_else(|_| "<unreadable>".to_string());
        let (kind, inode) = classify_fd_target(&target);
        let socket = inode
            .and_then(|inode| socket_map.get(&inode).cloned())
            .map(|meta| SocketDetails {
                inode: meta.inode,
                protocol: meta.protocol,
                state: meta.state,
                local_addr: meta.local_addr,
                remote_addr: meta.remote_addr,
                is_listener: meta.is_listener,
            });

        entries.push(FdEntry {
            fd,
            kind,
            role: "unknown".to_string(),
            target,
            inode,
            observed_secs: seen.get(&fd).map(|at| at.elapsed().as_secs()),
            socket,
        });
    }

    Ok(entries)
}

fn read_socket_table_map() -> Result<HashMap<u64, SocketMeta>, AppError> {
    let mut map = HashMap::new();
    for (path, protocol) in [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp6"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp6"),
    ] {
        let table = read_socket_table(path, protocol)?;
        for entry in table {
            map.insert(entry.inode, entry);
        }
    }
    Ok(map)
}

fn read_socket_table(path: &str, protocol: &str) -> Result<Vec<SocketMeta>, AppError> {
    let content = fs::read_to_string(path)?;
    let mut entries = Vec::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let local_addr = decode_proc_addr(cols[1], protocol.ends_with('6'))?;
        let remote_addr = decode_proc_addr(cols[2], protocol.ends_with('6'))?;
        let state_hex = cols[3];
        let inode = match cols.get(9).and_then(|value| value.parse::<u64>().ok()) {
            Some(inode) => inode,
            None => continue,
        };
        let state = decode_socket_state(state_hex, protocol);
        let is_listener = protocol.starts_with("tcp") && state == "LISTEN";
        entries.push(SocketMeta {
            inode,
            protocol: protocol.to_string(),
            state,
            local_addr,
            remote_addr,
            is_listener,
        });
    }
    Ok(entries)
}

fn decode_proc_addr(raw: &str, is_v6: bool) -> Result<String, AppError> {
    let mut parts = raw.split(':');
    let ip_hex = parts
        .next()
        .ok_or_else(|| AppError::InvalidConfig(format!("invalid socket addr {raw}")))?;
    let port_hex = parts
        .next()
        .ok_or_else(|| AppError::InvalidConfig(format!("invalid socket addr {raw}")))?;
    let port = u16::from_str_radix(port_hex, 16)
        .map_err(|_| AppError::InvalidConfig(format!("invalid socket port {raw}")))?;

    let ip = if is_v6 {
        decode_ipv6(ip_hex)?
    } else {
        decode_ipv4(ip_hex)?
    };
    match ip {
        IpAddr::V4(ip) => Ok(format!("{ip}:{port}")),
        IpAddr::V6(ip) => Ok(format!("[{ip}]:{port}")),
    }
}

fn decode_ipv4(hex: &str) -> Result<IpAddr, AppError> {
    if hex.len() != 8 {
        return Err(AppError::InvalidConfig(format!("invalid ipv4 hex {hex}")));
    }
    let mut bytes = [0u8; 4];
    for i in 0..4 {
        let part = &hex[i * 2..i * 2 + 2];
        bytes[3 - i] = u8::from_str_radix(part, 16)
            .map_err(|_| AppError::InvalidConfig(format!("invalid ipv4 hex {hex}")))?;
    }
    Ok(IpAddr::V4(Ipv4Addr::from(bytes)))
}

fn decode_ipv6(hex: &str) -> Result<IpAddr, AppError> {
    if hex.len() != 32 {
        return Err(AppError::InvalidConfig(format!("invalid ipv6 hex {hex}")));
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        let part = &hex[i * 2..i * 2 + 2];
        bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|_| AppError::InvalidConfig(format!("invalid ipv6 hex {hex}")))?;
    }
    for chunk in bytes.chunks_mut(4) {
        chunk.reverse();
    }
    Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
}

fn decode_socket_state(state: &str, protocol: &str) -> String {
    match (protocol.starts_with("tcp"), state) {
        (true, "01") => "ESTABLISHED".to_string(),
        (true, "02") => "SYN_SENT".to_string(),
        (true, "03") => "SYN_RECV".to_string(),
        (true, "04") => "FIN_WAIT1".to_string(),
        (true, "05") => "FIN_WAIT2".to_string(),
        (true, "06") => "TIME_WAIT".to_string(),
        (true, "07") => "CLOSE".to_string(),
        (true, "08") => "CLOSE_WAIT".to_string(),
        (true, "09") => "LAST_ACK".to_string(),
        (true, "0A") => "LISTEN".to_string(),
        (true, "0B") => "CLOSING".to_string(),
        (false, "07") => "UNCONN".to_string(),
        _ => state.to_string(),
    }
}

fn classify_fd_target(target: &str) -> (String, Option<u64>) {
    if let Some(inode) = extract_inode(target, "socket:[", ']') {
        return ("socket".to_string(), Some(inode));
    }
    if target.starts_with("anon_inode:") {
        return ("anon_inode".to_string(), None);
    }
    if target.starts_with("pipe:[") {
        return ("pipe".to_string(), None);
    }
    if target.starts_with('/') {
        return ("file".to_string(), None);
    }
    ("other".to_string(), None)
}

fn extract_inode(target: &str, prefix: &str, suffix: char) -> Option<u64> {
    let raw = target.strip_prefix(prefix)?.strip_suffix(suffix)?;
    raw.parse::<u64>().ok()
}

fn classify_socket(entry: &SocketEntry, summary: &mut Summary) {
    if entry.is_listener {
        summary.listener_sockets += 1;
    }
    if entry.state == "ESTABLISHED" {
        summary.established_sockets += 1;
    }
    if entry.protocol.starts_with("tcp") {
        summary.tcp_sockets += 1;
    }
    if entry.protocol.starts_with("udp") {
        summary.udp_sockets += 1;
    }
    match entry.role.as_str() {
        "client-srv" => summary.client_srv_sockets += 1,
        "srv-external" => summary.srv_external_sockets += 1,
        _ => summary.srv_internal_sockets += 1,
    }

    let remote_ip = parse_socket_ip(&entry.remote_addr);
    if let Some(remote_ip) = remote_ip {
        if remote_ip.is_loopback() {
            summary.loopback_peer_sockets += 1;
        } else if !entry.is_listener && !remote_addr_is_unspecified(&entry.remote_addr) {
            summary.external_peer_sockets += 1;
        }
    }
}

fn classify_fd(entry: &FdEntry, summary: &mut Summary) {
    match entry.role.as_str() {
        "client-srv" => summary.client_srv_fds += 1,
        "srv-external" => summary.srv_external_fds += 1,
        _ => summary.srv_internal_fds += 1,
    }
}

fn classify_non_socket_fd_role(kind: &str) -> &'static str {
    match kind {
        "socket" => "unknown",
        _ => "srv-internal",
    }
}

fn detect_server_listen_ports(entries: &[FdEntry]) -> Vec<u16> {
    let mut ports = Vec::new();
    for entry in entries {
        let Some(socket) = &entry.socket else {
            continue;
        };
        if !socket.is_listener || !socket.protocol.starts_with("tcp") {
            continue;
        }
        if let Some(port) = parse_socket_port(&socket.local_addr) {
            ports.push(port);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn classify_socket_role(socket: &SocketDetails, listen_ports: &[u16]) -> SocketRole {
    if socket.is_listener {
        return SocketRole::SrvInternal;
    }
    if socket.protocol.starts_with("udp") {
        return SocketRole::SrvInternal;
    }
    if !socket.protocol.starts_with("tcp") {
        return SocketRole::Unknown;
    }
    let local_port = parse_socket_port(&socket.local_addr);
    if socket.state == "ESTABLISHED"
        && local_port
            .map(|port| listen_ports.contains(&port))
            .unwrap_or(false)
    {
        return SocketRole::ClientSrv;
    }
    if socket.state == "ESTABLISHED" && !remote_addr_is_unspecified(&socket.remote_addr) {
        return SocketRole::SrvExternal;
    }
    SocketRole::SrvInternal
}

#[derive(Debug, Clone, Copy)]
enum SocketRole {
    ClientSrv,
    SrvExternal,
    SrvInternal,
    Unknown,
}

impl SocketRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::ClientSrv => "client-srv",
            Self::SrvExternal => "srv-external",
            Self::SrvInternal => "srv-internal",
            Self::Unknown => "unknown",
        }
    }
}

fn parse_socket_ip(addr: &str) -> Option<IpAddr> {
    if let Some(stripped) = addr.strip_prefix('[') {
        let end = stripped.find(']')?;
        return stripped[..end].parse::<IpAddr>().ok();
    }
    let pos = addr.rfind(':')?;
    addr[..pos].parse::<IpAddr>().ok()
}

fn parse_socket_port(addr: &str) -> Option<u16> {
    if addr.starts_with('[') {
        let end = addr.find(']')?;
        let port = addr.get(end + 2..)?;
        return port.parse::<u16>().ok();
    }
    let pos = addr.rfind(':')?;
    addr.get(pos + 1..)?.parse::<u16>().ok()
}

fn remote_addr_is_unspecified(addr: &str) -> bool {
    addr == "0.0.0.0:0" || addr == "[::]:0"
}

fn observed_secs<T>(seen: &HashMap<T, Instant>, key: T) -> Option<u64>
where
    T: Eq + std::hash::Hash,
{
    seen.get(&key).map(|at| at.elapsed().as_secs())
}

fn absolutize_path(path: &Path) -> Result<PathBuf, AppError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(path))
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

async fn handle_http(mut stream: TcpStream, state: Arc<AppState>) -> Result<(), AppError> {
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let req = String::from_utf8_lossy(&buf[..n]);
    let mut lines = req.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or("/");

    if method != "GET" {
        return write_response(
            &mut stream,
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            b"method not allowed",
        )
        .await;
    }

    match path {
        "/" => {
            let body = index_html_v2();
            write_response(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                body.as_bytes(),
            )
            .await
        }
        "/api/snapshot" => {
            let snapshot = state.snapshot.read().await.clone().unwrap_or_else(|| {
                UiSnapshot::error(
                    "unknown".to_string(),
                    "waiting for first sample".to_string(),
                )
            });
            let body = serde_json::to_vec(&snapshot)
                .map_err(|err| AppError::Boxed(format!("serialize snapshot failed: {err}")))?;
            write_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &body,
            )
            .await
        }
        "/healthz" => {
            write_response(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok").await
        }
        _ => {
            write_response(
                &mut stream,
                "404 Not Found",
                "text/plain; charset=utf-8",
                b"not found",
            )
            .await
        }
    }
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), AppError> {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

#[allow(dead_code)]
fn index_html() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>rama-proxy UI</title>
  <style>
    :root {
      --bg: #f4f1ea;
      --panel: #fffdf8;
      --ink: #1d1b18;
      --muted: #6f685f;
      --line: #ddd2c3;
      --accent: #1f6f78;
      --warn: #aa4a44;
      --ok: #3a7d44;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", "PingFang SC", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top right, #e5efe3 0, transparent 25%),
        radial-gradient(circle at left top, #f0ddd0 0, transparent 30%),
        var(--bg);
    }
    .wrap { max-width: 1400px; margin: 0 auto; padding: 24px; }
    h1 { margin: 0 0 8px; font-size: 28px; }
    .sub { color: var(--muted); margin-bottom: 20px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }
    .card, .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 16px;
      box-shadow: 0 10px 25px rgba(40, 33, 24, 0.04);
    }
    .card { padding: 16px; }
    .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }
    .value { margin-top: 6px; font-size: 28px; font-weight: 700; }
    .meta { font-size: 13px; color: var(--muted); }
    .status-ok { color: var(--ok); }
    .status-err { color: var(--warn); }
    .panel { padding: 16px; margin-top: 16px; overflow: hidden; }
    .panel h2 { margin: 0 0 12px; font-size: 18px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 10px 8px; border-top: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { color: var(--muted); font-weight: 600; }
    .toolbar {
      display: flex;
      gap: 12px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 12px;
      flex-wrap: wrap;
    }
    input {
      padding: 10px 12px;
      border-radius: 10px;
      border: 1px solid var(--line);
      min-width: 260px;
      background: #fff;
    }
    .badge {
      display: inline-block;
      border-radius: 999px;
      padding: 2px 8px;
      background: #e9f0ef;
      color: var(--accent);
      font-size: 12px;
      font-weight: 600;
    }
    .tabbar {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }
    .tab {
      border: 1px solid var(--line);
      background: #fff;
      color: var(--muted);
      border-radius: 999px;
      padding: 8px 12px;
      cursor: pointer;
      font-size: 13px;
      transition: all 0.15s ease;
    }
    .tab:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
    .tab.active {
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }
    @media (max-width: 900px) {
      .value { font-size: 22px; }
      table { display: block; overflow-x: auto; white-space: nowrap; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>rama-proxy 观测 UI</h1>
    <div class="sub" id="summaryLine">等待采样...</div>
    <div class="grid" id="cards"></div>
    <div class="grid" id="tunnelCards"></div>

    <div class="panel">
      <div class="toolbar">
        <h2>Tunnel</h2>
        <input id="tunnelFilter" placeholder="过滤: id / 状态 / client / target / upstream">
      </div>
      <div class="tabbar" id="clientTabs"></div>
      <div class="grid" id="clientCards"></div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>状态</th>
            <th>占用中</th>
            <th>Client</th>
            <th>Target</th>
            <th>Upstream</th>
            <th>连接时长</th>
            <th>空闲时长</th>
            <th>上行</th>
            <th>下行</th>
          </tr>
        </thead>
        <tbody id="tunnelRows"></tbody>
      </table>
    </div>

    <div class="panel">
      <div class="toolbar">
        <h2>Socket</h2>
        <input id="socketFilter" placeholder="过滤: fd / 协议 / 状态 / 地址">
      </div>
      <table>
        <thead>
          <tr>
            <th>fd</th>
            <th>角色</th>
            <th>协议</th>
            <th>状态</th>
            <th>本地</th>
            <th>对端</th>
            <th>观测时长</th>
          </tr>
        </thead>
        <tbody id="socketRows"></tbody>
      </table>
    </div>

    <div class="panel">
      <div class="toolbar">
        <h2>FD</h2>
        <input id="fdFilter" placeholder="过滤: fd / 类型 / target">
      </div>
      <table>
        <thead>
          <tr>
            <th>fd</th>
            <th>角色</th>
            <th>类型</th>
            <th>target</th>
            <th>socket</th>
            <th>观测时长</th>
          </tr>
        </thead>
        <tbody id="fdRows"></tbody>
      </table>
    </div>
  </div>

  <script>
    const cards = document.getElementById('cards');
    const tunnelCards = document.getElementById('tunnelCards');
    const summaryLine = document.getElementById('summaryLine');
    const tunnelRows = document.getElementById('tunnelRows');
    const socketRows = document.getElementById('socketRows');
    const fdRows = document.getElementById('fdRows');
    const clientTabs = document.getElementById('clientTabs');
    const clientCards = document.getElementById('clientCards');
    const tunnelFilter = document.getElementById('tunnelFilter');
    const socketFilter = document.getElementById('socketFilter');
    const fdFilter = document.getElementById('fdFilter');

    let latest = null;
    let activeClientKey = '';

    function fmtSeconds(value) {
      if (value === null || value === undefined) return '-';
      const h = Math.floor(value / 3600);
      const m = Math.floor((value % 3600) / 60);
      const s = value % 60;
      if (h > 0) return `${h}h ${m}m ${s}s`;
      if (m > 0) return `${m}m ${s}s`;
      return `${s}s`;
    }

    function fmtTs(sec) {
      if (!sec) return '-';
      return new Date(sec * 1000).toLocaleString();
    }

    function fmtBytes(value) {
      if (value === null || value === undefined) return '-';
      if (value < 1024) return `${value} B`;
      if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
      if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
      return `${(value / 1024 / 1024 / 1024).toFixed(1)} GB`;
    }

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, (ch) => {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
        return map[ch] || ch;
      });
    }

    function parseClientHost(addr) {
      if (!addr) return 'unknown';
      if (addr.startsWith('[')) {
        const end = addr.indexOf(']');
        return end > 0 ? addr.slice(1, end) : addr;
      }
      const lastColon = addr.lastIndexOf(':');
      if (lastColon <= 0) return addr;
      const maybePort = addr.slice(lastColon + 1);
      if (/^\d+$/.test(maybePort)) {
        return addr.slice(0, lastColon);
      }
      return addr;
    }

    function getClientGroups(snapshot) {
      const connections = ((snapshot.live_stats && snapshot.live_stats.connections) || []);
      const groups = new Map();
      for (const item of connections) {
        const key = parseClientHost(item.client_addr);
        if (!groups.has(key)) {
          groups.set(key, {
            key,
            label: key,
            total: 0,
            idle: 0,
            activeTcp: 0,
            activeUdp: 0,
            inUse: 0,
            bytesFromClient: 0,
            bytesFromTarget: 0,
            connections: [],
          });
        }
        const group = groups.get(key);
        group.total += 1;
        if (item.state === 'idle') group.idle += 1;
        else if (item.state === 'active-tcp') group.activeTcp += 1;
        else if (item.state === 'active-udp') group.activeUdp += 1;
        if (item.in_use) group.inUse += 1;
        group.bytesFromClient += item.bytes_from_client || 0;
        group.bytesFromTarget += item.bytes_from_target || 0;
        group.connections.push(item);
      }
      return Array.from(groups.values()).sort((a, b) => {
        if (b.total !== a.total) return b.total - a.total;
        return a.label.localeCompare(b.label);
      });
    }

    function computeClientSummary(snapshot, clientKey) {
      const connections = ((snapshot.live_stats && snapshot.live_stats.connections) || [])
        .filter((item) => parseClientHost(item.client_addr) === clientKey);
      const upstreamAddrs = new Set(
        connections.map((item) => item.upstream_addr).filter((value) => value)
      );

      const sockets = (snapshot.sockets || []).filter((item) => {
        if (item.role === 'client-srv') return parseClientHost(item.remote_addr) === clientKey;
        if (item.role === 'srv-external') return upstreamAddrs.has(item.remote_addr);
        return false;
      });
      const socketInodes = new Set(sockets.map((item) => item.inode));
      const fds = (snapshot.fds || []).filter((item) => {
        if (item.inode && socketInodes.has(item.inode)) return true;
        if (item.socket && socketInodes.has(item.socket.inode)) return true;
        return false;
      });

      return {
        fd: {
          total: fds.length,
          clientSrv: fds.filter((item) => item.role === 'client-srv').length,
          srvExternal: fds.filter((item) => item.role === 'srv-external').length,
          srvInternal: fds.filter((item) => item.role === 'srv-internal').length,
        },
        socket: {
          total: sockets.length,
          clientSrv: sockets.filter((item) => item.role === 'client-srv').length,
          srvExternal: sockets.filter((item) => item.role === 'srv-external').length,
          srvInternal: sockets.filter((item) => item.role === 'srv-internal').length,
        },
        tunnel: {
          total: connections.length,
          idle: connections.filter((item) => item.state === 'idle').length,
          inUse: connections.filter((item) => item.in_use).length,
          activeTcp: connections.filter((item) => item.state === 'active-tcp').length,
          activeUdp: connections.filter((item) => item.state === 'active-udp').length,
        },
      };
    }

    function ensureActiveClient(snapshot) {
      const keys = new Set(['all', ...getClientGroups(snapshot).map(item => item.key)]);
      if (!keys.has(activeClientKey)) {
        activeClientKey = 'all';
      }
    }

    function renderCards(snapshot) {
      const summary = snapshot.summary || {};
      const process = snapshot.process || {};
      const items = [
        ['PID', process.pid ?? '-'],
        ['总 FD', summary.total_fds ?? 0],
        ['Client->Srv FD', summary.client_srv_fds ?? 0],
        ['Srv->External FD', summary.srv_external_fds ?? 0],
        ['Srv Internal FD', summary.srv_internal_fds ?? 0],
        ['Client->Srv Socket', summary.client_srv_sockets ?? 0],
        ['Srv->External Socket', summary.srv_external_sockets ?? 0],
        ['Srv Internal Socket', summary.srv_internal_sockets ?? 0],
        ['Listeners', summary.listener_sockets ?? 0],
        ['进程存活', fmtSeconds(process.uptime_secs)],
      ];
      cards.innerHTML = items.map(([label, value]) => `
        <div class="card">
          <div class="label">${label}</div>
          <div class="value">${value}</div>
        </div>
      `).join('');
    }

    function renderTunnelCards(snapshot) {
      const stats = snapshot.live_stats || {};
      const summary = stats.summary || {};
      const items = [
        ['Tunnel 总数', summary.total_connections ?? 0],
        ['Idle', summary.idle_connections ?? 0],
        ['Active TCP', summary.active_tcp_connections ?? 0],
        ['Active UDP', summary.active_udp_connections ?? 0],
        ['In Use', summary.in_use_connections ?? 0],
        ['Tunnel 上行', fmtBytes(summary.bytes_from_client ?? 0)],
        ['Tunnel 下行', fmtBytes(summary.bytes_from_target ?? 0)],
      ];
      tunnelCards.innerHTML = items.map(([label, value]) => `
        <div class="card">
          <div class="label">${label}</div>
          <div class="value">${value}</div>
        </div>
      `).join('');
    }

    function renderClientTabs(snapshot) {
      const groups = getClientGroups(snapshot);
      const tabs = [
        { key: 'all', label: `All (${((snapshot.live_stats && snapshot.live_stats.summary && snapshot.live_stats.summary.total_connections) || 0)})` },
        ...groups.map(group => ({
          key: group.key,
          label: `${group.label} (${group.total})`,
        })),
      ];
      clientTabs.innerHTML = tabs.map(tab => `
        <button class="tab ${tab.key === activeClientKey ? 'active' : ''}" data-client-key="${escapeHtml(tab.key)}">
          ${escapeHtml(tab.label)}
        </button>
      `).join('');
      clientTabs.querySelectorAll('[data-client-key]').forEach((button) => {
        button.addEventListener('click', () => {
          activeClientKey = button.getAttribute('data-client-key') || '';
          if (latest) {
            renderClientTabs(latest);
            renderClientCards(latest);
            renderTunnels(latest);
          }
        });
      });
    }

    function renderClientCards(snapshot) {
      const groups = getClientGroups(snapshot);
      const selected = activeClientKey === 'all'
        ? null
        : groups.find(group => group.key === activeClientKey) || null;
      const items = selected
        ? [
            ['Client', selected.label],
            ['Connections', selected.total],
            ['Idle', selected.idle],
            ['Active TCP', selected.activeTcp],
            ['Active UDP', selected.activeUdp],
            ['In Use', selected.inUse],
            ['Upload', fmtBytes(selected.bytesFromClient)],
            ['Download', fmtBytes(selected.bytesFromTarget)],
          ]
        : [
            ['Client Scope', 'All'],
            ['Distinct Clients', groups.length],
            ['Connections', (snapshot.live_stats && snapshot.live_stats.summary && snapshot.live_stats.summary.total_connections) || 0],
            ['In Use', (snapshot.live_stats && snapshot.live_stats.summary && snapshot.live_stats.summary.in_use_connections) || 0],
            ['Upload', fmtBytes((snapshot.live_stats && snapshot.live_stats.summary && snapshot.live_stats.summary.bytes_from_client) || 0)],
            ['Download', fmtBytes((snapshot.live_stats && snapshot.live_stats.summary && snapshot.live_stats.summary.bytes_from_target) || 0)],
          ];
      clientCards.innerHTML = items.map(([label, value]) => `
        <div class="card">
          <div class="label">${label}</div>
          <div class="value">${escapeHtml(value)}</div>
        </div>
      `).join('');
    }

    function renderSummary(snapshot) {
      if (!snapshot.ok) {
        summaryLine.innerHTML = `<span class="status-err">采样失败:</span> ${snapshot.error || 'unknown'}`;
        return;
      }
      const process = snapshot.process || {};
      const liveStatsStatus = snapshot.live_stats
        ? `stats socket: ${snapshot.stats_socket}`
        : `stats socket 异常: ${snapshot.live_stats_error || snapshot.stats_socket}`;
      summaryLine.innerHTML =
        `<span class="status-ok">采样正常</span> · ` +
        `pid 文件: ${snapshot.pid_file} · ` +
        `进程: ${process.name || '-'}(${process.pid || '-'}) · ` +
        `启动时间: ${fmtTs(process.start_time_unix_secs)} · ` +
        `${liveStatsStatus} · ` +
        `最近采样: ${fmtTs(snapshot.collected_at_unix_secs)}`;
    }

    function renderTunnels(snapshot) {
      const filter = tunnelFilter.value.trim().toLowerCase();
      const rows = ((snapshot.live_stats && snapshot.live_stats.connections) || []).filter(item => {
        const clientKey = parseClientHost(item.client_addr);
        if (clientKey !== activeClientKey) return false;
        if (!filter) return true;
        const text = [
          item.id,
          item.state,
          item.in_use,
          item.client_addr,
          clientKey,
          item.target_addr || '',
          item.upstream_addr || '',
        ].join(' ').toLowerCase();
        return text.includes(filter);
      });

      tunnelRows.innerHTML = rows.map(item => `
        <tr>
          <td>${item.id}</td>
          <td>${item.state}</td>
          <td>${item.in_use ? 'yes' : 'no'}</td>
          <td>${item.client_addr}</td>
          <td>${item.target_addr || '-'}</td>
          <td>${item.upstream_addr || '-'}</td>
          <td>${fmtSeconds(item.age_secs)}</td>
          <td>${fmtSeconds(item.idle_secs)}</td>
          <td>${fmtBytes(item.bytes_from_client)}</td>
          <td>${fmtBytes(item.bytes_from_target)}</td>
        </tr>
      `).join('');
    }

    function renderSockets(snapshot) {
      const filter = socketFilter.value.trim().toLowerCase();
      const rows = (snapshot.sockets || []).filter(item => {
        if (!filter) return true;
        const text = [item.fd, item.role, item.protocol, item.state, item.local_addr, item.remote_addr].join(' ').toLowerCase();
        return text.includes(filter);
      });

      socketRows.innerHTML = rows.map(item => `
        <tr>
          <td>${item.fd}</td>
          <td>${item.role}</td>
          <td><span class="badge">${item.protocol}</span></td>
          <td>${item.state}</td>
          <td>${item.local_addr}</td>
          <td>${item.remote_addr}</td>
          <td>${fmtSeconds(item.observed_secs)}</td>
        </tr>
      `).join('');
    }

    function renderFds(snapshot) {
      const filter = fdFilter.value.trim().toLowerCase();
      const rows = (snapshot.fds || []).filter(item => {
        if (!filter) return true;
        const text = [item.fd, item.role, item.kind, item.target].join(' ').toLowerCase();
        return text.includes(filter);
      });

      fdRows.innerHTML = rows.map(item => {
        const socket = item.socket
          ? `${item.socket.protocol} ${item.socket.state}<br>${item.socket.local_addr} → ${item.socket.remote_addr}`
          : '-';
        return `
          <tr>
            <td>${item.fd}</td>
            <td>${item.role}</td>
            <td>${item.kind}</td>
            <td>${item.target}</td>
            <td>${socket}</td>
            <td>${fmtSeconds(item.observed_secs)}</td>
          </tr>
        `;
      }).join('');
    }

    function render(snapshot) {
      latest = snapshot;
      ensureActiveClient(snapshot);
      renderSummary(snapshot);
      renderCards(snapshot);
      renderTunnelCards(snapshot);
      renderClientTabs(snapshot);
      renderClientCards(snapshot);
      renderTunnels(snapshot);
      renderSockets(snapshot);
      renderFds(snapshot);
    }

    async function refresh() {
      try {
        const res = await fetch('/api/snapshot', { cache: 'no-store' });
        const data = await res.json();
        render(data);
      } catch (err) {
        summaryLine.innerHTML = `<span class="status-err">请求失败:</span> ${err}`;
      }
    }

    tunnelFilter.addEventListener('input', () => latest && renderTunnels(latest));
    socketFilter.addEventListener('input', () => latest && renderSockets(latest));
    fdFilter.addEventListener('input', () => latest && renderFds(latest));

    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
"#
}

fn index_html_v2() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>rama-proxy UI</title>
  <style>
    :root {
      --bg: #f3f6fb;
      --panel: rgba(255, 255, 255, 0.88);
      --ink: #172033;
      --muted: #6b778c;
      --line: rgba(124, 142, 173, 0.2);
      --accent: #2f6fed;
      --ok: #0f9f6e;
      --warn: #d15b45;
      --shadow: 0 18px 48px rgba(20, 38, 76, 0.08);
      --radius: 22px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Segoe UI", "PingFang SC", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(125, 166, 255, 0.16), transparent 26%),
        radial-gradient(circle at top right, rgba(72, 200, 168, 0.12), transparent 22%),
        linear-gradient(180deg, #f8fbff 0%, #f1f5fb 100%);
    }
    .shell { max-width: 1480px; margin: 0 auto; padding: 28px 20px 40px; }
    .hero {
      display: flex;
      justify-content: space-between;
      gap: 20px;
      align-items: flex-start;
      margin-bottom: 18px;
    }
    .hero h1 { margin: 0; font-size: 28px; letter-spacing: -0.02em; }
    .hero-meta { margin-top: 10px; color: var(--muted); font-size: 13px; line-height: 1.6; }
    .hero-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    .pill, .btn, .filter-chip, .client-tab, .detail-tab {
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.9);
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
      color: var(--muted);
      font-size: 13px;
      box-shadow: 0 6px 20px rgba(20, 38, 76, 0.04);
    }
    .dot {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      background: var(--ok);
      box-shadow: 0 0 0 5px rgba(15, 159, 110, 0.12);
      flex: none;
    }
    .dot.error {
      background: var(--warn);
      box-shadow: 0 0 0 5px rgba(209, 91, 69, 0.12);
    }
    .btn {
      padding: 10px 14px;
      cursor: pointer;
      color: var(--ink);
      font-size: 13px;
      font-weight: 600;
      transition: 0.18s ease;
    }
    .btn.primary {
      background: linear-gradient(135deg, #2f6fed, #5f8fff);
      border-color: transparent;
      color: #fff;
      box-shadow: 0 14px 28px rgba(47, 111, 237, 0.24);
    }
    .panel {
      background: var(--panel);
      border: 1px solid rgba(255, 255, 255, 0.7);
      backdrop-filter: blur(14px);
      box-shadow: var(--shadow);
      border-radius: var(--radius);
      padding: 18px;
      margin-top: 16px;
      overflow: hidden;
    }
    .panel-head {
      display: flex;
      gap: 14px;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }
    .panel-title { margin: 0; font-size: 19px; }
    .panel-note { color: var(--muted); font-size: 13px; line-height: 1.5; }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 12px;
    }
    .stats-grid.tight { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
    .stat-card {
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(246, 249, 255, 0.92));
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 16px;
      min-height: 96px;
    }
    .eyebrow {
      color: #75819a;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .metric {
      margin-top: 8px;
      font-size: 34px;
      line-height: 1.05;
      font-weight: 750;
      letter-spacing: -0.03em;
      overflow-wrap: anywhere;
    }
    .metric.small { font-size: 22px; line-height: 1.2; letter-spacing: 0; }
    .submetric { margin-top: 8px; color: var(--muted); font-size: 13px; line-height: 1.5; overflow-wrap: anywhere; }
    .section-stack { display: grid; gap: 14px; }
    .group {
      border: 1px solid rgba(124, 142, 173, 0.14);
      background: rgba(248, 250, 255, 0.72);
      border-radius: 18px;
      padding: 14px;
    }
    .group-head { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
    .tag {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 999px;
      padding: 4px 10px;
      color: #fff;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.04em;
    }
    .tag.fd { background: linear-gradient(135deg, #7a49f5, #5c6ff0); }
    .tag.socket { background: linear-gradient(135deg, #1098ad, #0f6fb8); }
    .tag.tunnel { background: linear-gradient(135deg, #f97316, #ef4444); }
    .toolbar, .tab-row, .filter-row {
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }
    .toolbar { justify-content: space-between; margin-top: 16px; margin-bottom: 12px; }
    .client-tab, .detail-tab, .filter-chip {
      cursor: pointer;
      transition: 0.18s ease;
      color: #4a5873;
      font-size: 13px;
      font-weight: 600;
      padding: 9px 14px;
    }
    .client-tab strong {
      font-size: 12px;
      background: rgba(47, 111, 237, 0.1);
      border-radius: 999px;
      padding: 2px 7px;
      margin-left: 8px;
    }
    .client-tab.active, .detail-tab.active, .filter-chip.active {
      background: linear-gradient(135deg, #2f6fed, #5482ff);
      border-color: transparent;
      color: #fff;
      box-shadow: 0 12px 24px rgba(47, 111, 237, 0.18);
    }
    .client-tab.active strong { background: rgba(255, 255, 255, 0.16); }
    .filter-chip { padding: 7px 11px; font-size: 12px; font-weight: 700; }
    input {
      min-width: 250px;
      width: min(100%, 320px);
      padding: 11px 13px;
      border-radius: 12px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.92);
      color: var(--ink);
      font-size: 13px;
      outline: none;
    }
    .detail-pane { display: none; }
    .detail-pane.active { display: block; }
    .table-shell {
      border: 1px solid rgba(124, 142, 173, 0.14);
      background: rgba(255, 255, 255, 0.8);
      border-radius: 16px;
      overflow: auto;
      margin-top: 12px;
    }
    table { width: 100%; border-collapse: collapse; min-width: 880px; font-size: 13px; }
    th, td {
      padding: 12px;
      border-top: 1px solid rgba(124, 142, 173, 0.12);
      text-align: left;
      vertical-align: top;
    }
    thead th {
      border-top: none;
      color: #73809a;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      background: rgba(247, 249, 255, 0.94);
    }
    tbody tr:hover { background: rgba(47, 111, 237, 0.04); }
    .mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; word-break: break-all; }
    .status-badge, .proto-badge {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 4px 9px;
      font-size: 11px;
      font-weight: 700;
      line-height: 1;
      white-space: nowrap;
    }
    .proto-badge { background: rgba(47, 111, 237, 0.1); color: var(--accent); }
    .status-badge.idle { background: rgba(124, 142, 173, 0.14); color: #64748b; }
    .status-badge.active-tcp { background: rgba(47, 111, 237, 0.14); color: #1d4ed8; }
    .status-badge.active-udp { background: rgba(14, 165, 164, 0.16); color: #0f766e; }
    .status-badge.yes { background: rgba(15, 159, 110, 0.12); color: var(--ok); }
    .status-badge.no { background: rgba(209, 91, 69, 0.12); color: var(--warn); }
    .empty { padding: 20px; color: var(--muted); text-align: center; font-size: 13px; }
    .split-meta { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
    code { background: rgba(23, 32, 51, 0.05); border-radius: 8px; padding: 2px 6px; }
    @media (max-width: 900px) {
      .shell { padding: 20px 14px 30px; }
      .hero { flex-direction: column; }
      .metric { font-size: 28px; }
      .stats-grid { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
      input { width: 100%; min-width: 0; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="hero">
      <div>
        <h1>rama-proxy srv 观测 UI</h1>
        <div class="hero-meta" id="summaryLine">等待首个采样结果...</div>
      </div>
      <div class="hero-actions">
        <div class="pill" id="statusPill"><span class="dot"></span><span>sampling</span></div>
        <button class="btn primary" id="refreshBtn">立即刷新</button>
      </div>
    </header>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2 class="panel-title">进程基础信息</h2>
          <div class="panel-note">srv 自身视角，不随 client 切换变化</div>
        </div>
      </div>
      <div class="stats-grid" id="overviewCards"></div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2 class="panel-title">全局统计</h2>
          <div class="panel-note">FD、Socket、Tunnel 三个维度的汇总统计</div>
        </div>
      </div>
      <div class="section-stack" id="globalSections"></div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2 class="panel-title">按 Client 查看</h2>
          <div class="panel-note">先选 client，再在 Tunnel / Socket / FD 明细里继续过滤</div>
        </div>
        <input id="clientSearch" placeholder="过滤 client ip / id ...">
      </div>

      <div class="tab-row" id="clientTabs"></div>
      <div class="stats-grid tight" id="clientCards" style="margin-top: 14px;"></div>

      <div class="toolbar">
        <div class="tab-row" id="detailTabs"></div>
        <div id="detailSearchWrap"></div>
      </div>

      <div class="detail-pane active" data-pane="tunnel">
        <div class="filter-row" id="tunnelStateChips"></div>
        <div class="table-shell">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>状态</th>
                <th>占用中</th>
                <th>Client</th>
                <th>Target</th>
                <th>Upstream</th>
                <th>连接时长</th>
                <th>空闲时长</th>
                <th>上行</th>
                <th>下行</th>
              </tr>
            </thead>
            <tbody id="tunnelRows"></tbody>
          </table>
        </div>
      </div>

      <div class="detail-pane" data-pane="socket">
        <div class="filter-row" id="socketRoleChips"></div>
        <div class="table-shell">
          <table>
            <thead>
              <tr>
                <th>FD</th>
                <th>角色</th>
                <th>协议</th>
                <th>状态</th>
                <th>本地地址</th>
                <th>对端地址</th>
                <th>观测时长</th>
              </tr>
            </thead>
            <tbody id="socketRows"></tbody>
          </table>
        </div>
      </div>

      <div class="detail-pane" data-pane="fd">
        <div class="filter-row" id="fdKindChips"></div>
        <div class="table-shell">
          <table>
            <thead>
              <tr>
                <th>FD</th>
                <th>角色</th>
                <th>类型</th>
                <th>Target</th>
                <th>Socket</th>
                <th>观测时长</th>
              </tr>
            </thead>
            <tbody id="fdRows"></tbody>
          </table>
        </div>
      </div>
    </section>
  </div>

  <script>
    const summaryLine = document.getElementById('summaryLine');
    const statusPill = document.getElementById('statusPill');
    const refreshBtn = document.getElementById('refreshBtn');
    const overviewCards = document.getElementById('overviewCards');
    const globalSections = document.getElementById('globalSections');
    const clientTabs = document.getElementById('clientTabs');
    const clientCards = document.getElementById('clientCards');
    const detailTabs = document.getElementById('detailTabs');
    const detailSearchWrap = document.getElementById('detailSearchWrap');
    const tunnelStateChips = document.getElementById('tunnelStateChips');
    const socketRoleChips = document.getElementById('socketRoleChips');
    const fdKindChips = document.getElementById('fdKindChips');
    const tunnelRows = document.getElementById('tunnelRows');
    const socketRows = document.getElementById('socketRows');
    const fdRows = document.getElementById('fdRows');
    const clientSearch = document.getElementById('clientSearch');

    let latest = null;
    let activeClientKey = '';
    let activeDetail = 'tunnel';
    let tunnelStateFilter = 'all';
    let socketRoleFilter = 'all';
    let fdKindFilter = 'all';
    let clientSearchTerm = '';
    let tunnelSearchTerm = '';
    let socketSearchTerm = '';
    let fdSearchTerm = '';

    const detailMeta = {
      tunnel: { label: 'Tunnel 通道', placeholder: '过滤 id / target / upstream / client' },
      socket: { label: 'Socket', placeholder: '过滤 fd / role / protocol / addr' },
      fd: { label: 'FD', placeholder: '过滤 fd / kind / target' },
    };

    function fmtSeconds(value) {
      if (value === null || value === undefined) return '-';
      const h = Math.floor(value / 3600);
      const m = Math.floor((value % 3600) / 60);
      const s = value % 60;
      if (h > 0) return `${h}h ${m}m ${s}s`;
      if (m > 0) return `${m}m ${s}s`;
      return `${s}s`;
    }

    function fmtTs(sec) {
      if (!sec) return '-';
      return new Date(sec * 1000).toLocaleString('zh-CN', { hour12: false });
    }

    function fmtBytes(value) {
      if (value === null || value === undefined) return '-';
      if (value < 1024) return `${value} B`;
      if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
      if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
      return `${(value / 1024 / 1024 / 1024).toFixed(1)} GB`;
    }

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, (ch) => {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
        return map[ch] || ch;
      });
    }

    function parseClientHost(addr) {
      if (!addr) return 'unknown';
      if (addr.startsWith('[')) {
        const end = addr.indexOf(']');
        return end > 0 ? addr.slice(1, end) : addr;
      }
      const lastColon = addr.lastIndexOf(':');
      if (lastColon <= 0) return addr;
      const maybePort = addr.slice(lastColon + 1);
      if (/^\d+$/.test(maybePort)) return addr.slice(0, lastColon);
      return addr;
    }

    function listenerSummary(snapshot) {
      const listeners = (snapshot.sockets || []).filter((item) => item.is_listener);
      if (!listeners.length) return '无监听 socket';
      return listeners.slice(0, 2).map((item) => `${item.protocol} ${item.local_addr}`).join(' · ');
    }

    function getClientGroups(snapshot) {
      const connections = ((snapshot.live_stats && snapshot.live_stats.connections) || []);
      const groups = new Map();
      for (const item of connections) {
        const key = parseClientHost(item.client_addr);
        if (!groups.has(key)) {
          groups.set(key, {
            key,
            label: key,
            total: 0,
            idle: 0,
            activeTcp: 0,
            activeUdp: 0,
            inUse: 0,
            bytesFromClient: 0,
            bytesFromTarget: 0,
          });
        }
        const group = groups.get(key);
        group.total += 1;
        if (item.state === 'idle') group.idle += 1;
        if (item.state === 'active-tcp') group.activeTcp += 1;
        if (item.state === 'active-udp') group.activeUdp += 1;
        if (item.in_use) group.inUse += 1;
        group.bytesFromClient += item.bytes_from_client || 0;
        group.bytesFromTarget += item.bytes_from_target || 0;
      }
      return Array.from(groups.values()).sort((a, b) => {
        if (b.total !== a.total) return b.total - a.total;
        return a.label.localeCompare(b.label);
      });
    }

    function ensureActiveClient(snapshot) {
      const groups = getClientGroups(snapshot);
      const keys = new Set(groups.map((item) => item.key));
      if (!keys.has(activeClientKey)) activeClientKey = groups.length ? groups[0].key : '';
    }

    function statusBadge(value) {
      return `<span class="status-badge ${escapeHtml(String(value))}">${escapeHtml(value)}</span>`;
    }

    function renderEmptyRow(text, colspan) {
      return `<tr><td colspan="${colspan}" class="empty">${escapeHtml(text)}</td></tr>`;
    }

    function currentDetailSearchValue() {
      if (activeDetail === 'socket') return socketSearchTerm;
      if (activeDetail === 'fd') return fdSearchTerm;
      return tunnelSearchTerm;
    }

    function setCurrentDetailSearchValue(value) {
      if (activeDetail === 'socket') socketSearchTerm = value;
      else if (activeDetail === 'fd') fdSearchTerm = value;
      else tunnelSearchTerm = value;
    }

    function renderSummary(snapshot) {
      if (!snapshot.ok) {
        statusPill.innerHTML = '<span class="dot error"></span><span>sampling error</span>';
        summaryLine.textContent = `采样失败: ${snapshot.error || 'unknown'}`;
        return;
      }

      const process = snapshot.process || {};
      const liveStatsText = snapshot.live_stats
        ? `stats socket <code>${escapeHtml(snapshot.stats_socket)}</code>`
        : `stats socket 异常 <code>${escapeHtml(snapshot.live_stats_error || snapshot.stats_socket)}</code>`;

      statusPill.innerHTML = '<span class="dot"></span><span>sampling ok</span>';
      summaryLine.innerHTML = `
        <div class="split-meta">
          <span>进程 <strong>${escapeHtml(process.name || '-')}</strong> (${escapeHtml(process.pid ?? '-')})</span>
          <span>pid 文件 <code>${escapeHtml(snapshot.pid_file)}</code></span>
          <span>${liveStatsText}</span>
          <span>启动时间 <strong>${escapeHtml(fmtTs(process.start_time_unix_secs))}</strong></span>
          <span>最近采样 <strong>${escapeHtml(fmtTs(snapshot.collected_at_unix_secs))}</strong></span>
        </div>
      `;
    }

    function renderOverview(snapshot) {
      const process = snapshot.process || {};
      const summary = snapshot.summary || {};
      const listeners = (snapshot.sockets || []).filter((item) => item.is_listener);
      const items = [
        ['PID', process.pid ?? '-', process.cmdline || '-'],
        ['进程名', process.name || '-', process.cmdline || '-'],
        ['启动时间', fmtTs(process.start_time_unix_secs), `已运行 ${fmtSeconds(process.uptime_secs)}`],
        ['Listeners', listeners.length || summary.listener_sockets || 0, listenerSummary(snapshot)],
        ['Socket 概览', `${summary.socket_fds ?? 0} / ${summary.total_fds ?? 0}`, `tcp ${summary.tcp_sockets ?? 0} · udp ${summary.udp_sockets ?? 0}`],
      ];
      overviewCards.innerHTML = items.map(([label, value, sub]) => `
        <article class="stat-card">
          <div class="eyebrow">${escapeHtml(label)}</div>
          <div class="metric ${String(value).length > 18 ? 'small' : ''}">${escapeHtml(value)}</div>
          <div class="submetric">${escapeHtml(sub || '-')}</div>
        </article>
      `).join('');
    }

    function renderGlobalSections(snapshot) {
      const summary = snapshot.summary || {};
      const tunnel = (snapshot.live_stats && snapshot.live_stats.summary) || {};
      const groups = [
        {
          tag: 'FD',
          tagClass: 'fd',
          title: '文件描述符',
          items: [
            ['总 FD', summary.total_fds ?? 0],
            ['client → srv', summary.client_srv_fds ?? 0],
            ['srv → external', summary.srv_external_fds ?? 0],
            ['srv internal', summary.srv_internal_fds ?? 0],
          ],
        },
        {
          tag: 'Socket',
          tagClass: 'socket',
          title: '套接字',
          items: [
            ['总 Socket', summary.socket_fds ?? 0],
            ['client → srv', summary.client_srv_sockets ?? 0],
            ['srv → external', summary.srv_external_sockets ?? 0],
            ['srv internal', summary.srv_internal_sockets ?? 0],
          ],
        },
        {
          tag: 'Tunnel',
          tagClass: 'tunnel',
          title: '通道',
          items: [
            ['总数', tunnel.total_connections ?? 0],
            ['Idle', tunnel.idle_connections ?? 0],
            ['In Use', tunnel.in_use_connections ?? 0],
            ['Active TCP', tunnel.active_tcp_connections ?? 0],
            ['Active UDP', tunnel.active_udp_connections ?? 0],
            ['上下行', `${fmtBytes(tunnel.bytes_from_client ?? 0)} / ${fmtBytes(tunnel.bytes_from_target ?? 0)}`],
          ],
        },
      ];

      globalSections.innerHTML = groups.map((group) => `
        <section class="group">
          <div class="group-head">
            <span class="tag ${group.tagClass}">${group.tag}</span>
            <strong>${group.title}</strong>
          </div>
          <div class="stats-grid ${group.items.length > 4 ? 'tight' : ''}">
            ${group.items.map(([label, value]) => `
              <article class="stat-card">
                <div class="eyebrow">${escapeHtml(label)}</div>
                <div class="metric ${String(value).length > 14 ? 'small' : ''}">${escapeHtml(value)}</div>
              </article>
            `).join('')}
          </div>
        </section>
      `).join('');
    }

    function renderClientTabs(snapshot) {
      const groups = getClientGroups(snapshot).filter((group) => {
        if (!clientSearchTerm) return true;
        return `${group.label} ${group.total}`.toLowerCase().includes(clientSearchTerm);
      });
      const tabs = groups.map((group) => ({ key: group.key, label: group.label, count: group.total }));
      /*
      const tabs = [
        { key: 'all', label: '全部 client', count: tunnelSummary.total_connections || 0 },
        ...groups.map((group) => ({ key: group.key, label: group.label, count: group.total })),
      ];
      */
      clientTabs.innerHTML = tabs.map((tab) => `
        <button class="client-tab ${tab.key === activeClientKey ? 'active' : ''}" data-client-key="${escapeHtml(tab.key)}">
          <span>${escapeHtml(tab.label)}</span>
          <strong>${escapeHtml(tab.count)}</strong>
        </button>
      `).join('');

      clientTabs.querySelectorAll('[data-client-key]').forEach((button) => {
        button.addEventListener('click', () => {
          activeClientKey = button.getAttribute('data-client-key') || '';
          if (latest) render(latest);
        });
      });
    }

    function renderClientCards(snapshot) {
      const groups = getClientGroups(snapshot);
      const selected = groups.find((group) => group.key === activeClientKey) || null;
      const tunnel = {
        total_connections: 0,
        in_use_connections: 0,
        active_tcp_connections: 0,
        active_udp_connections: 0,
        bytes_from_client: 0,
        bytes_from_target: 0,
      };
      const items = selected
        ? [
            ['Client', selected.label],
            ['Tunnel 总数', selected.total],
            ['Idle', selected.idle],
            ['In Use', selected.inUse],
            ['Active TCP', selected.activeTcp],
            ['Active UDP', selected.activeUdp],
            ['上行', fmtBytes(selected.bytesFromClient)],
            ['下行', fmtBytes(selected.bytesFromTarget)],
          ]
        : [
            ['Client Scope', 'ALL'],
            ['Distinct Clients', groups.length],
            ['Tunnel 总数', tunnel.total_connections ?? 0],
            ['In Use', tunnel.in_use_connections ?? 0],
            ['Active TCP', tunnel.active_tcp_connections ?? 0],
            ['Active UDP', tunnel.active_udp_connections ?? 0],
            ['上行', fmtBytes(tunnel.bytes_from_client ?? 0)],
            ['下行', fmtBytes(tunnel.bytes_from_target ?? 0)],
          ];
      clientCards.innerHTML = items.map(([label, value]) => `
        <article class="stat-card">
          <div class="eyebrow">${escapeHtml(label)}</div>
          <div class="metric ${String(value).length > 18 ? 'small' : ''}">${escapeHtml(value)}</div>
        </article>
      `).join('');
    }

    function renderClientCards(snapshot) {
      const groups = getClientGroups(snapshot);
      const selected = groups.find((group) => group.key === activeClientKey) || null;
      const stats = selected ? computeClientSummary(snapshot, selected.key) : {
        fd: { total: 0, clientSrv: 0, srvExternal: 0, srvInternal: 0 },
        socket: { total: 0, clientSrv: 0, srvExternal: 0, srvInternal: 0 },
        tunnel: { total: 0, idle: 0, inUse: 0, activeTcp: 0, activeUdp: 0 },
      };
      const sections = [
        {
          tag: 'FD',
          tagClass: 'fd',
          title: selected ? selected.label : '-',
          items: [
            ['总 FD', stats.fd.total],
            ['client → srv', stats.fd.clientSrv],
            ['srv → external', stats.fd.srvExternal],
            ['srv internal', stats.fd.srvInternal],
          ],
        },
        {
          tag: 'Socket',
          tagClass: 'socket',
          title: selected ? selected.label : '-',
          items: [
            ['总 Socket', stats.socket.total],
            ['client → srv', stats.socket.clientSrv],
            ['srv → external', stats.socket.srvExternal],
            ['srv internal', stats.socket.srvInternal],
          ],
        },
        {
          tag: 'Tunnel',
          tagClass: 'tunnel',
          title: selected ? selected.label : '-',
          items: [
            ['总数', stats.tunnel.total],
            ['Idle', stats.tunnel.idle],
            ['In Use', stats.tunnel.inUse],
            ['Active TCP', stats.tunnel.activeTcp],
            ['Active UDP', stats.tunnel.activeUdp],
          ],
        },
      ];
      clientCards.innerHTML = sections.map((section) => `
        <section class="group">
          <div class="group-head">
            <span class="tag ${section.tagClass}">${section.tag}</span>
            <strong>${escapeHtml(section.title)}</strong>
          </div>
          <div class="stats-grid ${section.items.length > 4 ? 'tight' : ''}">
            ${section.items.map(([label, value]) => `
              <article class="stat-card">
                <div class="eyebrow">${escapeHtml(label)}</div>
                <div class="metric ${String(value).length > 14 ? 'small' : ''}">${escapeHtml(value)}</div>
              </article>
            `).join('')}
          </div>
        </section>
      `).join('');
    }

    function renderDetailTabs() {
      detailTabs.innerHTML = Object.entries(detailMeta).map(([key, meta]) => `
        <button class="detail-tab ${key === activeDetail ? 'active' : ''}" data-detail-key="${escapeHtml(key)}">
          ${escapeHtml(meta.label)}
        </button>
      `).join('');

      detailTabs.querySelectorAll('[data-detail-key]').forEach((button) => {
        button.addEventListener('click', () => {
          activeDetail = button.getAttribute('data-detail-key') || 'tunnel';
          document.querySelectorAll('.detail-pane').forEach((pane) => {
            pane.classList.toggle('active', pane.getAttribute('data-pane') === activeDetail);
          });
          renderDetailTabs();
          renderDetailSearch();
        });
      });

      document.querySelectorAll('.detail-pane').forEach((pane) => {
        pane.classList.toggle('active', pane.getAttribute('data-pane') === activeDetail);
      });
    }

    function renderDetailSearch() {
      const meta = detailMeta[activeDetail];
      detailSearchWrap.innerHTML = `<input id="detailSearch" placeholder="${escapeHtml(meta.placeholder)}" value="${escapeHtml(currentDetailSearchValue())}">`;
      document.getElementById('detailSearch').addEventListener('input', (event) => {
        setCurrentDetailSearchValue(event.target.value.trim().toLowerCase());
        if (!latest) return;
        if (activeDetail === 'socket') renderSockets(latest);
        else if (activeDetail === 'fd') renderFds(latest);
        else renderTunnels(latest);
      });
    }

    function renderFilterChips(container, options, current, onSelect) {
      container.innerHTML = options.map((item) => `
        <button class="filter-chip ${item.key === current ? 'active' : ''}" data-filter-key="${escapeHtml(item.key)}">
          ${escapeHtml(item.label)}
        </button>
      `).join('');
      container.querySelectorAll('[data-filter-key]').forEach((button) => {
        button.addEventListener('click', () => onSelect(button.getAttribute('data-filter-key') || 'all'));
      });
    }

    function renderTunnels(snapshot) {
      renderFilterChips(tunnelStateChips, [
        { key: 'all', label: '全部' },
        { key: 'active-tcp', label: 'active-tcp' },
        { key: 'active-udp', label: 'active-udp' },
        { key: 'idle', label: 'idle' },
      ], tunnelStateFilter, (key) => {
        tunnelStateFilter = key;
        if (latest) renderTunnels(latest);
      });

      const rows = ((snapshot.live_stats && snapshot.live_stats.connections) || []).filter((item) => {
        const clientKey = parseClientHost(item.client_addr);
        if (clientKey !== activeClientKey) return false;
        if (tunnelStateFilter !== 'all' && item.state !== tunnelStateFilter) return false;
        if (!tunnelSearchTerm) return true;
        return [
          item.id,
          item.state,
          item.in_use,
          item.client_addr,
          clientKey,
          item.target_addr || '',
          item.upstream_addr || '',
        ].join(' ').toLowerCase().includes(tunnelSearchTerm);
      });

      tunnelRows.innerHTML = rows.length ? rows.map((item) => `
        <tr>
          <td class="mono">${escapeHtml(item.id)}</td>
          <td>${statusBadge(item.state)}</td>
          <td>${statusBadge(item.in_use ? 'yes' : 'no')}</td>
          <td class="mono">${escapeHtml(item.client_addr)}</td>
          <td class="mono">${escapeHtml(item.target_addr || '-')}</td>
          <td class="mono">${escapeHtml(item.upstream_addr || '-')}</td>
          <td>${escapeHtml(fmtSeconds(item.age_secs))}</td>
          <td>${escapeHtml(fmtSeconds(item.idle_secs))}</td>
          <td>${escapeHtml(fmtBytes(item.bytes_from_client))}</td>
          <td>${escapeHtml(fmtBytes(item.bytes_from_target))}</td>
        </tr>
      `).join('') : renderEmptyRow('当前筛选下没有 tunnel 记录', 10);
    }

    function renderSockets(snapshot) {
      renderFilterChips(socketRoleChips, [
        { key: 'all', label: '全部' },
        { key: 'client-srv', label: 'client-srv' },
        { key: 'srv-external', label: 'srv-external' },
        { key: 'srv-internal', label: 'srv-internal' },
      ], socketRoleFilter, (key) => {
        socketRoleFilter = key;
        if (latest) renderSockets(latest);
      });

      const rows = (snapshot.sockets || []).filter((item) => {
        if (socketRoleFilter !== 'all' && item.role !== socketRoleFilter) return false;
        if (!socketSearchTerm) return true;
        return [item.fd, item.role, item.protocol, item.state, item.local_addr, item.remote_addr]
          .join(' ')
          .toLowerCase()
          .includes(socketSearchTerm);
      });

      socketRows.innerHTML = rows.length ? rows.map((item) => `
        <tr>
          <td class="mono">${escapeHtml(item.fd)}</td>
          <td>${escapeHtml(item.role)}</td>
          <td><span class="proto-badge">${escapeHtml(item.protocol)}</span></td>
          <td>${statusBadge(item.state)}</td>
          <td class="mono">${escapeHtml(item.local_addr)}</td>
          <td class="mono">${escapeHtml(item.remote_addr)}</td>
          <td>${escapeHtml(fmtSeconds(item.observed_secs))}</td>
        </tr>
      `).join('') : renderEmptyRow('当前筛选下没有 socket 记录', 7);
    }

    function renderFds(snapshot) {
      renderFilterChips(fdKindChips, [
        { key: 'all', label: '全部' },
        { key: 'socket', label: 'socket' },
        { key: 'file', label: 'file' },
        { key: 'pipe', label: 'pipe' },
        { key: 'anon_inode', label: 'anon_inode' },
      ], fdKindFilter, (key) => {
        fdKindFilter = key;
        if (latest) renderFds(latest);
      });

      const rows = (snapshot.fds || []).filter((item) => {
        if (fdKindFilter !== 'all' && item.kind !== fdKindFilter) return false;
        if (!fdSearchTerm) return true;
        return [item.fd, item.role, item.kind, item.target].join(' ').toLowerCase().includes(fdSearchTerm);
      });

      fdRows.innerHTML = rows.length ? rows.map((item) => {
        const socket = item.socket
          ? `<div class="mono">${escapeHtml(item.socket.protocol)} ${escapeHtml(item.socket.state)}<br>${escapeHtml(item.socket.local_addr)} → ${escapeHtml(item.socket.remote_addr)}</div>`
          : '-';
        return `
          <tr>
            <td class="mono">${escapeHtml(item.fd)}</td>
            <td>${escapeHtml(item.role)}</td>
            <td>${escapeHtml(item.kind)}</td>
            <td class="mono">${escapeHtml(item.target)}</td>
            <td>${socket}</td>
            <td>${escapeHtml(fmtSeconds(item.observed_secs))}</td>
          </tr>
        `;
      }).join('') : renderEmptyRow('当前筛选下没有 fd 记录', 6);
    }

    function render(snapshot) {
      latest = snapshot;
      ensureActiveClient(snapshot);
      renderSummary(snapshot);
      renderOverview(snapshot);
      renderGlobalSections(snapshot);
      renderClientTabs(snapshot);
      renderClientCards(snapshot);
      renderDetailTabs();
      renderDetailSearch();
      renderTunnels(snapshot);
      renderSockets(snapshot);
      renderFds(snapshot);
    }

    async function refresh() {
      refreshBtn.disabled = true;
      try {
        const res = await fetch('/api/snapshot', { cache: 'no-store' });
        const data = await res.json();
        render(data);
      } catch (err) {
        statusPill.innerHTML = '<span class="dot error"></span><span>request error</span>';
        summaryLine.textContent = `请求失败: ${err}`;
      } finally {
        refreshBtn.disabled = false;
      }
    }

    clientSearch.addEventListener('input', (event) => {
      clientSearchTerm = event.target.value.trim().toLowerCase();
      if (latest) renderClientTabs(latest);
    });

    refreshBtn.addEventListener('click', () => refresh());

    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
"#
}
