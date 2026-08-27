use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rama::net::address::{Host, HostWithPort};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tracing::{info, warn};

use crate::error::AppError;
use crate::{config::TunnelClientConfig, tls::ClientTlsContext};

const MAGIC: &[u8; 4] = b"RPT1";
const VERSION_LEGACY: u8 = 1;
const VERSION_WITH_CLIENT_ID: u8 = 2;

const OP_CONNECT: u8 = 0x10;
const OP_UDP_ASSOCIATE: u8 = 0x11;
const OP_PING: u8 = 0x12;
const OP_PONG: u8 = 0x13;
const OP_HEARTBEAT: u8 = 0x14;
const OP_HEARTBEAT_ACK: u8 = 0x15;
const OP_HEARTBEAT_OPEN: u8 = 0x16;
const OP_RESPONSE: u8 = 0x20;
const OP_UDP_PACKET: u8 = 0x30;
const OP_CLOSE: u8 = 0x31;
const MAX_UDP_PAYLOAD: usize = 65535;

const STATUS_OK: u8 = 0x00;
const STATUS_AUTH_FAILED: u8 = 0x01;
const STATUS_BAD_REQUEST: u8 = 0x02;
const STATUS_CONNECT_FAILED: u8 = 0x03;
const STATUS_RESOLVE_FAILED: u8 = 0x04;
const STATUS_CLIENT_ID_REQUIRED: u8 = 0x05;
const IDLE_TUNNEL_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const IDLE_TUNNEL_HEALTHY_FOR: Duration = Duration::from_secs(15);
const POOL_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);
const MAINTENANCE_SWEEP_BATCH: usize = 8;
const MAX_STALE_TUNNELS_PER_ACQUIRE: usize = 2;
const MAX_REFILL_BACKOFF: Duration = Duration::from_secs(30);

struct IdleTunnel {
    stream: TunnelStream,
    verified_at: Instant,
}

struct RefillState {
    consecutive_failures: usize,
    next_allowed_at: Option<Instant>,
    cooldown_logged_for: Option<Instant>,
}

#[derive(Clone)]
pub struct TunnelPool {
    server_addr: SocketAddr,
    shared_secret: Arc<str>,
    client_id: Arc<str>,
    connect_timeout: Duration,
    idle_tx: mpsc::Sender<IdleTunnel>,
    idle_rx: Arc<Mutex<mpsc::Receiver<IdleTunnel>>>,
    max_idle_size: usize,
    warm_idle_target: usize,
    inspecting_idle: Arc<AtomicUsize>,
    connecting: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    refill_state: Arc<Mutex<RefillState>>,
    tls: Option<ClientTlsContext>,
}

pub trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TunnelIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type TunnelStream = Box<dyn TunnelIo>;

pub struct TunnelLease {
    inner: TunnelStream,
    active: Arc<AtomicUsize>,
}

impl TunnelPool {
    pub fn new(
        config: &TunnelClientConfig,
        tls: Option<ClientTlsContext>,
    ) -> Result<Self, AppError> {
        let server_addr = config.server_addr.parse::<SocketAddr>().map_err(|_| {
            AppError::InvalidConfig("client.server_addr must be host:port".to_string())
        })?;
        let (idle_tx, idle_rx) = mpsc::channel(config.pool_size);
        Ok(Self {
            server_addr,
            shared_secret: Arc::<str>::from(config.shared_secret.clone()),
            client_id: Arc::<str>::from(resolve_client_id(&config.client_id)),
            connect_timeout: Duration::from_secs(config.connect_timeout_secs.max(1)),
            idle_tx,
            idle_rx: Arc::new(Mutex::new(idle_rx)),
            max_idle_size: config.pool_size,
            warm_idle_target: compute_warm_idle_target(config.pool_size),
            inspecting_idle: Arc::new(AtomicUsize::new(0)),
            connecting: Arc::new(AtomicUsize::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
            refill_state: Arc::new(Mutex::new(RefillState::default())),
            tls,
        })
    }

    pub fn spawn_maintainer(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            this.schedule_refill().await;
            loop {
                this.reap_idle_tunnels().await;
                tokio::time::sleep(POOL_MAINTENANCE_INTERVAL).await;
            }
        });
    }

    fn idle_len(&self) -> usize {
        self.max_idle_size.saturating_sub(self.idle_tx.capacity())
    }

    async fn schedule_refill(&self) {
        let now = Instant::now();
        let (idle, inspecting_idle, connecting, missing) = {
            let mut refill_state = self.refill_state.lock().await;
            let idle = self.idle_len();
            let inspecting_idle = self.inspecting_idle.load(Ordering::Relaxed);
            let connecting = self.connecting.load(Ordering::Relaxed);
            let missing = self.warm_idle_target.saturating_sub(
                idle.saturating_add(inspecting_idle)
                    .saturating_add(connecting),
            );
            if missing == 0 {
                return;
            }
            if let Some(next_allowed_at) = refill_state.next_allowed_at {
                if now < next_allowed_at {
                    if refill_state.cooldown_logged_for != Some(next_allowed_at) {
                        warn!(
                            warm_idle_target = self.warm_idle_target,
                            max_idle_size = self.max_idle_size,
                            idle,
                            inspecting_idle,
                            connecting,
                            active = self.active.load(Ordering::Relaxed),
                            consecutive_failures = refill_state.consecutive_failures,
                            cooldown_secs =
                                next_allowed_at.saturating_duration_since(now).as_secs(),
                            "warm tunnel pool is backing off after refill failures"
                        );
                        refill_state.cooldown_logged_for = Some(next_allowed_at);
                    }
                    return;
                }
            }

            refill_state.cooldown_logged_for = None;
            self.connecting.fetch_add(missing, Ordering::SeqCst);
            (idle, inspecting_idle, connecting, missing)
        };

        info!(
            warm_idle_target = self.warm_idle_target,
            max_idle_size = self.max_idle_size,
            idle,
            inspecting_idle,
            connecting,
            active = self.active.load(Ordering::Relaxed),
            refill_batch = missing,
            "warm tunnel pool below target; scheduling refill"
        );
        for _ in 0..missing {
            self.spawn_fill_one();
        }
    }

    fn spawn_fill_one(&self) {
        let sender = self.idle_tx.clone();
        let server_addr = self.server_addr;
        let shared_secret = self.shared_secret.clone();
        let client_id = self.client_id.clone();
        let connect_timeout = self.connect_timeout;
        let connecting = self.connecting.clone();
        let refill_state = self.refill_state.clone();
        let tls = self.tls.clone();
        let tls_backend = tls.as_ref().map(|tls| tls.backend).unwrap_or("plain");
        let tls_server_name = tls
            .as_ref()
            .map(|tls| tls.server_name_display.clone())
            .unwrap_or_default();
        let client_auth_configured = tls
            .as_ref()
            .map(|tls| tls.client_auth_configured)
            .unwrap_or(false);
        tokio::spawn(async move {
            let result = connect_idle_tunnel(
                server_addr,
                &shared_secret,
                &client_id,
                connect_timeout,
                tls,
            )
            .await;
            match result {
                Ok(stream) => {
                    reset_refill_backoff(&refill_state).await;
                    if sender.send(IdleTunnel::new(stream)).await.is_err() {
                        connecting.fetch_sub(1, Ordering::SeqCst);
                        warn!("tunnel pool receiver dropped while returning idle tunnel");
                    } else {
                        connecting.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                Err(err) => {
                    connecting.fetch_sub(1, Ordering::SeqCst);
                    let (failures, backoff_secs) = register_refill_failure(&refill_state).await;
                    warn!(
                        server_addr = %server_addr,
                        client_id = %client_id,
                        timeout_secs = connect_timeout.as_secs(),
                        tls_backend,
                        tls_server_name,
                        client_auth_configured,
                        consecutive_failures = failures,
                        backoff_secs,
                        error = %err,
                        "failed to create idle tunnel"
                    );
                }
            }
        });
    }

    pub async fn acquire(&self) -> Result<TunnelLease, AppError> {
        let mut stale_count = 0usize;
        loop {
            let next_idle = {
                let mut idle_rx = self.idle_rx.lock().await;
                idle_rx.try_recv().ok()
            };
            let Some(mut idle_tunnel) = next_idle else {
                break;
            };

            if idle_tunnel.verified_at.elapsed() >= IDLE_TUNNEL_HEALTHY_FOR {
                match probe_idle_tunnel(&mut idle_tunnel.stream).await {
                    Ok(()) => {
                        idle_tunnel.verified_at = Instant::now();
                    }
                    Err(err) => {
                        stale_count += 1;
                        warn!(
                            stale_count,
                            max_stale = MAX_STALE_TUNNELS_PER_ACQUIRE,
                            error = %err,
                            "discarding stale idle tunnel during acquire"
                        );
                        self.schedule_refill().await;
                        if stale_count >= MAX_STALE_TUNNELS_PER_ACQUIRE {
                            warn!(
                                stale_count,
                                max_stale = MAX_STALE_TUNNELS_PER_ACQUIRE,
                                "too many stale idle tunnels during acquire; falling back to fresh tunnel"
                            );
                            break;
                        }
                        continue;
                    }
                }
            }

            self.active.fetch_add(1, Ordering::SeqCst);
            self.schedule_refill().await;
            return Ok(TunnelLease {
                inner: idle_tunnel.stream,
                active: self.active.clone(),
            });
        }

        self.schedule_refill().await;
        let stream = connect_idle_tunnel(
            self.server_addr,
            &self.shared_secret,
            &self.client_id,
            self.connect_timeout,
            self.tls.clone(),
        )
        .await
        .map_err(|err| {
            warn!(
                server_addr = %self.server_addr,
                client_id = %self.client_id,
                timeout_secs = self.connect_timeout.as_secs(),
                tls_backend = self.tls.as_ref().map(|tls| tls.backend).unwrap_or("plain"),
                tls_server_name = self
                    .tls
                    .as_ref()
                    .map(|tls| tls.server_name_display.as_str())
                    .unwrap_or(""),
                client_auth_configured = self
                    .tls
                    .as_ref()
                    .map(|tls| tls.client_auth_configured)
                    .unwrap_or(false),
                error = %err,
                "failed to create fresh tunnel during acquire fallback"
            );
            err
        })?;
        self.active.fetch_add(1, Ordering::SeqCst);
        Ok(TunnelLease {
            inner: stream,
            active: self.active.clone(),
        })
    }

    async fn reap_idle_tunnels(&self) {
        let mut drained = Vec::with_capacity(MAINTENANCE_SWEEP_BATCH);
        let mut dropped_stale = 0usize;
        {
            let mut idle_rx = self.idle_rx.lock().await;
            for _ in 0..MAINTENANCE_SWEEP_BATCH {
                match idle_rx.try_recv() {
                    Ok(idle_tunnel) => drained.push(idle_tunnel),
                    Err(_) => break,
                }
            }
        }
        self.inspecting_idle
            .fetch_add(drained.len(), Ordering::SeqCst);

        for mut idle_tunnel in drained {
            if idle_tunnel.verified_at.elapsed() < IDLE_TUNNEL_HEALTHY_FOR {
                self.return_idle_tunnel(idle_tunnel).await;
                continue;
            }

            match probe_idle_tunnel(&mut idle_tunnel.stream).await {
                Ok(()) => {
                    idle_tunnel.verified_at = Instant::now();
                    self.return_idle_tunnel(idle_tunnel).await;
                }
                Err(err) => {
                    dropped_stale = dropped_stale.saturating_add(1);
                    self.inspecting_idle.fetch_sub(1, Ordering::SeqCst);
                    warn!(error = %err, "discarding stale idle tunnel during maintenance");
                }
            }
        }

        if dropped_stale > 0 {
            self.schedule_refill().await;
        }
    }

    async fn return_idle_tunnel(&self, idle_tunnel: IdleTunnel) {
        if self.idle_tx.send(idle_tunnel).await.is_err() {
            warn!("tunnel pool receiver dropped while requeueing idle tunnel");
        }
        self.inspecting_idle.fetch_sub(1, Ordering::SeqCst);
    }
}

impl IdleTunnel {
    fn new(stream: TunnelStream) -> Self {
        Self {
            stream,
            verified_at: Instant::now(),
        }
    }
}

impl Default for RefillState {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            next_allowed_at: None,
            cooldown_logged_for: None,
        }
    }
}

async fn probe_idle_tunnel(stream: &mut TunnelStream) -> Result<(), AppError> {
    tokio::time::timeout(IDLE_TUNNEL_PROBE_TIMEOUT, async {
        write_ping(stream).await?;
        let opcode = read_opcode(stream).await?;
        if opcode_is_pong(opcode) {
            Ok(())
        } else {
            Err(AppError::InvalidConfig(format!(
                "unexpected opcode while probing idle tunnel: {opcode}"
            )))
        }
    })
    .await
    .map_err(|_| AppError::InvalidConfig("idle tunnel probe timed out".to_string()))?
}

impl Drop for TunnelLease {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl AsyncRead for TunnelLease {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunnelLease {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

async fn connect_idle_tunnel(
    server_addr: SocketAddr,
    shared_secret: &str,
    client_id: &str,
    connect_timeout: Duration,
    tls: Option<ClientTlsContext>,
) -> Result<TunnelStream, AppError> {
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(server_addr))
        .await
        .map_err(|_| AppError::InvalidConfig("client tunnel connect timed out".to_string()))??;
    stream.set_nodelay(true)?;
    let tls_backend = tls.as_ref().map(|tls| tls.backend).unwrap_or("plain");
    let tls_server_name = tls
        .as_ref()
        .map(|tls| tls.server_name_display.clone())
        .unwrap_or_default();
    let client_auth_configured = tls
        .as_ref()
        .map(|tls| tls.client_auth_configured)
        .unwrap_or(false);
    let mut stream: TunnelStream = match tls {
        Some(tls) => Box::new(
            tls.connector
                .connect(tls.server_name, stream)
                .await
                .map_err(|err| AppError::Boxed(format!("tls connect failed: {err}")))?,
        ),
        None => Box::new(stream),
    };
    client_handshake(&mut stream, shared_secret, client_id).await?;
    info!(
        server_addr = %server_addr,
        client_id,
        tls_enabled = tls_backend != "plain",
        tls_backend,
        tls_server_name,
        client_auth_configured,
        "fresh tunnel connection is ready"
    );
    Ok(stream)
}

pub async fn run_heartbeat(
    server_addr: SocketAddr,
    shared_secret: &str,
    client_id: &str,
    connect_timeout: Duration,
    tls: Option<ClientTlsContext>,
) -> Result<(), AppError> {
    let mut stream =
        connect_idle_tunnel(server_addr, shared_secret, client_id, connect_timeout, tls).await?;
    write_heartbeat_open(&mut stream).await?;
    loop {
        let (_, ids) = read_heartbeat(&mut stream).await?;
        write_heartbeat_ack(&mut stream, &ids).await?;
    }
}

pub async fn client_handshake<S>(
    stream: &mut S,
    shared_secret: &str,
    client_id: &str,
) -> Result<(), AppError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(MAGIC).await?;
    stream.write_u8(VERSION_WITH_CLIENT_ID).await?;
    write_string(stream, shared_secret).await?;
    write_string(stream, client_id).await?;
    stream.flush().await?;

    let status = stream.read_u8().await?;
    match status {
        STATUS_OK => Ok(()),
        STATUS_AUTH_FAILED => Err(AppError::InvalidConfig(
            "tunnel authentication rejected by server".to_string(),
        )),
        STATUS_CLIENT_ID_REQUIRED => Err(AppError::InvalidConfig(
            "server requires a non-empty client.client_id; upgrade the client binary and set [client].client_id".to_string(),
        )),
        _ => Err(AppError::InvalidConfig(format!(
            "unexpected tunnel handshake status: {status}"
        ))),
    }
}

pub async fn server_handshake<S>(stream: &mut S, shared_secret: &str) -> Result<String, AppError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic).await?;
    if &magic != MAGIC {
        stream.write_u8(STATUS_BAD_REQUEST).await?;
        return Err(AppError::InvalidConfig("invalid tunnel magic".to_string()));
    }
    let version = stream.read_u8().await?;
    if version != VERSION_LEGACY && version != VERSION_WITH_CLIENT_ID {
        stream.write_u8(STATUS_BAD_REQUEST).await?;
        return Err(AppError::InvalidConfig(format!(
            "unsupported tunnel version: {version}"
        )));
    }
    if version == VERSION_LEGACY {
        stream.write_u8(STATUS_BAD_REQUEST).await?;
        return Err(AppError::InvalidConfig(
            "legacy tunnel client is not supported; upgrade the client binary".to_string(),
        ));
    }
    let got_secret = read_string(stream).await?;
    if got_secret != shared_secret {
        stream.write_u8(STATUS_AUTH_FAILED).await?;
        return Err(AppError::InvalidConfig(
            "invalid tunnel shared secret".to_string(),
        ));
    }
    let client_id = if version == VERSION_WITH_CLIENT_ID {
        read_string(stream).await?
    } else {
        String::new()
    };
    if client_id.trim().is_empty() {
        stream.write_u8(STATUS_CLIENT_ID_REQUIRED).await?;
        stream.flush().await?;
        return Err(AppError::InvalidConfig(
            "client_id is required; anonymous tunnel clients are not supported".to_string(),
        ));
    }
    stream.write_u8(STATUS_OK).await?;
    stream.flush().await?;
    Ok(client_id)
}

pub fn resolve_client_id(configured: &str) -> String {
    let configured = configured.trim();
    if !configured.is_empty() {
        return configured.to_string();
    }

    for key in ["COMPUTERNAME", "HOSTNAME", "USERNAME", "USER"] {
        if let Ok(value) = std::env::var(key) {
            let value = value.trim();
            if !value.is_empty() {
                return value.to_string();
            }
        }
    }

    String::new()
}

pub async fn write_open_connect<W>(writer: &mut W, target: &HostWithPort) -> Result<(), AppError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u8(OP_CONNECT).await?;
    write_host(writer, target).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn write_open_udp<W>(writer: &mut W) -> Result<(), AppError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u8(OP_UDP_ASSOCIATE).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_opcode<R>(reader: &mut R) -> Result<u8, AppError>
where
    R: AsyncRead + Unpin,
{
    Ok(reader.read_u8().await?)
}

pub async fn read_connect_target<R>(reader: &mut R) -> Result<HostWithPort, AppError>
where
    R: AsyncRead + Unpin,
{
    read_host(reader).await
}

pub async fn write_response<W>(writer: &mut W, status: u8, message: &str) -> Result<(), AppError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u8(OP_RESPONSE).await?;
    writer.write_u8(status).await?;
    write_string(writer, message).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_response<R>(reader: &mut R) -> Result<(), AppError>
where
    R: AsyncRead + Unpin,
{
    let opcode = reader.read_u8().await?;
    if opcode != OP_RESPONSE {
        return Err(AppError::InvalidConfig(format!(
            "unexpected tunnel opcode while waiting for response: {opcode}"
        )));
    }
    let status = reader.read_u8().await?;
    let message = read_string(reader).await?;
    if status == STATUS_OK {
        Ok(())
    } else {
        Err(AppError::InvalidConfig(format!(
            "tunnel server rejected request: {message}"
        )))
    }
}

pub async fn write_ping<W>(writer: &mut W) -> Result<(), AppError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u8(OP_PING).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn write_pong<W>(writer: &mut W) -> Result<(), AppError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u8(OP_PONG).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn write_heartbeat<W>(writer: &mut W, ids: &[u64]) -> Result<(), AppError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u8(OP_HEARTBEAT).await?;
    writer.write_u32(ids.len() as u32).await?;
    for id in ids {
        writer.write_u64(*id).await?;
    }
    writer.flush().await?;
    Ok(())
}

pub async fn write_heartbeat_open<W>(writer: &mut W) -> Result<(), AppError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u8(OP_HEARTBEAT_OPEN).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_heartbeat<R>(reader: &mut R) -> Result<(u8, Vec<u64>), AppError>
where
    R: AsyncRead + Unpin,
{
    let opcode = reader.read_u8().await?;
    if !opcode_is_heartbeat(opcode) && !opcode_is_heartbeat_ack(opcode) {
        return Err(AppError::InvalidConfig(format!(
            "unexpected heartbeat opcode: {opcode}"
        )));
    }
    let count = reader.read_u32().await?;
    if count > 65535 {
        return Err(AppError::InvalidConfig(
            "heartbeat channel batch is too large".to_string(),
        ));
    }
    let mut ids = Vec::with_capacity(count as usize);
    for _ in 0..count {
        ids.push(reader.read_u64().await?);
    }
    Ok((opcode, ids))
}

pub async fn write_heartbeat_ack<W>(writer: &mut W, ids: &[u64]) -> Result<(), AppError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u8(OP_HEARTBEAT_ACK).await?;
    writer.write_u32(ids.len() as u32).await?;
    for id in ids {
        writer.write_u64(*id).await?;
    }
    writer.flush().await?;
    Ok(())
}

pub async fn write_udp_packet<W>(
    writer: &mut W,
    target: &HostWithPort,
    payload: &[u8],
) -> Result<(), AppError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u8(OP_UDP_PACKET).await?;
    write_host(writer, target).await?;
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_udp_packet<R>(reader: &mut R) -> Result<(HostWithPort, Vec<u8>), AppError>
where
    R: AsyncRead + Unpin,
{
    let target = read_host(reader).await?;
    let len = reader.read_u32().await? as usize;
    if len > MAX_UDP_PAYLOAD {
        return Err(AppError::InvalidConfig(format!(
            "udp payload is too large: {len} bytes, maximum is {MAX_UDP_PAYLOAD}"
        )));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok((target, payload))
}

pub async fn write_close<W>(writer: &mut W) -> Result<(), AppError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u8(OP_CLOSE).await?;
    writer.flush().await?;
    Ok(())
}

pub fn status_connect_failed(err: &str) -> (u8, String) {
    (STATUS_CONNECT_FAILED, err.to_string())
}

pub fn status_resolve_failed(err: &str) -> (u8, String) {
    (STATUS_RESOLVE_FAILED, err.to_string())
}

async fn write_host<W>(writer: &mut W, target: &HostWithPort) -> Result<(), AppError>
where
    W: AsyncWrite + Unpin,
{
    write_string(writer, &target.to_string()).await
}

async fn read_host<R>(reader: &mut R) -> Result<HostWithPort, AppError>
where
    R: AsyncRead + Unpin,
{
    let raw = read_string(reader).await?;
    raw.parse::<HostWithPort>().map_err(|err| {
        AppError::InvalidConfig(format!("invalid host-with-port in tunnel frame: {err}"))
    })
}

async fn write_string<W>(writer: &mut W, value: &str) -> Result<(), AppError>
where
    W: AsyncWrite + Unpin,
{
    let bytes = value.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(AppError::InvalidConfig(
            "tunnel string field is too large".to_string(),
        ));
    }
    writer.write_u16(bytes.len() as u16).await?;
    writer.write_all(bytes).await?;
    Ok(())
}

async fn read_string<R>(reader: &mut R) -> Result<String, AppError>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u16().await? as usize;
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes).await?;
    String::from_utf8(bytes)
        .map_err(|err| AppError::InvalidConfig(format!("invalid utf8 in tunnel frame: {err}")))
}

pub fn opcode_is_ping(opcode: u8) -> bool {
    opcode == OP_PING
}

pub fn opcode_is_pong(opcode: u8) -> bool {
    opcode == OP_PONG
}

pub fn opcode_is_heartbeat(opcode: u8) -> bool {
    opcode == OP_HEARTBEAT
}

pub fn opcode_is_heartbeat_ack(opcode: u8) -> bool {
    opcode == OP_HEARTBEAT_ACK
}

pub fn opcode_is_heartbeat_open(opcode: u8) -> bool {
    opcode == OP_HEARTBEAT_OPEN
}

pub fn opcode_is_connect(opcode: u8) -> bool {
    opcode == OP_CONNECT
}

pub fn opcode_is_udp(opcode: u8) -> bool {
    opcode == OP_UDP_ASSOCIATE
}

pub fn opcode_is_udp_packet(opcode: u8) -> bool {
    opcode == OP_UDP_PACKET
}

pub fn opcode_is_close(opcode: u8) -> bool {
    opcode == OP_CLOSE
}

pub fn host_to_socket_addr(target: &HostWithPort) -> Option<SocketAddr> {
    match target.host {
        Host::Address(ip) => Some(SocketAddr::new(ip, target.port)),
        Host::Name(_) => None,
    }
}

async fn reset_refill_backoff(refill_state: &Arc<Mutex<RefillState>>) {
    let mut refill_state = refill_state.lock().await;
    refill_state.consecutive_failures = 0;
    refill_state.next_allowed_at = None;
    refill_state.cooldown_logged_for = None;
}

async fn register_refill_failure(refill_state: &Arc<Mutex<RefillState>>) -> (usize, u64) {
    let mut refill_state = refill_state.lock().await;
    refill_state.consecutive_failures = refill_state.consecutive_failures.saturating_add(1);
    let backoff = compute_refill_backoff(refill_state.consecutive_failures);
    refill_state.next_allowed_at = Some(Instant::now() + backoff);
    refill_state.cooldown_logged_for = None;
    (refill_state.consecutive_failures, backoff.as_secs())
}

fn compute_refill_backoff(consecutive_failures: usize) -> Duration {
    let shift = consecutive_failures.saturating_sub(1).min(5) as u32;
    Duration::from_secs(1u64 << shift).min(MAX_REFILL_BACKOFF)
}

fn compute_warm_idle_target(max_idle_size: usize) -> usize {
    max_idle_size
}
