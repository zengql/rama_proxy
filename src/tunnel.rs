use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use rama::net::address::{Host, HostWithPort};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, warn};

use crate::error::AppError;
use crate::{config::TunnelClientConfig, tls::ClientTlsContext};

const MAGIC: &[u8; 4] = b"RPT1";
const VERSION: u8 = 1;

const OP_CONNECT: u8 = 0x10;
const OP_UDP_ASSOCIATE: u8 = 0x11;
const OP_PING: u8 = 0x12;
const OP_PONG: u8 = 0x13;
const OP_RESPONSE: u8 = 0x20;
const OP_UDP_PACKET: u8 = 0x30;
const OP_CLOSE: u8 = 0x31;

const STATUS_OK: u8 = 0x00;
const STATUS_AUTH_FAILED: u8 = 0x01;
const STATUS_BAD_REQUEST: u8 = 0x02;
const STATUS_CONNECT_FAILED: u8 = 0x03;
const STATUS_RESOLVE_FAILED: u8 = 0x04;
const IDLE_TUNNEL_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
#[derive(Clone)]
pub struct TunnelPool {
    server_addr: SocketAddr,
    shared_secret: Arc<str>,
    connect_timeout: Duration,
    idle_tx: mpsc::Sender<TunnelStream>,
    idle_rx: Arc<Mutex<mpsc::Receiver<TunnelStream>>>,
    desired_size: usize,
    connecting: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
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
            connect_timeout: Duration::from_secs(config.connect_timeout_secs.max(1)),
            idle_tx,
            idle_rx: Arc::new(Mutex::new(idle_rx)),
            desired_size: config.pool_size,
            connecting: Arc::new(AtomicUsize::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
            tls,
        })
    }

    pub fn spawn_maintainer(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let idle = this.idle_len();
                let connecting = this.connecting.load(Ordering::Relaxed);
                let active = this.active.load(Ordering::Relaxed);
                let total = idle.saturating_add(connecting).saturating_add(active);
                if total < this.desired_size {
                    let missing = this.desired_size - total;
                    for _ in 0..missing {
                        this.spawn_fill_one();
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    fn idle_len(&self) -> usize {
        self.desired_size.saturating_sub(self.idle_tx.capacity())
    }

    fn spawn_fill_one(&self) {
        let sender = self.idle_tx.clone();
        let server_addr = self.server_addr;
        let shared_secret = self.shared_secret.clone();
        let connect_timeout = self.connect_timeout;
        let connecting = self.connecting.clone();
        let tls = self.tls.clone();
        connecting.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let result =
                connect_idle_tunnel(server_addr, &shared_secret, connect_timeout, tls).await;
            connecting.fetch_sub(1, Ordering::SeqCst);
            match result {
                Ok(stream) => {
                    if sender.send(stream).await.is_err() {
                        debug!("tunnel pool receiver dropped while returning idle tunnel");
                    }
                }
                Err(err) => {
                    warn!("failed to create idle tunnel: {err}");
                }
            }
        });
    }

    pub async fn acquire(&self) -> Result<TunnelLease, AppError> {
        loop {
            let next_idle = {
                let mut idle_rx = self.idle_rx.lock().await;
                idle_rx.try_recv().ok()
            };
            let Some(mut stream) = next_idle else {
                break;
            };

            match probe_idle_tunnel(&mut stream).await {
                Ok(()) => {
                    self.active.fetch_add(1, Ordering::SeqCst);
                    return Ok(TunnelLease {
                        inner: stream,
                        active: self.active.clone(),
                    });
                }
                Err(err) => {
                    warn!("discarding stale idle tunnel: {err}");
                    self.spawn_fill_one();
                }
            }
        }

        let stream = connect_idle_tunnel(
            self.server_addr,
            &self.shared_secret,
            self.connect_timeout,
            self.tls.clone(),
        )
        .await?;
        self.active.fetch_add(1, Ordering::SeqCst);
        Ok(TunnelLease {
            inner: stream,
            active: self.active.clone(),
        })
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
    connect_timeout: Duration,
    tls: Option<ClientTlsContext>,
) -> Result<TunnelStream, AppError> {
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(server_addr))
        .await
        .map_err(|_| AppError::InvalidConfig("client tunnel connect timed out".to_string()))??;
    stream.set_nodelay(true)?;
    info!(server_addr = %server_addr, tls_enabled = tls.is_some(), "created fresh tunnel connection");
    let mut stream: TunnelStream = match tls {
        Some(tls) => Box::new(
            tls.connector
                .connect(tls.server_name, stream)
                .await
                .map_err(|err| AppError::Boxed(format!("tls connect failed: {err}")))?,
        ),
        None => Box::new(stream),
    };
    client_handshake(&mut stream, shared_secret).await?;
    Ok(stream)
}

pub async fn client_handshake<S>(stream: &mut S, shared_secret: &str) -> Result<(), AppError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(MAGIC).await?;
    stream.write_u8(VERSION).await?;
    write_string(stream, shared_secret).await?;
    stream.flush().await?;

    let status = stream.read_u8().await?;
    match status {
        STATUS_OK => Ok(()),
        STATUS_AUTH_FAILED => Err(AppError::InvalidConfig(
            "tunnel authentication rejected by server".to_string(),
        )),
        _ => Err(AppError::InvalidConfig(format!(
            "unexpected tunnel handshake status: {status}"
        ))),
    }
}

pub async fn server_handshake<S>(stream: &mut S, shared_secret: &str) -> Result<(), AppError>
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
    if version != VERSION {
        stream.write_u8(STATUS_BAD_REQUEST).await?;
        return Err(AppError::InvalidConfig(format!(
            "unsupported tunnel version: {version}"
        )));
    }
    let got_secret = read_string(stream).await?;
    if got_secret != shared_secret {
        stream.write_u8(STATUS_AUTH_FAILED).await?;
        return Err(AppError::InvalidConfig(
            "invalid tunnel shared secret".to_string(),
        ));
    }
    stream.write_u8(STATUS_OK).await?;
    stream.flush().await?;
    Ok(())
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
