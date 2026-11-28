use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    Arc, Mutex as StdMutex,
    atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rama::net::address::{Host, HostWithPort};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify, mpsc, watch};
use tracing::{debug, info, warn};

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
const IDLE_TUNNEL_HEALTHY_FOR: Duration = Duration::from_secs(120);
const POOL_MAINTENANCE_INTERVAL_FAST: Duration = Duration::from_secs(1);
const POOL_MAINTENANCE_INTERVAL_SLOW: Duration = Duration::from_secs(30);
const POOL_IDLE_CLOSE_AFTER: Duration = Duration::from_secs(5 * 60);
const HEARTBEAT_IDLE_GRACE: Duration = Duration::from_secs(5 * 60);
const TUNNEL_TCP_KEEPALIVE_SECS: u64 = 300;
const MAINTENANCE_SWEEP_BATCH: usize = 8;
const MAX_STALE_TUNNELS_PER_ACQUIRE: usize = 2;
const MAX_REFILL_BACKOFF: Duration = Duration::from_secs(30);

struct IdleTunnel {
    tunnel_id: u64,
    stream: TunnelStream,
    // Wall clock on purpose: `Instant` (CLOCK_MONOTONIC) stops while an Android
    // device is suspended, so a tunnel idle across a long sleep would look fresh
    // and be reused without a probe even though NAT/server may have dropped it.
    verified_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelPoolSnapshot {
    pub max_idle_size: usize,
    pub warm_idle_target: usize,
    pub idle: usize,
    pub inspecting_idle: usize,
    pub connecting: usize,
    pub active: usize,
    pub last_traffic_age_secs: Option<u64>,
    pub consecutive_failures: usize,
    pub next_refill_allowed_in_secs: Option<u64>,
    pub created_total: usize,
    pub failed_total: usize,
    pub reaped_stale_total: usize,
    pub last_success_age_secs: Option<u64>,
    pub last_refill_error: Option<String>,
}

struct RefillState {
    consecutive_failures: usize,
    next_allowed_at: Option<Instant>,
    cooldown_logged_for: Option<Instant>,
    created_total: usize,
    failed_total: usize,
    reaped_stale_total: usize,
    last_success_at: Option<Instant>,
    last_refill_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum OnDemandPhase {
    Dormant = 0,
    Active = 1,
    HeartbeatGrace = 2,
}

impl OnDemandPhase {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Active,
            2 => Self::HeartbeatGrace,
            _ => Self::Dormant,
        }
    }
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
    last_traffic_unix_ms: Arc<AtomicU64>,
    state_notify: Arc<Notify>,
    next_tunnel_id: Arc<AtomicU64>,
    refill_state: Arc<Mutex<RefillState>>,
    tls: Option<ClientTlsContext>,
    pool_idle_timeout: Duration,
    heartbeat_idle_grace: Duration,
    on_demand_phase: Arc<AtomicU8>,
    phase_lock: Arc<StdMutex<()>>,
    heartbeat_enabled_tx: watch::Sender<bool>,
}

pub trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TunnelIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type TunnelStream = Box<dyn TunnelIo>;

pub struct TunnelLease {
    inner: TunnelStream,
    id: u64,
    from_pool: bool,
    active: Arc<AtomicUsize>,
    last_traffic_unix_ms: Arc<AtomicU64>,
    state_notify: Arc<Notify>,
}

fn unix_now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
        let (heartbeat_enabled_tx, _) = watch::channel(false);
        let pool_idle_timeout = std::env::var("RAMA_PROXY_POOL_IDLE_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(|secs| Duration::from_secs(secs.max(1)))
            .unwrap_or(POOL_IDLE_CLOSE_AFTER);
        let heartbeat_idle_grace = std::env::var("RAMA_PROXY_HEARTBEAT_IDLE_GRACE_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(HEARTBEAT_IDLE_GRACE);
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
            last_traffic_unix_ms: Arc::new(AtomicU64::new(0)),
            state_notify: Arc::new(Notify::new()),
            next_tunnel_id: Arc::new(AtomicU64::new(1)),
            refill_state: Arc::new(Mutex::new(RefillState::default())),
            tls,
            pool_idle_timeout,
            heartbeat_idle_grace,
            on_demand_phase: Arc::new(AtomicU8::new(OnDemandPhase::Dormant as u8)),
            phase_lock: Arc::new(StdMutex::new(())),
            heartbeat_enabled_tx,
        })
    }

    pub fn is_dormant(&self) -> bool {
        self.phase() == OnDemandPhase::Dormant
    }

    pub fn subscribe_heartbeat_enabled(&self) -> watch::Receiver<bool> {
        self.heartbeat_enabled_tx.subscribe()
    }

    fn phase(&self) -> OnDemandPhase {
        OnDemandPhase::from_u8(self.on_demand_phase.load(Ordering::Acquire))
    }

    fn set_heartbeat_enabled(&self, enabled: bool) {
        self.heartbeat_enabled_tx.send_if_modified(|current| {
            if *current != enabled {
                *current = enabled;
                true
            } else {
                false
            }
        });
    }

    fn wake_on_request(&self) {
        let _guard = self
            .phase_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.last_traffic_unix_ms
            .store(unix_now_millis(), Ordering::Relaxed);
        let prev = OnDemandPhase::from_u8(
            self.on_demand_phase
                .swap(OnDemandPhase::Active as u8, Ordering::AcqRel),
        );
        self.set_heartbeat_enabled(true);
        if prev != OnDemandPhase::Active {
            info!(
                previous_phase = ?prev,
                "on-demand request received; waking tunnel pool and heartbeat"
            );
        }
        // Always notify so any active idle/grace timer resets from this request.
        self.state_notify.notify_waiters();
    }

    async fn drain_all_idle_tunnels(&self) -> usize {
        let mut drained_tunnels = Vec::new();
        {
            let mut idle_rx = self.idle_rx.lock().await;
            while let Ok(tunnel) = idle_rx.try_recv() {
                drained_tunnels.push(tunnel);
            }
        }
        {
            let mut refill_state = self.refill_state.lock().await;
            refill_state.next_allowed_at = None;
            refill_state.cooldown_logged_for = None;
        }
        let closed = drained_tunnels.len();
        for mut tunnel in drained_tunnels {
            let _ = tokio::time::timeout(Duration::from_millis(500), tunnel.stream.shutdown()).await;
        }
        closed
    }

    async fn advance_on_demand_phase(&self) {
        enum Transition {
            None,
            ToHeartbeatGrace,
            ToDormant { drain_pool: bool },
        }

        let transition = {
            let _guard = self
                .phase_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.active.load(Ordering::Relaxed) > 0 {
                let prev = OnDemandPhase::from_u8(
                    self.on_demand_phase
                        .swap(OnDemandPhase::Active as u8, Ordering::AcqRel),
                );
                if prev != OnDemandPhase::Active {
                    self.set_heartbeat_enabled(true);
                }
                Transition::None
            } else {
                let last_ms = self.last_traffic_unix_ms.load(Ordering::Relaxed);
                if last_ms == 0 {
                    Transition::None
                } else {
                    let elapsed = Duration::from_millis(unix_now_millis().saturating_sub(last_ms));
                    let total_idle_timeout = self
                        .pool_idle_timeout
                        .saturating_add(self.heartbeat_idle_grace);
                    match self.phase() {
                        OnDemandPhase::Active if elapsed >= total_idle_timeout => {
                            self.on_demand_phase
                                .store(OnDemandPhase::Dormant as u8, Ordering::Release);
                            self.set_heartbeat_enabled(false);
                            Transition::ToDormant { drain_pool: true }
                        }
                        OnDemandPhase::Active if elapsed >= self.pool_idle_timeout => {
                            self.on_demand_phase.store(
                                OnDemandPhase::HeartbeatGrace as u8,
                                Ordering::Release,
                            );
                            Transition::ToHeartbeatGrace
                        }
                        OnDemandPhase::HeartbeatGrace if elapsed >= total_idle_timeout => {
                            self.on_demand_phase
                                .store(OnDemandPhase::Dormant as u8, Ordering::Release);
                            self.set_heartbeat_enabled(false);
                            Transition::ToDormant { drain_pool: false }
                        }
                        _ => Transition::None,
                    }
                }
            }
        };

        match transition {
            Transition::None => {}
            Transition::ToHeartbeatGrace => {
                let closed = self.drain_all_idle_tunnels().await;
                info!(
                    closed_tunnels = closed,
                    grace_secs = self.heartbeat_idle_grace.as_secs(),
                    "idle pool timeout reached; closing reserved tunnels and keeping heartbeat for grace period"
                );
                self.state_notify.notify_waiters();
            }
            Transition::ToDormant { drain_pool } => {
                let closed = if drain_pool {
                    self.drain_all_idle_tunnels().await
                } else {
                    0
                };
                info!(
                    closed_tunnels = closed,
                    "heartbeat idle grace elapsed; entering dormant state"
                );
                self.state_notify.notify_waiters();
            }
        }
    }

    pub fn state_notify(&self) -> Arc<Notify> {
        self.state_notify.clone()
    }

    /// Called when the host OS reports a network connectivity change (e.g. Android
    /// Wi-Fi <-> 5G switch or wakeup with restored network). Clears refill backoff,
    /// invalidates cached idle tunnel freshness so they are probed immediately, and
    /// wakes the maintainer to ensure a connected tunnel is ready right away while active.
    pub async fn notify_network_available(&self) {
        if self.phase() != OnDemandPhase::Active {
            return;
        }
        {
            let mut refill_state = self.refill_state.lock().await;
            refill_state.consecutive_failures = 0;
            refill_state.next_allowed_at = None;
            refill_state.cooldown_logged_for = None;
        }
        // Expire `verified_at` on queued idle tunnels so the next sweep or acquire
        // probes them against the new network interface before trusting them.
        let mut drained = Vec::new();
        {
            let mut idle_rx = self.idle_rx.lock().await;
            while let Ok(mut tunnel) = idle_rx.try_recv() {
                tunnel.verified_at = UNIX_EPOCH;
                drained.push(tunnel);
            }
        }
        for tunnel in drained {
            let _ = self.idle_tx.send(tunnel).await;
        }
        self.state_notify.notify_waiters();
    }

    fn effective_warm_target(&self) -> usize {
        if self.phase() == OnDemandPhase::Active {
            self.warm_idle_target
        } else {
            0
        }
    }

    pub fn spawn_maintainer(&self) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                // Register the waiter before inspecting phase/timestamps so a concurrent
                // request wakeup can never be missed while transitioning or computing sleep.
                let notified = this.state_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                this.advance_on_demand_phase().await;
                if this.phase() == OnDemandPhase::Active {
                    this.reap_idle_tunnels().await;
                    this.schedule_refill().await;
                }
                match this.pick_maintenance_interval().await {
                    Some(interval) => {
                        tokio::select! {
                            _ = tokio::time::sleep(interval) => {}
                            _ = &mut notified => {}
                        }
                    }
                    None => {
                        notified.await;
                    }
                }
            }
        })
    }

    /// Chooses the next maintenance sleep duration based on pool state so the
    /// maintainer backs off when everything is healthy and parks completely when dormant.
    async fn pick_maintenance_interval(&self) -> Option<Duration> {
        match self.phase() {
            OnDemandPhase::Dormant => return None,
            OnDemandPhase::HeartbeatGrace => {
                let last_ms = self.last_traffic_unix_ms.load(Ordering::Relaxed);
                let elapsed = Duration::from_millis(unix_now_millis().saturating_sub(last_ms));
                let total = self
                    .pool_idle_timeout
                    .saturating_add(self.heartbeat_idle_grace);
                return Some(
                    total
                        .saturating_sub(elapsed)
                        .max(Duration::from_millis(50)),
                );
            }
            OnDemandPhase::Active => {}
        }

        let idle = self.idle_len();
        let inspecting = self.inspecting_idle.load(Ordering::Relaxed);
        let connecting = self.connecting.load(Ordering::Relaxed);
        let in_flight = inspecting.saturating_add(connecting);
        let target = self.effective_warm_target();

        // If refill is backing off, honor the backoff cooldown
        let mut interval = {
            let refill_state = self.refill_state.lock().await;
            refill_state
                .next_allowed_at
                .and_then(|next_allowed_at| {
                    let now = Instant::now();
                    (next_allowed_at > now).then(|| {
                        next_allowed_at
                            .duration_since(now)
                            .clamp(POOL_MAINTENANCE_INTERVAL_FAST, POOL_MAINTENANCE_INTERVAL_SLOW)
                    })
                })
        };

        if interval.is_none() {
            // Pool is below the effective warm target or refills/probes are running — stay fast.
            if idle.saturating_add(in_flight) < target || in_flight > 0 {
                interval = Some(POOL_MAINTENANCE_INTERVAL_FAST);
            } else {
                interval = Some(POOL_MAINTENANCE_INTERVAL_SLOW);
            }
        }

        let mut interval = interval.expect("maintenance interval should be computed");
        if self.active.load(Ordering::Relaxed) == 0 {
            let last_ms = self.last_traffic_unix_ms.load(Ordering::Relaxed);
            if last_ms > 0 {
                let elapsed = Duration::from_millis(unix_now_millis().saturating_sub(last_ms));
                let remaining = self
                    .pool_idle_timeout
                    .saturating_sub(elapsed)
                    .max(Duration::from_millis(50));
                interval = interval.min(remaining);
            }
        }

        Some(interval)
    }

    pub fn idle_len(&self) -> usize {
        self.max_idle_size.saturating_sub(self.idle_tx.capacity())
    }

    pub async fn snapshot(&self) -> TunnelPoolSnapshot {
        let refill_state = self.refill_state.lock().await;
        let now = Instant::now();
        let next_refill_allowed_in_secs = refill_state
            .next_allowed_at
            .and_then(|next_allowed_at| next_allowed_at.checked_duration_since(now))
            .map(|remaining| {
                remaining
                    .as_millis()
                    .saturating_add(999)
                    .saturating_div(1_000) as u64
            });
        let last_traffic_ms = self.last_traffic_unix_ms.load(Ordering::Relaxed);
        let last_traffic_age_secs = (last_traffic_ms > 0)
            .then(|| unix_now_millis().saturating_sub(last_traffic_ms) / 1_000);

        TunnelPoolSnapshot {
            max_idle_size: self.max_idle_size,
            warm_idle_target: self.effective_warm_target(),
            idle: self.idle_len(),
            inspecting_idle: self.inspecting_idle.load(Ordering::Relaxed),
            connecting: self.connecting.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            last_traffic_age_secs,
            consecutive_failures: refill_state.consecutive_failures,
            next_refill_allowed_in_secs,
            created_total: refill_state.created_total,
            failed_total: refill_state.failed_total,
            reaped_stale_total: refill_state.reaped_stale_total,
            last_success_age_secs: refill_state
                .last_success_at
                .map(|last_success_at| last_success_at.elapsed().as_secs()),
            last_refill_error: refill_state.last_refill_error.clone(),
        }
    }

    fn allocate_tunnel_id(&self) -> u64 {
        self.next_tunnel_id.fetch_add(1, Ordering::Relaxed)
    }

    async fn schedule_refill(&self) {
        let now = Instant::now();
        let target = self.effective_warm_target();
        let (idle, inspecting_idle, connecting, missing) = {
            let mut refill_state = self.refill_state.lock().await;
            let idle = self.idle_len();
            let inspecting_idle = self.inspecting_idle.load(Ordering::Relaxed);
            let connecting = self.connecting.load(Ordering::Relaxed);
            let missing = target.saturating_sub(
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
                            warm_idle_target = target,
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
            warm_idle_target = target,
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
        let tunnel_id = self.allocate_tunnel_id();
        let sender = self.idle_tx.clone();
        let server_addr = self.server_addr;
        let shared_secret = self.shared_secret.clone();
        let client_id = self.client_id.clone();
        let connect_timeout = self.connect_timeout;
        let connecting = self.connecting.clone();
        let state_notify = self.state_notify.clone();
        let refill_state = self.refill_state.clone();
        let tls = self.tls.clone();
        let on_demand_phase = self.on_demand_phase.clone();
        let tls_backend = tls.as_ref().map(|tls| tls.backend).unwrap_or("plain");
        let tls_server_name = tls
            .as_ref()
            .map(|tls| tls.server_name_display.clone())
            .unwrap_or_default();
        let client_auth_configured = tls
            .as_ref()
            .map(|tls| tls.client_auth_configured)
            .unwrap_or(false);
        info!(
            tunnel_id,
            server_addr = %server_addr,
            client_id = %client_id,
            tls_backend,
            tls_server_name,
            client_auth_configured,
            timeout_secs = connect_timeout.as_secs(),
            "starting idle tunnel creation"
        );
        tokio::spawn(async move {
            let result = connect_idle_tunnel(
                server_addr,
                &shared_secret,
                &client_id,
                connect_timeout,
                tls,
                tunnel_id,
                "warm-refill",
            )
            .await;
            match result {
                Ok(stream) => {
                    reset_refill_backoff(&refill_state).await;
                    if OnDemandPhase::from_u8(on_demand_phase.load(Ordering::Acquire))
                        != OnDemandPhase::Active
                    {
                        connecting.fetch_sub(1, Ordering::SeqCst);
                        drop(stream);
                        debug!(
                            tunnel_id,
                            "discarding late warm-refill tunnel after leaving active phase"
                        );
                    } else if sender
                        .send(IdleTunnel::new(tunnel_id, stream))
                        .await
                        .is_err()
                    {
                        connecting.fetch_sub(1, Ordering::SeqCst);
                        warn!(
                            tunnel_id,
                            "tunnel pool receiver dropped while returning idle tunnel"
                        );
                    } else {
                        connecting.fetch_sub(1, Ordering::SeqCst);
                        info!(tunnel_id, "idle tunnel added to pool");
                    }
                    state_notify.notify_waiters();
                }
                Err(err) => {
                    connecting.fetch_sub(1, Ordering::SeqCst);
                    let (failures, backoff_secs) =
                        register_refill_failure(&refill_state, &err.to_string()).await;
                    state_notify.notify_waiters();
                    warn!(
                        tunnel_id,
                        server_addr = %server_addr,
                        client_id = %client_id,
                        timeout_secs = connect_timeout.as_secs(),
                        tls_backend,
                        tls_server_name,
                        client_auth_configured,
                        consecutive_failures = failures,
                        backoff_secs,
                        error = %err,
                        "failed to create idle tunnel; refill will back off"
                    );
                }
            }
        });
    }

    fn record_traffic_start(&self) {
        self.last_traffic_unix_ms
            .store(unix_now_millis(), Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::SeqCst);
        self.state_notify.notify_waiters();
    }

    /// Upper bound for a single [`TunnelPool::acquire`] call: one cold dial plus
    /// the probes that may be spent discarding stale idle tunnels on the way.
    pub fn acquire_budget(&self) -> Duration {
        self.connect_timeout
            + IDLE_TUNNEL_PROBE_TIMEOUT * (MAX_STALE_TUNNELS_PER_ACQUIRE as u32 + 1)
    }

    pub async fn acquire(&self) -> Result<TunnelLease, AppError> {
        self.wake_on_request();
        let mut stale_count = 0usize;
        loop {
            let next_idle = {
                let mut idle_rx = self.idle_rx.lock().await;
                idle_rx.try_recv().ok()
            };
            let Some(mut idle_tunnel) = next_idle else {
                break;
            };

            if idle_tunnel
                .verified_at
                .elapsed()
                .map_or(true, |age| age >= IDLE_TUNNEL_HEALTHY_FOR)
            {
                match probe_idle_tunnel(&mut idle_tunnel.stream).await {
                    Ok(()) => {
                        idle_tunnel.verified_at = SystemTime::now();
                    }
                    Err(err) => {
                        stale_count += 1;
                        record_stale_tunnel(&self.refill_state).await;
                        warn!(
                            tunnel_id = idle_tunnel.tunnel_id,
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

            let idle_remaining = self.idle_len().saturating_sub(1);
            debug!(
                tunnel_id = idle_tunnel.tunnel_id,
                idle_remaining, "reusing verified pooled tunnel"
            );
            self.record_traffic_start();
            self.schedule_refill().await;
            return Ok(TunnelLease {
                inner: idle_tunnel.stream,
                id: idle_tunnel.tunnel_id,
                from_pool: true,
                active: self.active.clone(),
                last_traffic_unix_ms: self.last_traffic_unix_ms.clone(),
                state_notify: self.state_notify.clone(),
            });
        }

        self.acquire_fresh().await
    }

    /// Dials a brand new tunnel, bypassing the idle pool entirely.
    ///
    /// Callers use this as the retry step after a pooled tunnel failed to answer
    /// a CONNECT: on a lossy path a "warm" tunnel can be silently dead while
    /// still looking fresh to the pool, and only a fresh dial recovers.
    pub async fn acquire_fresh(&self) -> Result<TunnelLease, AppError> {
        self.schedule_refill().await;
        let tunnel_id = self.allocate_tunnel_id();
        info!(
            tunnel_id,
            server_addr = %self.server_addr,
            client_id = %self.client_id,
            "pool is empty; creating fresh tunnel during acquire fallback"
        );
        let stream = match connect_idle_tunnel(
            self.server_addr,
            &self.shared_secret,
            &self.client_id,
            self.connect_timeout,
            self.tls.clone(),
            tunnel_id,
            "acquire-fallback",
        )
        .await
        {
            Ok(stream) => {
                reset_refill_backoff(&self.refill_state).await;
                info!(tunnel_id, "fresh acquire fallback tunnel is ready");
                stream
            }
            Err(err) => {
                let (failures, backoff_secs) =
                    register_refill_failure(&self.refill_state, &err.to_string()).await;
                self.state_notify.notify_waiters();
                warn!(
                    tunnel_id,
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
                    consecutive_failures = failures,
                    backoff_secs,
                    error = %err,
                    "failed to create fresh tunnel during acquire fallback"
                );
                return Err(err);
            }
        };
        self.record_traffic_start();
        Ok(TunnelLease {
            inner: stream,
            id: tunnel_id,
            from_pool: false,
            active: self.active.clone(),
            last_traffic_unix_ms: self.last_traffic_unix_ms.clone(),
            state_notify: self.state_notify.clone(),
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
            if idle_tunnel
                .verified_at
                .elapsed()
                .is_ok_and(|age| age < IDLE_TUNNEL_HEALTHY_FOR)
            {
                self.return_idle_tunnel(idle_tunnel).await;
                continue;
            }

            match probe_idle_tunnel(&mut idle_tunnel.stream).await {
                Ok(()) => {
                    idle_tunnel.verified_at = SystemTime::now();
                    debug!(
                        tunnel_id = idle_tunnel.tunnel_id,
                        "idle tunnel probe succeeded"
                    );
                    self.return_idle_tunnel(idle_tunnel).await;
                }
                Err(err) => {
                    dropped_stale = dropped_stale.saturating_add(1);
                    record_stale_tunnel(&self.refill_state).await;
                    self.inspecting_idle.fetch_sub(1, Ordering::SeqCst);
                    warn!(
                        tunnel_id = idle_tunnel.tunnel_id,
                        error = %err,
                        "discarding stale idle tunnel during maintenance"
                    );
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
    fn new(tunnel_id: u64, stream: TunnelStream) -> Self {
        Self {
            tunnel_id,
            stream,
            verified_at: SystemTime::now(),
        }
    }
}

impl Default for RefillState {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            next_allowed_at: None,
            cooldown_logged_for: None,
            created_total: 0,
            failed_total: 0,
            reaped_stale_total: 0,
            last_success_at: None,
            last_refill_error: None,
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

impl TunnelLease {
    pub(crate) fn log_context(&self) -> (u64, &'static str) {
        (self.id, if self.from_pool { "warm" } else { "cold" })
    }

    /// Whether this lease came from the pre-warmed idle pool instead of being
    /// dialed on demand. Callers use it to decide whether a failed CONNECT is
    /// worth retrying on a brand new tunnel.
    pub fn from_pool(&self) -> bool {
        self.from_pool
    }

    fn touch_traffic(&self) {
        self.last_traffic_unix_ms
            .store(unix_now_millis(), Ordering::Relaxed);
    }
}

impl Drop for TunnelLease {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.state_notify.notify_waiters();
    }
}

impl AsyncRead for TunnelLease {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if matches!(&poll, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.touch_traffic();
        }
        poll
    }
}

impl AsyncWrite for TunnelLease {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if matches!(&poll, Poll::Ready(Ok(n)) if *n > 0) {
            self.touch_traffic();
        }
        poll
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
    tunnel_id: u64,
    purpose: &'static str,
) -> Result<TunnelStream, AppError> {
    debug!(
        tunnel_id,
        purpose,
        server_addr = %server_addr,
        timeout_secs = connect_timeout.as_secs(),
        "tcp tunnel dial started"
    );
    let started = Instant::now();
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(server_addr))
        .await
        .map_err(|_| AppError::InvalidConfig("client tunnel connect timed out".to_string()))
        .and_then(|result| result.map_err(AppError::Io))
        .inspect_err(|err| {
            warn!(tunnel_id, purpose, stage = "tcp", elapsed_ms = started.elapsed().as_millis() as u64, error = %err, "Rama tunnel setup failed");
        })?;
    let tcp_ms = started.elapsed().as_millis() as u64;
    stream.set_nodelay(true)?;
    let socket = socket2::SockRef::from(&stream);
    let keepalive =
        socket2::TcpKeepalive::new().with_time(Duration::from_secs(TUNNEL_TCP_KEEPALIVE_SECS));
    let _ = socket.set_tcp_keepalive(&keepalive);

    let tls_started = Instant::now();
    let (mut stream, tls_ms): (TunnelStream, u64) = match tls {
        Some(tls) => {
            let result = tls.connector.connect(tls.server_name, stream).await;
            let elapsed_ms = tls_started.elapsed().as_millis() as u64;
            let stream = result.map_err(|err| {
                warn!(tunnel_id, purpose, stage = "tls", elapsed_ms, error = %err, "Rama tunnel setup failed");
                AppError::Boxed(format!("tls connect failed: {err}"))
            })?;
            (Box::new(stream), elapsed_ms)
        }
        None => (Box::new(stream), 0),
    };
    let auth_started = Instant::now();
    let auth_result = client_handshake(&mut stream, shared_secret, client_id).await;
    let auth_ms = auth_started.elapsed().as_millis() as u64;
    auth_result.inspect_err(|err| {
        warn!(tunnel_id, purpose, stage = "auth", elapsed_ms = auth_ms, error = %err, "Rama tunnel setup failed");
    })?;
    info!(
        tunnel_id,
        purpose,
        server = %server_addr,
        tcp_ms,
        tls_ms,
        auth_ms,
        total_ms = started.elapsed().as_millis() as u64,
        "Rama tunnel ready"
    );
    Ok(stream)
}

pub async fn run_heartbeat(
    server_addr: SocketAddr,
    shared_secret: &str,
    client_id: &str,
    connect_timeout: Duration,
    tls: Option<ClientTlsContext>,
    heartbeat_id: u64,
    read_timeout: Duration,
) -> Result<(), AppError> {
    let mut stream = connect_idle_tunnel(
        server_addr,
        shared_secret,
        client_id,
        connect_timeout,
        tls,
        heartbeat_id,
        "heartbeat",
    )
    .await?;
    write_heartbeat_open(&mut stream).await?;
    info!(
        heartbeat_id,
        server_addr = %server_addr,
        client_id,
        read_timeout_secs = read_timeout.as_secs(),
        "heartbeat channel established"
    );
    loop {
        let (_, ids) = tokio::time::timeout(read_timeout, read_heartbeat(&mut stream))
            .await
            .map_err(|_| {
                AppError::InvalidConfig(format!(
                    "heartbeat read timed out after {} seconds",
                    read_timeout.as_secs()
                ))
            })??;
        write_heartbeat_ack(&mut stream, &ids).await?;
        debug!(
            heartbeat_id,
            tunnel_count = ids.len(),
            tunnel_ids = ?ids,
            "heartbeat tunnel snapshot received"
        );
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

pub async fn server_handshake<S>(
    stream: &mut S,
    shared_secret: &str,
    require_client_id: bool,
) -> Result<String, AppError>
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
    if require_client_id && client_id.trim().is_empty() {
        stream.write_u8(STATUS_CLIENT_ID_REQUIRED).await?;
        stream.flush().await?;
        return Err(AppError::InvalidConfig(
            "client_id is required by server auth policy".to_string(),
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
    read_response_message(reader).await.map(|_| ())
}

pub(crate) async fn read_response_message<R>(reader: &mut R) -> Result<String, AppError>
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
        Ok(message)
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
    refill_state.created_total = refill_state.created_total.saturating_add(1);
    refill_state.last_success_at = Some(Instant::now());
    refill_state.last_refill_error = None;
}

async fn register_refill_failure(
    refill_state: &Arc<Mutex<RefillState>>,
    error: &str,
) -> (usize, u64) {
    let mut refill_state = refill_state.lock().await;
    refill_state.consecutive_failures = refill_state.consecutive_failures.saturating_add(1);
    refill_state.failed_total = refill_state.failed_total.saturating_add(1);
    refill_state.last_refill_error = Some(error.to_string());
    let backoff = compute_refill_backoff(refill_state.consecutive_failures);
    refill_state.next_allowed_at = Some(Instant::now() + backoff);
    refill_state.cooldown_logged_for = None;
    (refill_state.consecutive_failures, backoff.as_secs())
}

async fn record_stale_tunnel(refill_state: &Arc<Mutex<RefillState>>) {
    let mut refill_state = refill_state.lock().await;
    refill_state.reaped_stale_total = refill_state.reaped_stale_total.saturating_add(1);
}

fn compute_refill_backoff(consecutive_failures: usize) -> Duration {
    let shift = consecutive_failures.saturating_sub(1).min(5) as u32;
    Duration::from_secs(1u64 << shift).min(MAX_REFILL_BACKOFF)
}

fn compute_warm_idle_target(max_idle_size: usize) -> usize {
    max_idle_size
}
