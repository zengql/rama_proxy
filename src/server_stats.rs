use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::AppError;

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Clone)]
pub struct ServerStatsRegistry {
    next_id: Arc<AtomicU64>,
    connections: Arc<RwLock<HashMap<u64, LiveConnection>>>,
}

impl ServerStatsRegistry {
    pub fn new() -> Self {
        Self {
            next_id: Arc::new(AtomicU64::new(1)),
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_connection(&self, client_addr: String) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let now = now_unix_secs();
        let entry = LiveConnection {
            id,
            client_addr,
            state: "handshake".to_string(),
            accepted_at_unix_secs: now,
            last_active_unix_secs: now,
            target_addr: None,
            upstream_addr: None,
            bytes_from_client: 0,
            bytes_from_target: 0,
            in_use: false,
        };
        self.connections.write().await.insert(id, entry);
        id
    }

    pub async fn mark_idle(&self, id: u64) {
        self.update(id, |entry| {
            entry.state = "idle".to_string();
            entry.in_use = false;
            entry.last_active_unix_secs = now_unix_secs();
        })
        .await;
    }

    pub async fn mark_active_tcp(&self, id: u64, target_addr: String) {
        self.update(id, |entry| {
            entry.state = "active-tcp".to_string();
            entry.target_addr = Some(target_addr.clone());
            entry.in_use = true;
            entry.last_active_unix_secs = now_unix_secs();
        })
        .await;
    }

    pub async fn mark_active_udp(&self, id: u64) {
        self.update(id, |entry| {
            entry.state = "active-udp".to_string();
            entry.in_use = true;
            entry.last_active_unix_secs = now_unix_secs();
        })
        .await;
    }

    pub async fn set_upstream_addr(&self, id: u64, upstream_addr: String) {
        self.update(id, |entry| {
            entry.upstream_addr = Some(upstream_addr.clone());
            entry.last_active_unix_secs = now_unix_secs();
        })
        .await;
    }

    pub async fn touch(&self, id: u64) {
        self.update(id, |entry| {
            entry.last_active_unix_secs = now_unix_secs();
        })
        .await;
    }

    pub async fn add_tcp_bytes(&self, id: u64, bytes_from_client: u64, bytes_from_target: u64) {
        self.update(id, |entry| {
            entry.bytes_from_client = entry.bytes_from_client.saturating_add(bytes_from_client);
            entry.bytes_from_target = entry.bytes_from_target.saturating_add(bytes_from_target);
            entry.last_active_unix_secs = now_unix_secs();
        })
        .await;
    }

    pub async fn add_udp_client_bytes(&self, id: u64, target_addr: String, bytes: u64) {
        self.update(id, |entry| {
            entry.state = "active-udp".to_string();
            entry.target_addr = Some(target_addr.clone());
            entry.in_use = true;
            entry.bytes_from_client = entry.bytes_from_client.saturating_add(bytes);
            entry.last_active_unix_secs = now_unix_secs();
        })
        .await;
    }

    pub async fn add_udp_target_bytes(&self, id: u64, upstream_addr: String, bytes: u64) {
        self.update(id, |entry| {
            entry.state = "active-udp".to_string();
            entry.upstream_addr = Some(upstream_addr.clone());
            entry.in_use = true;
            entry.bytes_from_target = entry.bytes_from_target.saturating_add(bytes);
            entry.last_active_unix_secs = now_unix_secs();
        })
        .await;
    }

    pub async fn remove_connection(&self, id: u64) {
        self.connections.write().await.remove(&id);
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub async fn snapshot(&self) -> ServerStatsSnapshot {
        let now = now_unix_secs();
        let connections = self.connections.read().await;
        let mut items = connections.values().cloned().collect::<Vec<_>>();
        items.sort_by_key(|item| item.id);

        let mut summary = ServerStatsSummary::default();
        for item in &items {
            summary.total_connections += 1;
            match item.state.as_str() {
                "idle" => summary.idle_connections += 1,
                "active-tcp" => summary.active_tcp_connections += 1,
                "active-udp" => summary.active_udp_connections += 1,
                _ => summary.handshake_connections += 1,
            }
            if item.in_use {
                summary.in_use_connections += 1;
            }
            summary.bytes_from_client = summary
                .bytes_from_client
                .saturating_add(item.bytes_from_client);
            summary.bytes_from_target = summary
                .bytes_from_target
                .saturating_add(item.bytes_from_target);
        }

        ServerStatsSnapshot {
            generated_at_unix_secs: now,
            summary,
            connections: items
                .into_iter()
                .map(|item| ConnectionSnapshot {
                    id: item.id,
                    client_addr: item.client_addr,
                    state: item.state,
                    accepted_at_unix_secs: item.accepted_at_unix_secs,
                    last_active_unix_secs: item.last_active_unix_secs,
                    age_secs: now.saturating_sub(item.accepted_at_unix_secs),
                    idle_secs: now.saturating_sub(item.last_active_unix_secs),
                    target_addr: item.target_addr,
                    upstream_addr: item.upstream_addr,
                    bytes_from_client: item.bytes_from_client,
                    bytes_from_target: item.bytes_from_target,
                    in_use: item.in_use,
                })
                .collect(),
        }
    }

    async fn update<F>(&self, id: u64, mut f: F)
    where
        F: FnMut(&mut LiveConnection),
    {
        if let Some(entry) = self.connections.write().await.get_mut(&id) {
            f(entry);
        }
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatsSnapshot {
    pub generated_at_unix_secs: u64,
    pub summary: ServerStatsSummary,
    pub connections: Vec<ConnectionSnapshot>,
}

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerStatsSummary {
    pub total_connections: usize,
    pub handshake_connections: usize,
    pub idle_connections: usize,
    pub active_tcp_connections: usize,
    pub active_udp_connections: usize,
    pub in_use_connections: usize,
    pub bytes_from_client: u64,
    pub bytes_from_target: u64,
}

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    pub id: u64,
    pub client_addr: String,
    pub state: String,
    pub accepted_at_unix_secs: u64,
    pub last_active_unix_secs: u64,
    pub age_secs: u64,
    pub idle_secs: u64,
    pub target_addr: Option<String>,
    pub upstream_addr: Option<String>,
    pub bytes_from_client: u64,
    pub bytes_from_target: u64,
    pub in_use: bool,
}

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone)]
struct LiveConnection {
    id: u64,
    client_addr: String,
    state: String,
    accepted_at_unix_secs: u64,
    last_active_unix_secs: u64,
    target_addr: Option<String>,
    upstream_addr: Option<String>,
    bytes_from_client: u64,
    bytes_from_target: u64,
    in_use: bool,
}

#[cfg(unix)]
pub fn spawn_stats_server(registry: ServerStatsRegistry, path: PathBuf) {
    tokio::spawn(async move {
        if let Err(err) = run_stats_server(registry, path).await {
            tracing::warn!("stats socket server stopped: {err}");
        }
    });
}

#[cfg(not(unix))]
pub fn spawn_stats_server(_registry: ServerStatsRegistry, _path: PathBuf) {}

#[cfg(unix)]
pub async fn print_snapshot(path: &Path) -> Result<(), AppError> {
    let value = query_snapshot_value(path).await?;
    let rendered = serde_json::to_string_pretty(&value)
        .map_err(|err| AppError::Boxed(format!("render stats response failed: {err}")))?;
    println!("{rendered}");
    Ok(())
}

#[cfg(unix)]
pub async fn query_snapshot(path: &Path) -> Result<ServerStatsSnapshot, AppError> {
    let body = query_snapshot_bytes(path).await?;
    serde_json::from_slice(&body)
        .map_err(|err| AppError::Boxed(format!("parse stats response failed: {err}")))
}

#[cfg(not(unix))]
pub async fn print_snapshot(_path: &Path) -> Result<(), AppError> {
    Err(AppError::InvalidConfig(
        "server stats socket is supported on unix-like systems only".to_string(),
    ))
}

#[cfg(unix)]
async fn run_stats_server(registry: ServerStatsRegistry, path: PathBuf) -> Result<(), AppError> {
    use tokio::net::UnixListener;

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| AppError::Boxed(format!("create stats socket dir failed: {err}")))?;
    }
    if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        let _ = tokio::fs::remove_file(&path).await;
    }

    let listener = UnixListener::bind(&path)
        .map_err(|err| AppError::Boxed(format!("bind stats socket failed: {err}")))?;

    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|err| AppError::Boxed(format!("accept stats socket failed: {err}")))?;
        let registry = registry.clone();
        tokio::spawn(async move {
            let mut req = [0u8; 64];
            let _ = stream.read(&mut req).await;
            let snapshot = registry.snapshot().await;
            match serde_json::to_vec(&snapshot) {
                Ok(body) => {
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                }
                Err(err) => {
                    let _ = stream
                        .write_all(
                            format!(r#"{{"error":"serialize stats response failed: {err}"}}"#)
                                .as_bytes(),
                        )
                        .await;
                }
            }
        });
    }
}

#[cfg(unix)]
async fn query_snapshot_value(path: &Path) -> Result<serde_json::Value, AppError> {
    let body = query_snapshot_bytes(path).await?;
    serde_json::from_slice(&body)
        .map_err(|err| AppError::Boxed(format!("parse stats response failed: {err}")))
}

#[cfg(unix)]
async fn query_snapshot_bytes(path: &Path) -> Result<Vec<u8>, AppError> {
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(path)
        .await
        .map_err(|err| AppError::Boxed(format!("connect stats socket failed: {err}")))?;
    stream
        .write_all(b"stats\n")
        .await
        .map_err(|err| AppError::Boxed(format!("write stats request failed: {err}")))?;
    let mut body = Vec::new();
    stream
        .read_to_end(&mut body)
        .await
        .map_err(|err| AppError::Boxed(format!("read stats response failed: {err}")))?;
    Ok(body)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}
