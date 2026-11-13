use std::collections::VecDeque;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "android")]
use jni::objects::{GlobalRef, JObject, JString, JValue};
#[cfg(target_os = "android")]
use jni::sys::{jboolean, JNI_FALSE, JNI_TRUE};
#[cfg(target_os = "android")]
use jni::{JNIEnv, JavaVM};
use proxy_core::config::ClientConfigFile;
use proxy_core::tunnel::TunnelPoolSnapshot;
use rustls::pki_types::{pem::PemObject, CertificateDer};
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use tokio::sync::{oneshot, watch, Mutex};
use tracing::{info, warn};
use tracing_subscriber::{filter::EnvFilter, fmt::MakeWriter};

const LOCAL_BIND: &str = "127.0.0.1";
const CONFIG_FILE: &str = "client.toml";
const RESUME_MARKER_FILE: &str = "resume.intent";
const LOG_FILE: &str = "rama-proxy.log";
const CERTS_DIR: &str = "certs";
const CA_CERT_FILE: &str = "ca.pem";
const MAX_CA_CERT_BYTES: usize = 512 * 1024;
const START_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
/// Keep the wake/Wi-Fi locks this long after the last proxied connection closes.
#[cfg(target_os = "android")]
const TRAFFIC_LOCK_RELEASE_DELAY: Duration = Duration::from_secs(30);
/// Re-send "active" this often so the Android-side 10 minute lock timeout never expires
/// mid-traffic; leaves room for several failed bridge calls before the timeout.
#[cfg(target_os = "android")]
const TRAFFIC_LOCK_REFRESH_INTERVAL: Duration = Duration::from_secs(2 * 60);

const MAX_LOG_LINES: usize = 1_000;
const MAX_LOG_FILE_BYTES: u64 = 2 * 1024 * 1024;
#[cfg(target_os = "android")]
const ANDROID_LOG_TAG: &str = "RamaProxy";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogRecord {
    timestamp_ms: u64,
    line: String,
}

static LOG_BUFFER: OnceLock<StdMutex<VecDeque<LogRecord>>> = OnceLock::new();
static LOG_FILE_PATH: OnceLock<StdMutex<Option<PathBuf>>> = OnceLock::new();
static LOG_FILE_IO_LOCK: StdMutex<()> = StdMutex::new(());
static SERVICE_STATE: OnceLock<Arc<Mutex<ServiceState>>> = OnceLock::new();
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

#[cfg(target_os = "android")]
static ANDROID_JAVA_VM: OnceLock<JavaVM> = OnceLock::new();
#[cfg(target_os = "android")]
static ANDROID_SERVICE_CLASS: OnceLock<GlobalRef> = OnceLock::new();

fn shared_service_state() -> &'static Arc<Mutex<ServiceState>> {
    SERVICE_STATE.get_or_init(|| Arc::new(Mutex::new(ServiceState::default())))
}

fn next_generation() -> u64 {
    NEXT_GENERATION.fetch_add(1, Ordering::Relaxed)
}

fn log_buffer() -> &'static StdMutex<VecDeque<LogRecord>> {
    LOG_BUFFER.get_or_init(|| StdMutex::new(VecDeque::with_capacity(MAX_LOG_LINES)))
}

fn log_file_path() -> &'static StdMutex<Option<PathBuf>> {
    LOG_FILE_PATH.get_or_init(|| StdMutex::new(None))
}

fn unix_now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Default)]
struct MemoryLogWriter {
    bytes: Vec<u8>,
}

struct MemoryLogMakeWriter;

impl<'a> MakeWriter<'a> for MemoryLogMakeWriter {
    type Writer = MemoryLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        MemoryLogWriter::default()
    }
}

impl Write for MemoryLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for MemoryLogWriter {
    fn drop(&mut self) {
        let line = String::from_utf8_lossy(&self.bytes);
        emit_log_line(line.trim_end_matches(['\r', '\n']));
    }
}

fn initialize_log_file(path: PathBuf) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let _io_guard = LOG_FILE_IO_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut loaded = Vec::new();
    if path.is_file() {
        let contents = fs::read_to_string(&path)?;
        for line in contents.lines().rev().take(MAX_LOG_LINES) {
            if let Ok(record) = serde_json::from_str::<LogRecord>(line) {
                loaded.push(record);
            }
        }
        loaded.reverse();
    }

    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    {
        let mut records = log_buffer()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        records.clear();
        records.extend(loaded);
    }

    let mut target = log_file_path()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *target = Some(path);
    Ok(())
}

fn append_log_record(record: &LogRecord) {
    let path = log_file_path()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let Some(path) = path else {
        return;
    };

    let _io_guard = LOG_FILE_IO_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if fs::metadata(&path)
        .map(|metadata| metadata.len() >= MAX_LOG_FILE_BYTES)
        .unwrap_or(false)
    {
        let rotated = path.with_extension("log.1");
        let _ = fs::remove_file(&rotated);
        let _ = fs::rename(&path, rotated);
    }

    let Ok(encoded) = serde_json::to_string(record) else {
        return;
    };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{encoded}");
    }
}

fn emit_log_line(line: &str) {
    if line.is_empty() {
        return;
    }

    let record = LogRecord {
        timestamp_ms: unix_now_millis(),
        line: line.to_string(),
    };
    {
        let mut records = log_buffer()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while records.len() >= MAX_LOG_LINES {
            records.pop_front();
        }
        records.push_back(record.clone());
    }

    append_log_record(&record);
    write_platform_log(line);
}

#[cfg(target_os = "android")]
fn write_platform_log(line: &str) {
    use std::ffi::CString;

    let sanitized = line.replace('\0', "");
    let Ok(tag) = CString::new(ANDROID_LOG_TAG) else {
        return;
    };
    let Ok(message) = CString::new(sanitized) else {
        return;
    };

    // ANDROID_LOG_INFO
    unsafe {
        ndk_sys::__android_log_write(4, tag.as_ptr(), message.as_ptr());
    }
}

#[cfg(not(target_os = "android"))]
fn write_platform_log(line: &str) {
    eprintln!("{line}");
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_env("RAMA_PROXY_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(MemoryLogMakeWriter)
        .try_init();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct ClientSettings {
    server_addr: String,
    shared_secret: String,
    client_id: String,
    socks5_port: u16,
    pool_size: usize,
    udp_enabled: bool,
    tls_enabled: bool,
    tls_server_name: String,
    tls_ca_cert_path: String,
    tls_insecure_skip_verify: bool,
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            server_addr: String::new(),
            shared_secret: String::new(),
            client_id: String::new(),
            socks5_port: 1080,
            pool_size: 4,
            udp_enabled: false,
            tls_enabled: false,
            tls_server_name: String::new(),
            tls_ca_cert_path: String::new(),
            tls_insecure_skip_verify: false,
        }
    }
}

impl ClientSettings {
    fn into_config(&self) -> ClientConfigFile {
        let mut config = ClientConfigFile::default();
        config.client.server_addr = self.server_addr.trim().to_string();
        config.client.shared_secret = self.shared_secret.clone();
        config.client.client_id = self.client_id.trim().to_string();
        config.client.pool_size = self.pool_size;

        // Mobile clients are intentionally local-only. Do not accept a
        // configurable LAN bind address from the frontend.
        config.socks5.bind = LOCAL_BIND.to_string();
        config.socks5.port = self.socks5_port;

        config.http_connect.port = None;
        config.udp.enabled = self.udp_enabled;

        config.auth.mode = "none".to_string();
        config.auth.users.clear();

        config.tls.enabled = self.tls_enabled;
        config.tls.server_name = self.tls_server_name.trim().to_string();
        config.tls.ca_cert_path = self.tls_ca_cert_path.clone();
        config.tls.insecure_skip_verify = self.tls_insecure_skip_verify;
        config.tls.client_cert_path.clear();
        config.tls.client_key_path.clear();

        config
    }

    fn from_config(config: &ClientConfigFile) -> Self {
        Self {
            server_addr: config.client.server_addr.clone(),
            shared_secret: config.client.shared_secret.clone(),
            client_id: config.client.client_id.clone(),
            socks5_port: config.socks5.port,
            pool_size: config.client.pool_size,
            udp_enabled: config.udp.enabled,
            tls_enabled: config.tls.enabled,
            tls_server_name: config.tls.server_name.clone(),
            tls_ca_cert_path: config.tls.ca_cert_path.clone(),
            tls_insecure_skip_verify: config.tls.insecure_skip_verify,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientStatus {
    running: bool,
    socks5_bind: String,
    server_addr: String,
    started_at: Option<u64>,
    process_id: u32,
    last_error: Option<String>,
    pool_stats: Option<TunnelPoolSnapshot>,
    foreground_service_running: bool,
    foreground_service_restoring: bool,
    foreground_service_error: Option<String>,
    system_restarted: bool,
    battery_optimization_ignored: bool,
    wake_lock_held: bool,
    wifi_lock_held: bool,
    resume_pending: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: &'static str,
    vpn_enabled: bool,
    socks5_local_only: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportedCaCertificate {
    path: String,
    certificate_count: usize,
}

struct ServiceRuntime {
    generation: u64,
    shutdown: watch::Sender<bool>,
    pool_stats: watch::Receiver<Option<TunnelPoolSnapshot>>,
    task: tauri::async_runtime::JoinHandle<()>,
}

#[derive(Default)]
struct ServiceState {
    runtime: Option<ServiceRuntime>,
    socks5_bind: String,
    server_addr: String,
    started_at: Option<u64>,
    last_error: Option<String>,
    foreground_service_running: bool,
    foreground_service_error: Option<String>,
}

struct AppState {
    service: Arc<Mutex<ServiceState>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            service: shared_service_state().clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ForegroundServiceStatus {
    running: bool,
    system_restarted: bool,
    restore_in_progress: bool,
    restore_error: Option<String>,
    battery_optimization_ignored: bool,
    wake_lock_held: bool,
    wifi_lock_held: bool,
}

#[cfg(target_os = "android")]
struct ForegroundPluginHandle(tauri::plugin::PluginHandle<tauri::Wry>);

#[cfg(target_os = "android")]
fn proxy_foreground_plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::<tauri::Wry>::new("proxy-foreground")
        .setup(|app, api| {
            let handle =
                api.register_android_plugin("com.zqliang.ramaproxy", "ProxyForegroundPlugin")?;
            app.manage(ForegroundPluginHandle(handle));
            Ok(())
        })
        .build()
}

#[cfg(not(target_os = "android"))]
fn proxy_foreground_plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::<tauri::Wry>::new("proxy-foreground").build()
}

#[cfg(target_os = "android")]
async fn start_foreground_service(app: &tauri::AppHandle) -> Result<(), String> {
    let handle = app.state::<ForegroundPluginHandle>().0.clone();
    handle
        .run_mobile_plugin_async::<serde_json::Value>("start", serde_json::json!({}))
        .await
        .map_err(|err| format!("failed to start Android foreground service: {err}"))?;
    wait_for_foreground_service(app, true).await
}

#[cfg(not(target_os = "android"))]
async fn start_foreground_service(_app: &tauri::AppHandle) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "android")]
async fn stop_foreground_service(app: &tauri::AppHandle) -> Result<(), String> {
    let handle = app.state::<ForegroundPluginHandle>().0.clone();
    handle
        .run_mobile_plugin_async::<serde_json::Value>("stop", serde_json::json!({}))
        .await
        .map_err(|err| format!("failed to stop Android foreground service: {err}"))?;
    wait_for_foreground_service(app, false).await
}

#[cfg(not(target_os = "android"))]
async fn stop_foreground_service(_app: &tauri::AppHandle) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "android")]
async fn query_foreground_service_status(
    app: &tauri::AppHandle,
) -> Result<ForegroundServiceStatus, String> {
    let handle = app.state::<ForegroundPluginHandle>().0.clone();
    let value = handle
        .run_mobile_plugin_async::<serde_json::Value>("status", serde_json::json!({}))
        .await
        .map_err(|err| format!("failed to query Android foreground service: {err}"))?;
    Ok(ForegroundServiceStatus {
        running: value
            .get("running")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        system_restarted: value
            .get("systemRestarted")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        restore_in_progress: value
            .get("restoreInProgress")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        restore_error: value
            .get("restoreError")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
        battery_optimization_ignored: value
            .get("batteryOptimizationIgnored")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        wake_lock_held: value
            .get("wakeLockHeld")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        wifi_lock_held: value
            .get("wifiLockHeld")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    })
}

#[cfg(not(target_os = "android"))]
async fn query_foreground_service_status(
    _app: &tauri::AppHandle,
) -> Result<ForegroundServiceStatus, String> {
    Ok(ForegroundServiceStatus::default())
}

#[cfg(target_os = "android")]
fn call_android_foreground_static(
    method: &str,
    signature: &str,
    args: &[JValue<'_, '_>],
) -> Result<(), String> {
    let vm = ANDROID_JAVA_VM
        .get()
        .ok_or_else(|| "Android JavaVM is not initialized".to_string())?;
    let class = ANDROID_SERVICE_CLASS
        .get()
        .ok_or_else(|| "Android foreground service class is not initialized".to_string())?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|err| format!("failed to attach Android JNI thread: {err}"))?;
    env.call_static_method(class, method, signature, args)
        .map(|_| ())
        .map_err(|err| format!("failed to call ProxyForegroundService.{method}: {err}"))
}

#[cfg(target_os = "android")]
fn initialize_android_bridge(env: &mut JNIEnv<'_>, service: &JObject<'_>) -> Result<(), String> {
    let vm = env
        .get_java_vm()
        .map_err(|err| format!("failed to get Android JavaVM: {err}"))?;
    let class = env
        .get_object_class(service)
        .map_err(|err| format!("failed to get Android foreground service class: {err}"))?;
    let class = env
        .new_global_ref(class)
        .map_err(|err| format!("failed to retain Android foreground service class: {err}"))?;

    let _ = ANDROID_JAVA_VM.set(vm);
    let _ = ANDROID_SERVICE_CLASS.set(class);
    Ok(())
}

#[cfg(target_os = "android")]
fn notify_android_runtime_stopped() {
    if let Err(err) = call_android_foreground_static("onRuntimeStoppedFromRust", "()V", &[]) {
        warn!(error = %err, "failed to notify Android foreground service that the runtime stopped");
    }
}

#[cfg(target_os = "android")]
fn notify_android_restore_result(success: bool, message: &str) {
    let result = (|| -> Result<(), String> {
        let vm = ANDROID_JAVA_VM
            .get()
            .ok_or_else(|| "Android JavaVM is not initialized".to_string())?;
        let class = ANDROID_SERVICE_CLASS
            .get()
            .ok_or_else(|| "Android foreground service class is not initialized".to_string())?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|err| format!("failed to attach Android JNI thread: {err}"))?;
        let message = env
            .new_string(message)
            .map_err(|err| format!("failed to create Android restore message: {err}"))?;
        env.call_static_method(
            class,
            "onRuntimeRestoreResultFromRust",
            "(ZLjava/lang/String;)V",
            &[
                JValue::Bool(success as jboolean),
                JValue::Object(message.as_ref()),
            ],
        )
        .map(|_| ())
        .map_err(|err| format!("failed to report Android restore result: {err}"))
    })();

    if let Err(err) = result {
        warn!(error = %err, "failed to report Android runtime restore result");
    }
}

#[cfg(target_os = "android")]
async fn restore_runtime_from_android(data_dir: String) -> Result<String, String> {
    let data_dir = PathBuf::from(data_dir);

    init_tracing();
    if let Err(err) = initialize_log_file(data_dir.join(LOG_FILE)) {
        eprintln!("failed to initialize Android restore log file: {err}");
    }

    let marker = data_dir.join(RESUME_MARKER_FILE);
    if !marker.is_file() {
        return Err("automatic resume marker is missing".to_string());
    }

    let config_path = data_dir.join(CONFIG_FILE);
    let config = ClientConfigFile::from_path(&config_path)
        .map_err(|err| format!("failed to load {}: {err}", config_path.display()))?;

    info!(
        data_dir = %data_dir.display(),
        "restoring local SOCKS5 runtime from Android foreground service"
    );
    start_runtime(shared_service_state().clone(), config, None).await
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_zqliang_ramaproxy_ProxyForegroundService_nativeRuntimeBridge(
    mut env: JNIEnv<'_>,
    service: JObject<'_>,
    data_dir: JString<'_>,
    restore: jboolean,
) -> jboolean {
    let result = (|| -> Result<(), String> {
        initialize_android_bridge(&mut env, &service)?;

        if restore != JNI_TRUE {
            return Ok(());
        }

        let data_dir: String = env
            .get_string(&data_dir)
            .map_err(|err| format!("failed to read Android data directory: {err}"))?
            .into();

        tauri::async_runtime::spawn(async move {
            let result = restore_runtime_from_android(data_dir).await;
            match &result {
                Ok(bind) => info!(bind, "Android runtime restored from foreground service"),
                Err(err) => warn!(error = %err, "Android runtime restore failed"),
            }
            let message = result
                .as_deref()
                .unwrap_or("failed to restore the local SOCKS5 listener");
            notify_android_restore_result(result.is_ok(), message);
        });

        Ok(())
    })();

    match result {
        Ok(()) => JNI_TRUE,
        Err(err) => {
            warn!(error = %err, "failed to initialize Android runtime bridge");
            JNI_FALSE
        }
    }
}

/// Holds the Android wake/Wi-Fi locks only while proxied connections are active,
/// so the device may sleep when the proxy is idle. Ends when the runtime drops its stats sender.
#[cfg(target_os = "android")]
async fn drive_traffic_locks(
    app: Option<tauri::AppHandle>,
    mut pool_stats: watch::Receiver<Option<TunnelPoolSnapshot>>,
) {
    // Lock state Kotlin last confirmed; `None` after a failed call, which forces a resend.
    let mut confirmed = Some(false);
    let mut last_busy: Option<std::time::Instant> = None;
    let mut last_sent = std::time::Instant::now();
    while pool_stats.changed().await.is_ok() {
        let now = std::time::Instant::now();
        if pool_stats
            .borrow_and_update()
            .as_ref()
            .is_some_and(|snapshot| snapshot.active > 0)
        {
            last_busy = Some(now);
        }
        // Decided by traffic only; `confirmed` is used just to suppress duplicate calls.
        let want = last_busy.is_some_and(|at| now.duration_since(at) < TRAFFIC_LOCK_RELEASE_DELAY);
        let refresh_due = want && now.duration_since(last_sent) >= TRAFFIC_LOCK_REFRESH_INTERVAL;
        if confirmed == Some(want) && !refresh_due {
            continue;
        }
        confirmed = set_traffic_locks(app.as_ref(), want).await.then_some(want);
        last_sent = now;
    }
    // Runtime is gone (normal stop or abnormal exit): never leave the locks to the timeout.
    if confirmed != Some(false) {
        set_traffic_locks(app.as_ref(), false).await;
    }
}

/// Asks the Android foreground service to hold or release the traffic locks; returns success.
#[cfg(target_os = "android")]
async fn set_traffic_locks(app: Option<&tauri::AppHandle>, active: bool) -> bool {
    let result = if let Some(app) = app {
        let handle = app.state::<ForegroundPluginHandle>().0.clone();
        handle
            .run_mobile_plugin_async::<serde_json::Value>(
                "setTrafficActive",
                serde_json::json!({ "active": active }),
            )
            .await
            .map(|_| ())
            .map_err(|err| err.to_string())
    } else {
        call_android_foreground_static(
            "setTrafficActiveFromRust",
            "(Z)V",
            &[JValue::Bool(active as u8)],
        )
    };

    match result {
        Ok(()) => {
            info!(active, "proxy traffic locks updated");
            true
        }
        Err(err) => {
            warn!(active, error = %err, "failed to update proxy traffic locks");
            false
        }
    }
}

#[cfg(target_os = "android")]
async fn wait_for_foreground_service(
    app: &tauri::AppHandle,
    expected_running: bool,
) -> Result<(), String> {
    let mut last_error = None;
    for _ in 0..30 {
        match query_foreground_service_status(app).await {
            Ok(status) if status.running == expected_running => return Ok(()),
            Ok(_) => {}
            Err(err) => last_error = Some(err),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(last_error.unwrap_or_else(|| {
        format!(
            "Android foreground service did not become {}",
            if expected_running {
                "running"
            } else {
                "stopped"
            }
        )
    }))
}

fn config_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|dir| dir.join(CONFIG_FILE))
        .map_err(|err| format!("无法获取应用配置目录: {err}"))
}

fn ca_certificate_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|dir| dir.join(CERTS_DIR).join(CA_CERT_FILE))
        .map_err(|err| format!("无法获取应用证书目录: {err}"))
}

fn resume_marker_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|dir| dir.join(RESUME_MARKER_FILE))
        .map_err(|err| format!("无法获取应用数据目录: {err}"))
}

fn set_resume_pending(app: &tauri::AppHandle, pending: bool) -> Result<(), String> {
    let path = resume_marker_path(app)?;
    if pending {
        let parent = path
            .parent()
            .ok_or_else(|| "自动恢复标记路径无效".to_string())?;
        fs::create_dir_all(parent).map_err(|err| format!("创建应用数据目录失败: {err}"))?;
        fs::write(&path, b"resume\n").map_err(|err| format!("写入自动恢复标记失败: {err}"))?;
        #[cfg(unix)]
        set_private_permissions(&path, 0o600)?;
    } else if path.is_file() {
        fs::remove_file(&path).map_err(|err| format!("删除自动恢复标记失败: {err}"))?;
    }
    Ok(())
}

fn resume_pending(app: &tauri::AppHandle) -> bool {
    resume_marker_path(app)
        .map(|path| path.is_file())
        .unwrap_or(false)
}

fn validate_ca_certificates(contents: &str) -> Result<usize, String> {
    if contents.is_empty() {
        return Err("证书文件为空".to_string());
    }
    if contents.len() > MAX_CA_CERT_BYTES {
        return Err(format!(
            "证书文件过大，最大支持 {} KiB",
            MAX_CA_CERT_BYTES / 1024
        ));
    }
    if !contents.contains("-----BEGIN CERTIFICATE-----") {
        return Err("当前仅支持 PEM 证书，文件中未找到 BEGIN CERTIFICATE 标记".to_string());
    }

    let mut root_store = RootCertStore::empty();
    let mut certificate_count = 0usize;
    for certificate in CertificateDer::pem_slice_iter(contents.as_bytes()) {
        let certificate = certificate.map_err(|err| format!("CA 证书 PEM 解析失败: {err}"))?;
        root_store
            .add(certificate)
            .map_err(|err| format!("CA 证书不可用: {err}"))?;
        certificate_count += 1;
    }

    if certificate_count == 0 {
        return Err("未在文件中找到可用的 PEM CA 证书".to_string());
    }

    Ok(certificate_count)
}

#[cfg(unix)]
fn set_private_permissions(path: &std::path::Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| format!("设置证书文件权限失败: {err}"))
}

fn local_bind(port: u16) -> String {
    format!("{LOCAL_BIND}:{port}")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn status_from_state(state: &AppState, app: &tauri::AppHandle) -> ClientStatus {
    let (running, socks5_bind, server_addr, started_at, last_error, pool_stats, stored_error) = {
        let guard = state.service.lock().await;
        (
            guard.runtime.is_some(),
            guard.socks5_bind.clone(),
            guard.server_addr.clone(),
            if guard.runtime.is_some() {
                guard.started_at
            } else {
                None
            },
            guard.last_error.clone(),
            guard
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.pool_stats.borrow().clone()),
            guard.foreground_service_error.clone(),
        )
    };
    let (
        foreground_service_running,
        foreground_service_restoring,
        system_restarted,
        battery_optimization_ignored,
        wake_lock_held,
        wifi_lock_held,
        foreground_service_error,
    ) = match query_foreground_service_status(app).await {
        Ok(status) => (
            status.running,
            status.restore_in_progress,
            status.system_restarted,
            status.battery_optimization_ignored,
            status.wake_lock_held,
            status.wifi_lock_held,
            stored_error.or(status.restore_error),
        ),
        Err(err) => (false, false, false, false, false, false, Some(err)),
    };

    ClientStatus {
        running,
        socks5_bind,
        server_addr,
        started_at,
        process_id: std::process::id(),
        last_error,
        pool_stats,
        foreground_service_running,
        foreground_service_restoring,
        foreground_service_error,
        system_restarted,
        battery_optimization_ignored,
        wake_lock_held,
        wifi_lock_held,
        resume_pending: resume_pending(app),
    }
}

async fn take_runtime(state: &AppState, generation: u64) -> Option<ServiceRuntime> {
    let mut guard = state.service.lock().await;
    if guard
        .runtime
        .as_ref()
        .is_some_and(|runtime| runtime.generation == generation)
    {
        guard.runtime.take()
    } else {
        None
    }
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        vpn_enabled: false,
        socks5_local_only: true,
    }
}

#[tauri::command]
async fn import_ca_certificate(
    app: tauri::AppHandle,
    certificate: String,
) -> Result<ImportedCaCertificate, String> {
    let certificate = certificate.trim_start_matches('\u{feff}');
    let certificate_count = validate_ca_certificates(certificate)?;
    let path = ca_certificate_path(&app)?;
    let parent = path
        .parent()
        .ok_or_else(|| "应用证书路径无效".to_string())?;

    fs::create_dir_all(parent).map_err(|err| format!("创建证书目录失败: {err}"))?;
    #[cfg(unix)]
    set_private_permissions(parent, 0o700)?;

    fs::write(&path, certificate.as_bytes()).map_err(|err| format!("写入证书失败: {err}"))?;
    #[cfg(unix)]
    set_private_permissions(&path, 0o600)?;

    Ok(ImportedCaCertificate {
        path: path.to_string_lossy().into_owned(),
        certificate_count,
    })
}

#[tauri::command]
async fn remove_ca_certificate(app: tauri::AppHandle) -> Result<(), String> {
    let path = ca_certificate_path(&app)?;
    if path.is_file() {
        fs::remove_file(&path).map_err(|err| format!("删除证书失败: {err}"))?;
    }
    Ok(())
}

#[tauri::command]
async fn load_config(app: tauri::AppHandle) -> Result<ClientSettings, String> {
    let path = config_path(&app)?;
    if !path.is_file() {
        return Ok(ClientSettings::default());
    }

    let config = ClientConfigFile::from_path(&path).map_err(|err| err.to_string())?;
    Ok(ClientSettings::from_config(&config))
}

#[tauri::command]
async fn save_config(app: tauri::AppHandle, settings: ClientSettings) -> Result<(), String> {
    let path = config_path(&app)?;
    let parent = path
        .parent()
        .ok_or_else(|| "应用配置路径无效".to_string())?;
    fs::create_dir_all(parent).map_err(|err| format!("创建配置目录失败: {err}"))?;

    let config = settings.into_config();
    let content =
        toml::to_string_pretty(&config).map_err(|err| format!("序列化配置失败: {err}"))?;
    fs::write(&path, content.as_bytes()).map_err(|err| format!("写入配置失败: {err}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

#[tauri::command]
async fn validate_config(settings: ClientSettings) -> Result<(), String> {
    settings
        .into_config()
        .validate()
        .map_err(|err| err.to_string())
}

async fn start_runtime(
    service: Arc<Mutex<ServiceState>>,
    config: ClientConfigFile,
    app: Option<tauri::AppHandle>,
) -> Result<String, String> {
    let bind = local_bind(config.socks5.port);
    let server_addr = config.client.server_addr.clone();

    if let Err(err) = config.validate() {
        let message = err.to_string();
        let mut guard = service.lock().await;
        guard.socks5_bind = bind;
        guard.server_addr = server_addr;
        guard.started_at = None;
        guard.last_error = Some(message.clone());
        return Err(message);
    }

    // Keep this lock while waiting for the listener. A concurrent JNI restore and
    // Tauri start therefore observe a single process-wide runtime instead of racing
    // to bind the same SOCKS5 port twice.
    let mut guard = service.lock().await;
    if guard.runtime.is_some() {
        return Ok(guard.socks5_bind.clone());
    }

    let generation = next_generation();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();
    let (pool_stats_tx, pool_stats_rx) = watch::channel::<Option<TunnelPoolSnapshot>>(None);
    let task_service = service.clone();
    let task_app = app.clone();

    #[cfg(target_os = "android")]
    tauri::async_runtime::spawn(drive_traffic_locks(app.clone(), pool_stats_rx.clone()));

    let task = tauri::async_runtime::spawn(async move {
        let result = proxy_core::client_runtime::run_with_shutdown_ready_and_pool_stats(
            config,
            shutdown_rx,
            Some(ready_tx),
            Some(pool_stats_tx),
        )
        .await;

        let foreground_stop_error = if let Some(app) = task_app.as_ref() {
            stop_foreground_service(app).await.err()
        } else {
            #[cfg(target_os = "android")]
            notify_android_runtime_stopped();
            None
        };
        let mut guard = task_service.lock().await;
        if guard
            .runtime
            .as_ref()
            .is_some_and(|runtime| runtime.generation == generation)
        {
            guard.runtime = None;
            guard.started_at = None;
            guard.foreground_service_running = false;
            guard.foreground_service_error = foreground_stop_error;
            if let Err(err) = result {
                guard.last_error = Some(err.to_string());
            }
        }
    });

    guard.runtime = Some(ServiceRuntime {
        generation,
        shutdown: shutdown_tx,
        pool_stats: pool_stats_rx,
        task,
    });
    guard.socks5_bind = bind;
    guard.server_addr = server_addr;
    guard.started_at = None;
    guard.last_error = None;

    let ready_result = tokio::time::timeout(START_TIMEOUT, ready_rx).await;
    let start_error = match ready_result {
        Ok(Ok(Ok(_bound_addr))) => None,
        Ok(Ok(Err(err))) => Some(err),
        Ok(Err(err)) => Some(format!("启动任务提前结束: {err}")),
        Err(_) => Some(format!(
            "启动本地 SOCKS5 端口超时（{} 秒）",
            START_TIMEOUT.as_secs()
        )),
    };

    if let Some(err) = start_error {
        let runtime = guard.runtime.take();
        drop(guard);
        if let Some(runtime) = runtime {
            let _ = runtime.shutdown.send(true);
            let _ = tokio::time::timeout(STOP_TIMEOUT, runtime.task).await;
        }
        let mut guard = service.lock().await;
        guard.started_at = None;
        guard.last_error = Some(err.clone());
        return Err(err);
    }

    guard.started_at = Some(unix_now());
    Ok(guard.socks5_bind.clone())
}

#[tauri::command]
async fn start_client(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    settings: ClientSettings,
) -> Result<ClientStatus, String> {
    let config = settings.into_config();
    start_runtime(state.service.clone(), config, Some(app.clone())).await?;

    let foreground_error = start_foreground_service(&app).await.err();
    if let Some(error) = foreground_error.as_deref() {
        warn!(
            error,
            "foreground service unavailable; proxy remains running"
        );
    }
    {
        let mut guard = state.service.lock().await;
        guard.foreground_service_running =
            cfg!(target_os = "android") && foreground_error.is_none();
        guard.foreground_service_error = foreground_error;
    }

    let status = status_from_state(&state, &app).await;
    if status.running {
        match set_resume_pending(&app, true) {
            Ok(()) => info!(
                marker = %RESUME_MARKER_FILE,
                "automatic resume intent recorded"
            ),
            Err(err) => warn!(error = %err, "failed to record automatic resume intent"),
        }
        Ok(status)
    } else {
        Err(status
            .last_error
            .unwrap_or_else(|| "本地 SOCKS5 服务启动后立即退出".to_string()))
    }
}

#[tauri::command]
async fn stop_client(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<ClientStatus, String> {
    let generation = {
        let guard = state.service.lock().await;
        guard.runtime.as_ref().map(|runtime| runtime.generation)
    };

    let mut stop_error = None;
    if let Some(generation) = generation {
        if let Some(runtime) = take_runtime(&state, generation).await {
            let _ = runtime.shutdown.send(true);
            stop_error = match tokio::time::timeout(STOP_TIMEOUT, runtime.task).await {
                Ok(Ok(())) => None,
                Ok(Err(err)) => Some(format!("停止任务失败: {err}")),
                Err(_) => Some(format!(
                    "停止本地 SOCKS5 超时（{} 秒）",
                    STOP_TIMEOUT.as_secs()
                )),
            };
        }
    }

    let foreground_error = stop_foreground_service(&app).await.err();
    match set_resume_pending(&app, false) {
        Ok(()) => info!("automatic resume intent cleared"),
        Err(err) => warn!(error = %err, "failed to clear automatic resume intent"),
    }
    {
        let mut guard = state.service.lock().await;
        guard.started_at = None;
        guard.foreground_service_running = false;
        guard.foreground_service_error = foreground_error;
        if let Some(err) = stop_error {
            guard.last_error = Some(err);
        }
    }

    Ok(status_from_state(&state, &app).await)
}

#[tauri::command]
async fn client_status(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<ClientStatus, String> {
    Ok(status_from_state(&state, &app).await)
}

#[tauri::command]
async fn request_battery_optimization_exemption(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let handle = app.state::<ForegroundPluginHandle>().0.clone();
        handle
            .run_mobile_plugin_async::<serde_json::Value>(
                "requestBatteryOptimizationExemption",
                serde_json::json!({}),
            )
            .await
            .map_err(|err| format!("failed to open battery optimization settings: {err}"))?;
        info!("requested Android battery optimization exemption");
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        Err("仅 Android 支持忽略电池优化设置".to_string())
    }
}

#[tauri::command]
fn get_recent_logs() -> Vec<LogRecord> {
    let records = log_buffer()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    records.iter().cloned().collect()
}

#[tauri::command]
fn clear_logs() -> Result<(), String> {
    log_buffer()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();

    let path = log_file_path()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    if let Some(path) = path {
        let _io_guard = LOG_FILE_IO_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|err| format!("清空日志文件失败: {err}"))?;
        let rotated = path.with_extension("log.1");
        if rotated.is_file() {
            fs::remove_file(rotated).map_err(|err| format!("删除轮转日志失败: {err}"))?;
        }
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    init_tracing();
    tauri::Builder::default()
        .plugin(proxy_foreground_plugin())
        .manage(AppState::default())
        .setup(|app| {
            match app.path().app_data_dir() {
                Ok(data_dir) => {
                    let log_path = data_dir.join(LOG_FILE);
                    match initialize_log_file(log_path.clone()) {
                        Ok(()) => info!(
                            pid = std::process::id(),
                            version = env!("CARGO_PKG_VERSION"),
                            log_file = %log_path.display(),
                            "Rama Proxy mobile application started"
                        ),
                        Err(err) => {
                            eprintln!(
                                "failed to initialize log file {}: {err}",
                                log_path.display()
                            );
                        }
                    }
                }
                Err(err) => {
                    eprintln!("failed to resolve app data directory for logs: {err}");
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            import_ca_certificate,
            remove_ca_certificate,
            load_config,
            save_config,
            validate_config,
            start_client,
            stop_client,
            client_status,
            request_battery_optimization_exemption,
            get_recent_logs,
            clear_logs
        ])
        .run(tauri::generate_context!())
        .expect("error while running rama proxy mobile");
}
