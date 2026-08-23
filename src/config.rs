use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigFile {
    #[serde(default)]
    pub server: TunnelServerConfig,
    #[serde(default)]
    pub auth: TunnelAuthConfig,
    #[serde(default)]
    pub tls: ServerTlsConfig,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_server_port")]
    pub port: u16,
    #[serde(default = "default_outbound_ip_mode")]
    pub outbound_ip_mode: String,
    #[serde(default)]
    pub workers: usize,
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_max_handshakes")]
    pub max_handshakes: usize,
    #[serde(default = "default_server_udp_idle_timeout_secs")]
    pub udp_idle_timeout_secs: u64,
    #[serde(default = "default_tcp_keepalive_secs")]
    pub tcp_keepalive_secs: u64,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelAuthConfig {
    #[serde(default = "default_shared_secret")]
    pub shared_secret: String,
    #[serde(default)]
    pub require_client_id: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfigFile {
    #[serde(default)]
    pub client: TunnelClientConfig,
    #[serde(default)]
    pub socks5: LocalSocks5Config,
    #[serde(default)]
    pub http_connect: LocalHttpConnectConfig,
    #[serde(default)]
    pub udp: LocalUdpConfig,
    #[serde(default)]
    pub auth: LocalAuthConfig,
    #[serde(default)]
    pub tls: ClientTlsConfig,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: String,
    #[serde(default)]
    pub key_path: String,
    #[serde(default)]
    pub require_client_auth: bool,
    #[serde(default)]
    pub client_ca_cert_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub ca_cert_path: String,
    #[serde(default)]
    pub insecure_skip_verify: bool,
    #[serde(default)]
    pub client_cert_path: String,
    #[serde(default)]
    pub client_key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelClientConfig {
    #[serde(default = "default_server_addr")]
    pub server_addr: String,
    #[serde(default = "default_shared_secret")]
    pub shared_secret: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSocks5Config {
    #[serde(default = "default_local_bind")]
    pub bind: String,
    #[serde(default = "default_socks5_port")]
    pub port: u16,
    #[serde(default = "default_tcp_keepalive_secs")]
    pub tcp_keepalive_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalHttpConnectConfig {
    #[serde(default = "default_local_bind")]
    pub bind: String,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalUdpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAuthConfig {
    #[serde(default = "default_auth_mode")]
    pub mode: String,
    #[serde(default)]
    pub users: Vec<UserConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for ServerConfigFile {
    fn default() -> Self {
        Self {
            server: TunnelServerConfig::default(),
            auth: TunnelAuthConfig::default(),
            tls: ServerTlsConfig::default(),
            log: LogConfig::default(),
        }
    }
}

impl Default for TunnelServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_server_port(),
            outbound_ip_mode: default_outbound_ip_mode(),
            workers: 0,
            handshake_timeout_secs: default_handshake_timeout_secs(),
            max_handshakes: default_max_handshakes(),
            udp_idle_timeout_secs: default_server_udp_idle_timeout_secs(),
            tcp_keepalive_secs: default_tcp_keepalive_secs(),
            heartbeat_interval_secs: default_heartbeat_interval_secs(),
            heartbeat_timeout_secs: default_heartbeat_timeout_secs(),
        }
    }
}

impl Default for TunnelAuthConfig {
    fn default() -> Self {
        Self {
            shared_secret: default_shared_secret(),
            require_client_id: false,
        }
    }
}

impl Default for ClientConfigFile {
    fn default() -> Self {
        Self {
            client: TunnelClientConfig::default(),
            socks5: LocalSocks5Config::default(),
            http_connect: LocalHttpConnectConfig::default(),
            udp: LocalUdpConfig::default(),
            auth: LocalAuthConfig::default(),
            tls: ClientTlsConfig::default(),
            log: LogConfig::default(),
        }
    }
}

impl Default for ServerTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: String::new(),
            key_path: String::new(),
            require_client_auth: false,
            client_ca_cert_path: String::new(),
        }
    }
}

impl Default for ClientTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_name: String::new(),
            ca_cert_path: String::new(),
            insecure_skip_verify: false,
            client_cert_path: String::new(),
            client_key_path: String::new(),
        }
    }
}

impl Default for TunnelClientConfig {
    fn default() -> Self {
        Self {
            server_addr: default_server_addr(),
            shared_secret: default_shared_secret(),
            client_id: String::new(),
            pool_size: default_pool_size(),
            connect_timeout_secs: default_connect_timeout_secs(),
            heartbeat_interval_secs: default_heartbeat_interval_secs(),
            heartbeat_timeout_secs: default_heartbeat_timeout_secs(),
        }
    }
}

impl Default for LocalSocks5Config {
    fn default() -> Self {
        Self {
            bind: default_local_bind(),
            port: default_socks5_port(),
            tcp_keepalive_secs: default_tcp_keepalive_secs(),
        }
    }
}

impl Default for LocalHttpConnectConfig {
    fn default() -> Self {
        Self {
            bind: default_local_bind(),
            port: None,
        }
    }
}

impl Default for LocalUdpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            idle_timeout_secs: default_idle_timeout(),
        }
    }
}

impl Default for LocalAuthConfig {
    fn default() -> Self {
        Self {
            mode: default_auth_mode(),
            users: Vec::new(),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

impl ServerConfigFile {
    pub fn from_path(path: &Path) -> Result<Self, AppError> {
        let content = fs::read_to_string(path)?;
        let mut config = toml::from_str::<Self>(&content)?;
        config.resolve_relative_paths(path);
        Ok(config)
    }

    pub fn write_default_to_path(path: &Path, force: bool) -> Result<(), AppError> {
        write_default_template(path, force, default_server_template())
    }

    pub fn validate(&self) -> Result<(), AppError> {
        validate_ip_bind(&self.server.bind, "server.bind")?;
        validate_outbound_ip_mode(&self.server.outbound_ip_mode)?;
        if self.server.max_handshakes == 0 {
            return Err(AppError::InvalidConfig(
                "server.max_handshakes must be greater than 0".to_string(),
            ));
        }
        if self.auth.shared_secret.trim().is_empty() {
            return Err(AppError::InvalidConfig(
                "auth.shared_secret must not be empty".to_string(),
            ));
        }
        validate_server_tls_config(&self.tls)?;
        Ok(())
    }

    fn resolve_relative_paths(&mut self, path: &Path) {
        let Some(base_dir) = path.parent() else {
            return;
        };
        resolve_file_path_in_place(&mut self.tls.cert_path, base_dir);
        resolve_file_path_in_place(&mut self.tls.key_path, base_dir);
        resolve_file_path_in_place(&mut self.tls.client_ca_cert_path, base_dir);
    }
}

impl ClientConfigFile {
    pub fn from_path(path: &Path) -> Result<Self, AppError> {
        let content = fs::read_to_string(path)?;
        let mut config = toml::from_str::<Self>(&content)?;
        config.resolve_relative_paths(path);
        Ok(config)
    }

    pub fn write_default_to_path(path: &Path, force: bool) -> Result<(), AppError> {
        write_default_template(path, force, default_client_template())
    }

    pub fn validate(&self) -> Result<(), AppError> {
        validate_ip_bind(&self.socks5.bind, "socks5.bind")?;
        validate_http_connect_config(&self.http_connect, &self.socks5)?;
        self.client.server_addr.parse::<SocketAddr>().map_err(|_| {
            AppError::InvalidConfig("client.server_addr must be host:port".to_string())
        })?;
        if self.client.shared_secret.trim().is_empty() {
            return Err(AppError::InvalidConfig(
                "client.shared_secret must not be empty".to_string(),
            ));
        }
        if self.client.client_id.contains('\n') || self.client.client_id.contains('\r') {
            return Err(AppError::InvalidConfig(
                "client.client_id must be a single-line string".to_string(),
            ));
        }
        if self.client.pool_size == 0 {
            return Err(AppError::InvalidConfig(
                "client.pool_size must be greater than 0".to_string(),
            ));
        }
        if self.auth.mode != "none" && self.auth.mode != "password" {
            return Err(AppError::InvalidConfig(
                "auth.mode must be either 'none' or 'password'".to_string(),
            ));
        }
        if self.auth.mode == "password" && self.auth.users.is_empty() {
            return Err(AppError::InvalidConfig(
                "auth.users must not be empty when auth.mode is 'password'".to_string(),
            ));
        }
        validate_client_tls_config(&self.tls)?;
        Ok(())
    }

    fn resolve_relative_paths(&mut self, path: &Path) {
        let Some(base_dir) = path.parent() else {
            return;
        };
        resolve_file_path_in_place(&mut self.tls.ca_cert_path, base_dir);
        resolve_file_path_in_place(&mut self.tls.client_cert_path, base_dir);
        resolve_file_path_in_place(&mut self.tls.client_key_path, base_dir);
    }
}

fn validate_ip_bind(value: &str, field: &str) -> Result<(), AppError> {
    IpAddr::from_str(value).map_err(|_| {
        AppError::InvalidConfig(format!("{field} must be a valid IPv4 or IPv6 address"))
    })?;
    Ok(())
}

fn validate_outbound_ip_mode(mode: &str) -> Result<(), AppError> {
    match mode {
        "dual" | "ipv4" | "ipv6" | "dual-prefer-ipv4" => Ok(()),
        _ => Err(AppError::InvalidConfig(
            "server.outbound_ip_mode must be one of 'dual', 'ipv4', 'ipv6', 'dual-prefer-ipv4'"
                .to_string(),
        )),
    }
}

fn validate_server_tls_config(tls: &ServerTlsConfig) -> Result<(), AppError> {
    if !tls.enabled {
        return Ok(());
    }

    require_non_empty_file(&tls.cert_path, "tls.cert_path")?;
    require_non_empty_file(&tls.key_path, "tls.key_path")?;

    if tls.require_client_auth {
        require_non_empty_file(&tls.client_ca_cert_path, "tls.client_ca_cert_path")?;
    } else if !tls.client_ca_cert_path.trim().is_empty() {
        require_existing_file(&tls.client_ca_cert_path, "tls.client_ca_cert_path")?;
    }

    Ok(())
}

fn validate_client_tls_config(tls: &ClientTlsConfig) -> Result<(), AppError> {
    if !tls.enabled {
        return Ok(());
    }

    if tls.server_name.trim().is_empty() {
        return Err(AppError::InvalidConfig(
            "tls.server_name must not be empty when tls.enabled is true".to_string(),
        ));
    }

    if tls.insecure_skip_verify {
        return Err(AppError::InvalidConfig(
            "tls.insecure_skip_verify is reserved and not supported yet".to_string(),
        ));
    }
    require_non_empty_file(&tls.ca_cert_path, "tls.ca_cert_path")?;

    let has_client_cert = !tls.client_cert_path.trim().is_empty();
    let has_client_key = !tls.client_key_path.trim().is_empty();
    match (has_client_cert, has_client_key) {
        (true, true) => {
            require_existing_file(&tls.client_cert_path, "tls.client_cert_path")?;
            require_existing_file(&tls.client_key_path, "tls.client_key_path")?;
        }
        (false, false) => {}
        _ => {
            return Err(AppError::InvalidConfig(
                "tls.client_cert_path and tls.client_key_path must be configured together"
                    .to_string(),
            ));
        }
    }

    Ok(())
}

fn require_non_empty_file(value: &str, field: &str) -> Result<(), AppError> {
    if value.trim().is_empty() {
        return Err(AppError::InvalidConfig(format!(
            "{field} must not be empty when tls is enabled"
        )));
    }
    require_existing_file(value, field)
}

fn require_existing_file(value: &str, field: &str) -> Result<(), AppError> {
    let path = Path::new(value);
    if !path.is_file() {
        return Err(AppError::InvalidConfig(format!(
            "{field} must point to an existing file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn resolve_file_path_in_place(value: &mut String, base_dir: &Path) {
    let raw = value.trim();
    if raw.is_empty() {
        return;
    }

    let path = Path::new(raw);
    if path.is_absolute() {
        return;
    }

    let config_relative = base_dir.join(path);
    if config_relative.is_file() {
        *value = config_relative.to_string_lossy().into_owned();
        return;
    }

    if let Some(runtime_root) = base_dir.parent() {
        let root_relative = runtime_root.join(path);
        if root_relative.is_file() {
            *value = root_relative.to_string_lossy().into_owned();
            return;
        }
    }

    *value = config_relative.to_string_lossy().into_owned();
}

fn write_default_template(path: &Path, force: bool, content: String) -> Result<(), AppError> {
    if path.exists() && !force {
        return Err(AppError::ConfigAlreadyExists(path.display().to_string()));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    Ok(())
}

fn default_bind() -> String {
    "0.0.0.0".to_string()
}

fn default_local_bind() -> String {
    "127.0.0.1".to_string()
}

fn default_server_port() -> u16 {
    19090
}

fn default_socks5_port() -> u16 {
    1080
}

fn default_tcp_keepalive_secs() -> u64 {
    60
}

fn default_heartbeat_interval_secs() -> u64 {
    30
}

fn default_heartbeat_timeout_secs() -> u64 {
    10
}

fn default_server_addr() -> String {
    format!("127.0.0.1:{}", default_server_port())
}

fn default_outbound_ip_mode() -> String {
    "ipv4".to_string()
}

fn default_shared_secret() -> String {
    "change-me".to_string()
}

fn default_pool_size() -> usize {
    8
}

fn default_connect_timeout_secs() -> u64 {
    10
}

fn default_handshake_timeout_secs() -> u64 {
    10
}

fn default_max_handshakes() -> usize {
    1024
}

fn default_server_udp_idle_timeout_secs() -> u64 {
    300
}

fn default_idle_timeout() -> u64 {
    60
}

fn default_auth_mode() -> String {
    "none".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

fn default_server_template() -> String {
    r#"# Remote tunnel server config for rama-proxy.

[server]
bind = "0.0.0.0"
port = 19090
outbound_ip_mode = "ipv4"
workers = 0
handshake_timeout_secs = 10
max_handshakes = 1024
udp_idle_timeout_secs = 300
tcp_keepalive_secs = 60
heartbeat_interval_secs = 30
heartbeat_timeout_secs = 10

[auth]
shared_secret = "change-me"
require_client_id = false

[tls]
enabled = false
cert_path = ""
key_path = ""
require_client_auth = false
client_ca_cert_path = ""

[log]
level = "info"
format = "text"
"#
    .to_string()
}

fn default_client_template() -> String {
    r#"# Local Clash-facing client config for rama-proxy.

[client]
server_addr = "127.0.0.1:19090"
shared_secret = "change-me"
client_id = ""
pool_size = 8
connect_timeout_secs = 10
heartbeat_interval_secs = 30
heartbeat_timeout_secs = 10

[socks5]
bind = "127.0.0.1"
port = 1080
tcp_keepalive_secs = 60

[http_connect]
bind = "127.0.0.1"
# port = 18080

[udp]
enabled = true
idle_timeout_secs = 60

[auth]
mode = "none"
users = []

[tls]
enabled = false
server_name = ""
ca_cert_path = ""
insecure_skip_verify = false
client_cert_path = ""
client_key_path = ""

[log]
level = "info"
format = "text"
"#
    .to_string()
}

fn validate_http_connect_config(
    http_connect: &LocalHttpConnectConfig,
    socks5: &LocalSocks5Config,
) -> Result<(), AppError> {
    let Some(http_port) = http_connect.port else {
        return Ok(());
    };

    validate_ip_bind(&http_connect.bind, "http_connect.bind")?;
    if http_port == 0 {
        return Err(AppError::InvalidConfig(
            "http_connect.port must be greater than 0 when configured".to_string(),
        ));
    }

    let http_bind = SocketAddr::new(IpAddr::from_str(&http_connect.bind).unwrap(), http_port);
    let socks_bind = SocketAddr::new(IpAddr::from_str(&socks5.bind).unwrap(), socks5.port);
    if http_bind == socks_bind {
        return Err(AppError::InvalidConfig(
            "http_connect listener must not reuse the same bind address and port as socks5"
                .to_string(),
        ));
    }

    Ok(())
}
