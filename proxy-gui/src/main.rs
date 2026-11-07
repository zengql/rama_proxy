#![cfg_attr(windows, windows_subsystem = "windows")]

use std::{
    collections::VecDeque,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError},
    time::Duration,
};

#[cfg(windows)]
use std::os::windows::process::CommandExt as _;

use gpui_kit::component::{
    IconName, Root, Selectable as _, StyledExt as _,
    button::{Button, ButtonVariants as _},
    checkbox::Checkbox,
    h_flex,
    input::{Input, InputState},
    scroll::ScrollableElement as _,
    v_flex,
};
use gpui_kit::{
    App, AppContext as _, Bounds, Context, Entity, InteractiveElement as _, IntoElement,
    ParentElement as _, Render, ScrollHandle, SharedString, StatefulInteractiveElement as _,
    Styled as _, Window, WindowBounds, WindowOptions, div, prelude::FluentBuilder as _, px, rgb,
    size,
};
use proxy_core::config::{
    ClientConfigFile, ClientTlsConfig, LocalAuthConfig, LocalHttpConnectConfig, LocalSocks5Config,
    LocalUdpConfig, LogConfig, TunnelClientConfig,
};
use serde::{Deserialize, Serialize};
use tray_item::{IconSource, TrayItem};

#[cfg(windows)]
use raw_window_handle::{HasWindowHandle as _, RawWindowHandle};
#[cfg(windows)]
use windows_sys::Win32::{
    System::Threading::GetCurrentProcessId,
    UI::WindowsAndMessaging::{
        FindWindowExW, GetWindowThreadProcessId, IsWindowVisible, SW_HIDE, SW_RESTORE,
        ShowWindowAsync,
    },
};

const APP_NAME: &str = "Rama Proxy Client";
const ACCENT_DARK: u32 = 0x0d7046;
const CONSOLE_CHANNEL_CAPACITY: usize = 512;
const CONSOLE_MAX_BYTES: usize = 512 * 1024;
const CONSOLE_MAX_LINE_BYTES: usize = 8 * 1024;
const TRAY_MONITOR_INTERVAL: Duration = Duration::from_secs(60);
const TRAY_ERROR_PREFIX: &str = "Tray icon unavailable";
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum CloseAction {
    Ask,
    Exit,
    MinimizeToTray,
}

impl Default for CloseAction {
    fn default() -> Self {
        Self::Ask
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuiSettings {
    #[serde(default)]
    close_action: CloseAction,
    #[serde(default = "default_remember_config")]
    remember_config: bool,
    #[serde(default = "default_console_max_lines")]
    console_max_lines: usize,
}

impl Default for GuiSettings {
    fn default() -> Self {
        Self {
            close_action: CloseAction::Ask,
            remember_config: true,
            console_max_lines: default_console_max_lines(),
        }
    }
}

fn default_remember_config() -> bool {
    true
}

fn default_console_max_lines() -> usize {
    1000
}

#[derive(Debug, Clone)]
struct ClientForm {
    server_addr: String,
    shared_secret: String,
    client_id: String,
    pool_size: String,
    connect_timeout_secs: String,
    heartbeat_interval_secs: String,
    heartbeat_timeout_secs: String,
    socks_bind: String,
    socks_port: String,
    socks_keepalive_secs: String,
    http_enabled: bool,
    http_bind: String,
    http_port: String,
    udp_enabled: bool,
    udp_idle_timeout_secs: String,
    auth_mode: String,
    auth_username: String,
    auth_password: String,
    tls_enabled: bool,
    tls_server_name: String,
    tls_ca_cert_path: String,
    tls_client_cert_path: String,
    tls_client_key_path: String,
    log_level: String,
    log_format: String,
}

impl Default for ClientForm {
    fn default() -> Self {
        Self::from_config(ClientConfigFile::default())
    }
}

impl ClientForm {
    fn from_config(config: ClientConfigFile) -> Self {
        let user = config.auth.users.first();
        Self {
            server_addr: config.client.server_addr,
            shared_secret: config.client.shared_secret,
            client_id: config.client.client_id,
            pool_size: config.client.pool_size.to_string(),
            connect_timeout_secs: config.client.connect_timeout_secs.to_string(),
            heartbeat_interval_secs: config.client.heartbeat_interval_secs.to_string(),
            heartbeat_timeout_secs: config.client.heartbeat_timeout_secs.to_string(),
            socks_bind: config.socks5.bind,
            socks_port: config.socks5.port.to_string(),
            socks_keepalive_secs: config.socks5.tcp_keepalive_secs.to_string(),
            http_enabled: config.http_connect.port.is_some(),
            http_bind: config.http_connect.bind,
            http_port: config.http_connect.port.unwrap_or(18080).to_string(),
            udp_enabled: config.udp.enabled,
            udp_idle_timeout_secs: config.udp.idle_timeout_secs.to_string(),
            auth_mode: config.auth.mode,
            auth_username: user.map(|user| user.username.clone()).unwrap_or_default(),
            auth_password: user.map(|user| user.password.clone()).unwrap_or_default(),
            tls_enabled: config.tls.enabled,
            tls_server_name: config.tls.server_name,
            tls_ca_cert_path: config.tls.ca_cert_path,
            tls_client_cert_path: config.tls.client_cert_path,
            tls_client_key_path: config.tls.client_key_path,
            log_level: config.log.level,
            log_format: config.log.format,
        }
    }

    fn to_config(&self) -> Result<ClientConfigFile, String> {
        let parse = |value: &str, name: &str| {
            value
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("{name} must be a positive number"))
        };
        let parse_port = |value: &str, name: &str| {
            value
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("{name} must be a valid port"))
        };
        let users = if self.auth_mode == "password" {
            vec![proxy_core::config::UserConfig {
                username: self.auth_username.clone(),
                password: self.auth_password.clone(),
            }]
        } else {
            Vec::new()
        };
        let config = ClientConfigFile {
            client: TunnelClientConfig {
                server_addr: self.server_addr.trim().to_string(),
                shared_secret: self.shared_secret.clone(),
                client_id: self.client_id.trim().to_string(),
                pool_size: parse(&self.pool_size, "pool size")? as usize,
                connect_timeout_secs: parse(&self.connect_timeout_secs, "connect timeout")?,
                heartbeat_interval_secs: parse(
                    &self.heartbeat_interval_secs,
                    "heartbeat interval",
                )?,
                heartbeat_timeout_secs: parse(&self.heartbeat_timeout_secs, "heartbeat timeout")?,
            },
            socks5: LocalSocks5Config {
                bind: self.socks_bind.trim().to_string(),
                port: parse_port(&self.socks_port, "SOCKS5 port")?,
                tcp_keepalive_secs: parse(&self.socks_keepalive_secs, "TCP keepalive")?,
            },
            http_connect: LocalHttpConnectConfig {
                bind: self.http_bind.trim().to_string(),
                port: self
                    .http_enabled
                    .then(|| parse_port(&self.http_port, "HTTP port"))
                    .transpose()?,
            },
            udp: LocalUdpConfig {
                enabled: self.udp_enabled,
                idle_timeout_secs: parse(&self.udp_idle_timeout_secs, "UDP idle timeout")?,
            },
            auth: LocalAuthConfig {
                mode: self.auth_mode.clone(),
                users,
            },
            tls: ClientTlsConfig {
                enabled: self.tls_enabled,
                server_name: self.tls_server_name.clone(),
                ca_cert_path: self.tls_ca_cert_path.clone(),
                insecure_skip_verify: false,
                client_cert_path: self.tls_client_cert_path.clone(),
                client_key_path: self.tls_client_key_path.clone(),
            },
            log: LogConfig {
                level: self.log_level.clone(),
                format: self.log_format.clone(),
            },
        };
        config.validate().map_err(|error| error.to_string())?;
        Ok(config)
    }
}

struct FormInputs {
    server_addr: Entity<InputState>,
    shared_secret: Entity<InputState>,
    client_id: Entity<InputState>,
    pool_size: Entity<InputState>,
    connect_timeout_secs: Entity<InputState>,
    heartbeat_interval_secs: Entity<InputState>,
    heartbeat_timeout_secs: Entity<InputState>,
    socks_bind: Entity<InputState>,
    socks_port: Entity<InputState>,
    socks_keepalive_secs: Entity<InputState>,
    http_bind: Entity<InputState>,
    http_port: Entity<InputState>,
    udp_idle_timeout_secs: Entity<InputState>,
    auth_username: Entity<InputState>,
    auth_password: Entity<InputState>,
    tls_server_name: Entity<InputState>,
    tls_ca_cert_path: Entity<InputState>,
    tls_client_cert_path: Entity<InputState>,
    tls_client_key_path: Entity<InputState>,
    log_level: Entity<InputState>,
    log_format: Entity<InputState>,
}

impl FormInputs {
    fn new(form: &ClientForm, window: &mut Window, cx: &mut Context<'_, ClientView>) -> Self {
        let mut input = |value: &str, masked: bool, cx: &mut Context<'_, ClientView>| {
            cx.new(|cx| {
                InputState::new(window, cx)
                    .default_value(value.to_string())
                    .masked(masked)
            })
        };
        Self {
            server_addr: input(&form.server_addr, false, cx),
            shared_secret: input(&form.shared_secret, true, cx),
            client_id: input(&form.client_id, false, cx),
            pool_size: input(&form.pool_size, false, cx),
            connect_timeout_secs: input(&form.connect_timeout_secs, false, cx),
            heartbeat_interval_secs: input(&form.heartbeat_interval_secs, false, cx),
            heartbeat_timeout_secs: input(&form.heartbeat_timeout_secs, false, cx),
            socks_bind: input(&form.socks_bind, false, cx),
            socks_port: input(&form.socks_port, false, cx),
            socks_keepalive_secs: input(&form.socks_keepalive_secs, false, cx),
            http_bind: input(&form.http_bind, false, cx),
            http_port: input(&form.http_port, false, cx),
            udp_idle_timeout_secs: input(&form.udp_idle_timeout_secs, false, cx),
            auth_username: input(&form.auth_username, false, cx),
            auth_password: input(&form.auth_password, true, cx),
            tls_server_name: input(&form.tls_server_name, false, cx),
            tls_ca_cert_path: input(&form.tls_ca_cert_path, false, cx),
            tls_client_cert_path: input(&form.tls_client_cert_path, false, cx),
            tls_client_key_path: input(&form.tls_client_key_path, false, cx),
            log_level: input(&form.log_level, false, cx),
            log_format: input(&form.log_format, false, cx),
        }
    }

    fn form(&self, state: &ClientView, cx: &App) -> ClientForm {
        let value = |input: &Entity<InputState>| input.read(cx).value().to_string();
        ClientForm {
            server_addr: value(&self.server_addr),
            shared_secret: value(&self.shared_secret),
            client_id: value(&self.client_id),
            pool_size: value(&self.pool_size),
            connect_timeout_secs: value(&self.connect_timeout_secs),
            heartbeat_interval_secs: value(&self.heartbeat_interval_secs),
            heartbeat_timeout_secs: value(&self.heartbeat_timeout_secs),
            socks_bind: value(&self.socks_bind),
            socks_port: value(&self.socks_port),
            socks_keepalive_secs: value(&self.socks_keepalive_secs),
            http_enabled: state.http_enabled,
            http_bind: value(&self.http_bind),
            http_port: value(&self.http_port),
            udp_enabled: state.udp_enabled,
            udp_idle_timeout_secs: value(&self.udp_idle_timeout_secs),
            auth_mode: state.auth_mode.clone(),
            auth_username: value(&self.auth_username),
            auth_password: value(&self.auth_password),
            tls_enabled: state.tls_enabled,
            tls_server_name: value(&self.tls_server_name),
            tls_ca_cert_path: value(&self.tls_ca_cert_path),
            tls_client_cert_path: value(&self.tls_client_cert_path),
            tls_client_key_path: value(&self.tls_client_key_path),
            log_level: value(&self.log_level),
            log_format: value(&self.log_format),
        }
    }
}

enum TrayCommand {
    Show,
    Quit,
}

struct ClientView {
    inputs: FormInputs,
    config_path: PathBuf,
    settings_path: PathBuf,
    settings: GuiSettings,
    console_sender: SyncSender<String>,
    console_lines: VecDeque<String>,
    console_bytes: usize,
    console_scroll_handle: ScrollHandle,
    follow_console: bool,
    process: Option<Child>,
    status: String,
    error: Option<String>,
    http_enabled: bool,
    udp_enabled: bool,
    tls_enabled: bool,
    auth_mode: String,
    remember_close_action: bool,
    show_close_confirmation: bool,
    show_settings: bool,
    exiting: bool,
    _tray: Option<TrayItem>,
}

impl ClientView {
    fn new(
        window: &mut Window,
        cx: &mut Context<'_, Self>,
        tray: Option<TrayItem>,
        console_sender: SyncSender<String>,
    ) -> Self {
        let config_path = default_client_config_path();
        let settings_path = app_data_dir().join("gui.toml");
        let mut settings: GuiSettings = read_toml(&settings_path).unwrap_or_default();
        if !matches!(settings.console_max_lines, 500 | 1000 | 5000) {
            settings.console_max_lines = default_console_max_lines();
        }
        let persisted = read_toml::<ClientConfigFile>(&config_path)
            .map(ClientForm::from_config)
            .unwrap_or_default();
        let form = if settings.remember_config {
            persisted
        } else {
            ClientForm::default()
        };
        let mut state = Self {
            inputs: FormInputs::new(&form, window, cx),
            config_path,
            settings_path,
            settings,
            console_sender,
            console_lines: VecDeque::new(),
            console_bytes: 0,
            console_scroll_handle: ScrollHandle::new(),
            follow_console: false,
            process: None,
            status: "Ready".to_string(),
            error: None,
            http_enabled: form.http_enabled,
            udp_enabled: form.udp_enabled,
            tls_enabled: form.tls_enabled,
            auth_mode: form.auth_mode,
            remember_close_action: false,
            show_close_confirmation: false,
            show_settings: false,
            exiting: false,
            _tray: tray,
        };
        state.persist_settings();
        state
    }

    fn save_config(&mut self, cx: &App) -> bool {
        let result = self
            .inputs
            .form(self, cx)
            .to_config()
            .and_then(|config| toml::to_string_pretty(&config).map_err(|error| error.to_string()))
            .and_then(|content| write_file(&self.config_path, content));
        match result {
            Ok(()) => {
                self.error = None;
                self.status = format!("Saved {}", self.config_path.display());
                true
            }
            Err(error) => {
                self.error = Some(error);
                false
            }
        }
    }

    fn start_client(&mut self, cx: &App) {
        if !self.save_config(cx) {
            self.show_settings = true;
            return;
        }
        if self.process.is_some() {
            self.status = "Client is already running".to_string();
            return;
        }
        let mut command = Command::new(proxy_executable());
        command
            .args(["client", "--config"])
            .arg(&self.config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);
        match command.spawn() {
            Ok(mut child) => {
                self.status = format!("Client running (pid {})", child.id());
                self.append_console(format!("[gui] {}", self.status));
                if let Some(stdout) = child.stdout.take() {
                    spawn_console_reader(stdout, "", self.console_sender.clone());
                }
                if let Some(stderr) = child.stderr.take() {
                    spawn_console_reader(stderr, "[stderr] ", self.console_sender.clone());
                }
                self.process = Some(child);
                self.error = None;
            }
            Err(error) => {
                let message = format!("Unable to start proxy-core: {error}");
                self.append_console(format!("[gui] {message}"));
                self.error = Some(message);
            }
        }
    }

    fn stop_client(&mut self) {
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.wait();
            self.status = "Client stopped".to_string();
            self.append_console("[gui] Client stopped".to_string());
        }
    }

    fn refresh_process_state(&mut self) -> bool {
        let exited = self
            .process
            .as_mut()
            .and_then(|child| child.try_wait().ok().flatten());
        if let Some(status) = exited {
            self.process = None;
            self.status = format!("Client exited ({status})");
            self.append_console(format!("[gui] {}", self.status));
            return true;
        }
        false
    }

    fn append_console(&mut self, line: String) {
        push_console_line(
            &mut self.console_lines,
            &mut self.console_bytes,
            self.settings.console_max_lines,
            line,
        );
        if self.follow_console {
            self.console_scroll_handle.scroll_to_bottom();
        }
    }

    fn trim_console(&mut self) {
        while self.console_lines.len() > self.settings.console_max_lines
            || self.console_bytes > CONSOLE_MAX_BYTES
        {
            let Some(removed) = self.console_lines.pop_front() else {
                break;
            };
            self.console_bytes = self.console_bytes.saturating_sub(removed.len());
        }
    }

    fn persist_settings(&mut self) {
        let result = toml::to_string_pretty(&self.settings)
            .map_err(|error| error.to_string())
            .and_then(|content| write_file(&self.settings_path, content));
        if let Err(error) = result {
            self.error = Some(format!("Unable to save GUI settings: {error}"));
        }
    }

    fn input_row(
        label: &'static str,
        required: bool,
        input: &Entity<InputState>,
    ) -> impl IntoElement {
        h_flex()
            .w_full()
            .gap_3()
            .items_center()
            .child(div().w(px(164.)).flex_none().text_sm().child(if required {
                format!("{label} *")
            } else {
                label.to_string()
            }))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .child(Input::new(input).min_w_0().w_full()),
            )
    }

    fn section(title: &'static str, content: impl IntoElement) -> impl IntoElement {
        v_flex()
            .w_full()
            .gap_3()
            .pb_5()
            .border_b_1()
            .border_color(rgb(0xdfe5e2))
            .child(
                div()
                    .text_lg()
                    .font_semibold()
                    .text_color(rgb(ACCENT_DARK))
                    .child(title),
            )
            .child(content)
    }

    fn stacked_input(label: &'static str, input: &Entity<InputState>) -> impl IntoElement {
        v_flex()
            .w_full()
            .gap_2()
            .child(div().text_sm().child(label))
            .child(Input::new(input).min_w_0().w_full())
    }

    fn ladder_mark() -> impl IntoElement {
        let rail = || {
            div()
                .absolute()
                .top(px(7.))
                .h(px(28.))
                .w(px(5.))
                .rounded(px(2.5))
                .bg(rgb(0x47d17a))
        };
        let rung = |top| {
            div()
                .absolute()
                .left(px(11.))
                .top(px(top))
                .h(px(4.))
                .w(px(20.))
                .rounded(px(2.))
                .bg(rgb(0x47d17a))
        };
        div()
            .relative()
            .size(px(42.))
            .flex_none()
            .rounded(px(7.))
            .bg(rgb(0x0f2d24))
            .child(rail().left(px(10.)))
            .child(rail().right(px(10.)))
            .child(rung(12.))
            .child(rung(20.))
            .child(rung(28.))
    }

    fn render_tunnel(&self) -> impl IntoElement {
        Self::section(
            "Tunnel",
            v_flex()
                .gap_3()
                .child(Self::input_row(
                    "Server address",
                    true,
                    &self.inputs.server_addr,
                ))
                .child(Self::input_row(
                    "Shared secret",
                    true,
                    &self.inputs.shared_secret,
                ))
                .child(Self::input_row("Client ID", true, &self.inputs.client_id))
                .child(Self::input_row("Pool size", false, &self.inputs.pool_size))
                .child(Self::input_row(
                    "Connect timeout (s)",
                    false,
                    &self.inputs.connect_timeout_secs,
                ))
                .child(Self::input_row(
                    "Heartbeat interval (s)",
                    false,
                    &self.inputs.heartbeat_interval_secs,
                ))
                .child(Self::input_row(
                    "Heartbeat timeout (s)",
                    false,
                    &self.inputs.heartbeat_timeout_secs,
                )),
        )
    }

    fn render_listeners(&self, cx: &Context<'_, Self>) -> impl IntoElement {
        let http_view = cx.entity();
        let udp_view = http_view.clone();
        Self::section(
            "Local listeners",
            v_flex()
                .gap_3()
                .child(Self::input_row("SOCKS5 IP", true, &self.inputs.socks_bind))
                .child(Self::input_row(
                    "SOCKS5 port",
                    true,
                    &self.inputs.socks_port,
                ))
                .child(Self::input_row(
                    "TCP keepalive (s)",
                    false,
                    &self.inputs.socks_keepalive_secs,
                ))
                .child(
                    Checkbox::new("http-enabled")
                        .label("Enable HTTP CONNECT")
                        .checked(self.http_enabled)
                        .on_click(move |checked, _, cx| {
                            http_view.update(cx, |state, cx| {
                                state.http_enabled = *checked;
                                cx.notify();
                            });
                        }),
                )
                .when(self.http_enabled, |content| {
                    content
                        .child(Self::input_row("HTTP IP", true, &self.inputs.http_bind))
                        .child(Self::input_row("HTTP port", true, &self.inputs.http_port))
                })
                .child(
                    Checkbox::new("udp-enabled")
                        .label("Enable UDP relay")
                        .checked(self.udp_enabled)
                        .on_click(move |checked, _, cx| {
                            udp_view.update(cx, |state, cx| {
                                state.udp_enabled = *checked;
                                cx.notify();
                            });
                        }),
                )
                .child(Self::input_row(
                    "UDP idle timeout (s)",
                    false,
                    &self.inputs.udp_idle_timeout_secs,
                )),
        )
    }

    fn render_authentication(&self, cx: &Context<'_, Self>) -> impl IntoElement {
        let none_view = cx.entity();
        let password_view = none_view.clone();
        Self::section(
            "Authentication",
            v_flex()
                .gap_3()
                .child(
                    h_flex()
                        .gap_2()
                        .child(
                            Button::new("auth-none")
                                .label("None")
                                .selected(self.auth_mode == "none")
                                .on_click(move |_, _, cx| {
                                    none_view.update(cx, |state, cx| {
                                        state.auth_mode = "none".to_string();
                                        cx.notify();
                                    });
                                }),
                        )
                        .child(
                            Button::new("auth-password")
                                .label("Username / password")
                                .selected(self.auth_mode == "password")
                                .on_click(move |_, _, cx| {
                                    password_view.update(cx, |state, cx| {
                                        state.auth_mode = "password".to_string();
                                        cx.notify();
                                    });
                                }),
                        ),
                )
                .when(self.auth_mode == "password", |content| {
                    content
                        .child(Self::stacked_input("Username", &self.inputs.auth_username))
                        .child(Self::stacked_input("Password", &self.inputs.auth_password))
                }),
        )
    }

    fn render_tls(&self, cx: &Context<'_, Self>) -> impl IntoElement {
        let view = cx.entity();
        Self::section(
            "TLS",
            v_flex()
                .gap_3()
                .child(
                    Checkbox::new("tls-enabled")
                        .label("Enable TLS")
                        .checked(self.tls_enabled)
                        .on_click(move |checked, _, cx| {
                            view.update(cx, |state, cx| {
                                state.tls_enabled = *checked;
                                cx.notify();
                            });
                        }),
                )
                .when(self.tls_enabled, |content| {
                    content
                        .child(Self::stacked_input(
                            "Server name",
                            &self.inputs.tls_server_name,
                        ))
                        .child(Self::stacked_input(
                            "CA certificate",
                            &self.inputs.tls_ca_cert_path,
                        ))
                        .child(Self::stacked_input(
                            "Client certificate",
                            &self.inputs.tls_client_cert_path,
                        ))
                        .child(Self::stacked_input(
                            "Client key",
                            &self.inputs.tls_client_key_path,
                        ))
                }),
        )
    }

    fn render_logging(&self) -> impl IntoElement {
        Self::section(
            "Logging",
            v_flex()
                .gap_3()
                .child(Self::stacked_input("Level", &self.inputs.log_level))
                .child(Self::stacked_input("Format", &self.inputs.log_format)),
        )
    }

    fn render_main(&self, cx: &Context<'_, Self>) -> impl IntoElement {
        let settings_view = cx.entity();
        let run_view = settings_view.clone();
        let clear_view = settings_view.clone();
        let follow_view = settings_view.clone();
        let manual_scroll_view = settings_view.clone();
        let console_text = if self.console_lines.is_empty() {
            "No console output.".to_string()
        } else {
            self.console_lines
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("\n")
        };
        let header = h_flex()
            .w_full()
            .justify_between()
            .items_center()
            .gap_4()
            .pb_4()
            .border_b_1()
            .border_color(rgb(0xdfe5e2))
            .child(
                h_flex()
                    .flex_1()
                    .min_w_0()
                    .gap_3()
                    .items_center()
                    .child(Self::ladder_mark())
                    .child(div().text_xl().font_semibold().child(APP_NAME)),
            )
            .child(
                Button::new("open-settings")
                    .ml_auto()
                    .flex_none()
                    .icon(IconName::Settings)
                    .label("Settings")
                    .tooltip("Settings")
                    .on_click(move |_, _, cx| {
                        settings_view.update(cx, |state, cx| {
                            state.show_settings = true;
                            cx.notify();
                        });
                    }),
            );
        let controls = h_flex()
            .w_full()
            .justify_between()
            .items_center()
            .gap_4()
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .gap_1()
                    .child(div().text_lg().font_semibold().child("Client service"))
                    .child(div().text_sm().text_color(rgb(0x63706a)).child(
                        if self.process.is_some() {
                            "Traffic forwarding is enabled"
                        } else {
                            "Traffic forwarding is disabled"
                        },
                    )),
            )
            .child(if self.process.is_some() {
                Button::new("disable-client")
                    .flex_none()
                    .danger()
                    .icon(IconName::Pause)
                    .label("Disable")
                    .on_click(move |_, _, cx| {
                        run_view.update(cx, |state, cx| {
                            state.stop_client();
                            cx.notify();
                        });
                    })
            } else {
                Button::new("enable-client")
                    .flex_none()
                    .primary()
                    .icon(IconName::Play)
                    .label("Enable")
                    .on_click(move |_, _, cx| {
                        run_view.update(cx, |state, cx| {
                            state.start_client(cx);
                            cx.notify();
                        });
                    })
            });
        let console = v_flex()
            .flex_1()
            .min_h_0()
            .gap_3()
            .child(
                h_flex()
                    .w_full()
                    .justify_between()
                    .items_center()
                    .gap_3()
                    .child(
                        h_flex()
                            .flex_1()
                            .min_w_0()
                            .items_center()
                            .gap_2()
                            .child(div().text_lg().font_semibold().child("Console"))
                            .child(div().text_sm().text_color(rgb(0x63706a)).child(format!(
                                "{} / {} lines",
                                self.console_lines.len(),
                                self.settings.console_max_lines
                            ))),
                    )
                    .child(
                        Button::new("follow-console")
                            .flex_none()
                            .icon(IconName::ChevronDown)
                            .label("Follow latest")
                            .tooltip("Toggle automatic scrolling to the newest console output")
                            .selected(self.follow_console)
                            .on_click(move |_, _, cx| {
                                follow_view.update(cx, |state, cx| {
                                    state.follow_console = !state.follow_console;
                                    if state.follow_console {
                                        state.console_scroll_handle.scroll_to_bottom();
                                    }
                                    cx.notify();
                                });
                            }),
                    )
                    .child(
                        Button::new("clear-console")
                            .flex_none()
                            .icon(IconName::Delete)
                            .label("Clear")
                            .tooltip("Clear console")
                            .on_click(move |_, _, cx| {
                                clear_view.update(cx, |state, cx| {
                                    state.console_lines.clear();
                                    state.console_bytes = 0;
                                    if state.follow_console {
                                        state.console_scroll_handle.scroll_to_bottom();
                                    }
                                    cx.notify();
                                });
                            }),
                    ),
            )
            .child(
                div()
                    .id("console-scroll")
                    .track_scroll(&self.console_scroll_handle)
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .overflow_scrollbar()
                    .rounded(px(6.))
                    .border_1()
                    .border_color(rgb(0x243a32))
                    .bg(rgb(0x10221c))
                    .p_4()
                    .font_family("Consolas")
                    .text_sm()
                    .text_color(rgb(0xc8ded4))
                    .whitespace_normal()
                    .on_scroll_wheel(move |_, _, cx| {
                        manual_scroll_view.update(cx, |state, cx| {
                            if state.follow_console {
                                state.follow_console = false;
                                cx.notify();
                            }
                        });
                    })
                    .child(SharedString::from(console_text)),
            );
        v_flex()
            .absolute()
            .top(px(24.))
            .right(px(24.))
            .bottom(px(24.))
            .left(px(24.))
            .gap_5()
            .child(header)
            .child(controls)
            .when_some(self.error.clone(), |content, error| {
                content.child(
                    div()
                        .w_full()
                        .px_3()
                        .py_2()
                        .rounded(px(5.))
                        .bg(rgb(0xffe7e5))
                        .text_color(rgb(0xa4231d))
                        .text_sm()
                        .child(error),
                )
            })
            .child(console)
    }

    fn render_close_confirmation(&self, cx: &Context<'_, Self>) -> impl IntoElement {
        let view = cx.entity();
        let cancel_view = view.clone();
        let minimize_view = view.clone();
        let exit_view = view.clone();
        div()
            .absolute()
            .top(px(0.))
            .right(px(0.))
            .bottom(px(0.))
            .left(px(0.))
            .bg(rgb(0x000000))
            .child(
                v_flex()
                    .absolute()
                    .top(px(220.))
                    .left(px(320.))
                    .right(px(320.))
                    .gap_4()
                    .p_6()
                    .rounded(px(8.))
                    .bg(rgb(0xf7faf8))
                    .border_1()
                    .border_color(rgb(0xdfe5e2))
                    .child(div().text_lg().font_semibold().child("Close Rama Proxy"))
                    .child("What should happen when the window closes?")
                    .child(
                        Checkbox::new("remember-close-action")
                            .label("Remember this choice")
                            .checked(self.remember_close_action)
                            .on_click(move |checked, _, cx| {
                                view.update(cx, |state, cx| {
                                    state.remember_close_action = *checked;
                                    cx.notify();
                                });
                            }),
                    )
                    .child(
                        h_flex()
                            .justify_end()
                            .gap_2()
                            .child(
                                Button::new("close-cancel")
                                    .icon(IconName::Close)
                                    .label("Cancel")
                                    .on_click(move |_, _, cx| {
                                        cancel_view.update(cx, |state, cx| {
                                            state.show_close_confirmation = false;
                                            cx.notify();
                                        });
                                    }),
                            )
                            .child(
                                Button::new("close-minimize")
                                    .icon(IconName::WindowMinimize)
                                    .label("Close to tray")
                                    .on_click(move |_, window, cx| {
                                        apply_close_choice(
                                            &minimize_view,
                                            CloseAction::MinimizeToTray,
                                            window,
                                            cx,
                                        );
                                    }),
                            )
                            .child(
                                Button::new("close-exit")
                                    .danger()
                                    .icon(IconName::WindowClose)
                                    .label("Exit")
                                    .on_click(move |_, window, cx| {
                                        apply_close_choice(
                                            &exit_view,
                                            CloseAction::Exit,
                                            window,
                                            cx,
                                        );
                                    }),
                            ),
                    ),
            )
    }

    fn render_settings(&self, wide: bool, cx: &Context<'_, Self>) -> impl IntoElement {
        let back_view = cx.entity();
        let save_view = back_view.clone();
        let remember_view = back_view.clone();
        let ask_view = back_view.clone();
        let exit_view = back_view.clone();
        let tray_view = back_view.clone();
        let lines_500_view = back_view.clone();
        let lines_1000_view = back_view.clone();
        let lines_5000_view = back_view.clone();
        let header = h_flex()
            .w_full()
            .justify_between()
            .items_center()
            .gap_4()
            .pb_4()
            .border_b_1()
            .border_color(rgb(0xdfe5e2))
            .child(
                h_flex()
                    .flex_1()
                    .min_w_0()
                    .gap_3()
                    .items_center()
                    .child(
                        Button::new("back-to-client")
                            .icon(IconName::ArrowLeft)
                            .label("Back")
                            .tooltip("Back")
                            .on_click(move |_, _, cx| {
                                back_view.update(cx, |state, cx| {
                                    state.show_settings = false;
                                    cx.notify();
                                });
                            }),
                    )
                    .child(
                        v_flex()
                            .gap_1()
                            .child(div().text_xl().font_semibold().child("Settings"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(0x63706a))
                                    .child(format!("Config: {}", self.config_path.display())),
                            ),
                    ),
            )
            .child(
                Button::new("save-settings")
                    .ml_auto()
                    .flex_none()
                    .primary()
                    .icon(IconName::HardDrive)
                    .label("Save")
                    .on_click(move |_, _, cx| {
                        save_view.update(cx, |state, cx| {
                            if state.save_config(cx) {
                                state.persist_settings();
                                if state.error.is_none() {
                                    state.show_settings = false;
                                }
                            }
                            cx.notify();
                        });
                    }),
            );
        let left = v_flex()
            .flex_1()
            .flex_basis(px(0.))
            .min_w_0()
            .gap_5()
            .child(self.render_tunnel())
            .child(self.render_listeners(cx));
        let right = v_flex()
            .flex_1()
            .flex_basis(px(0.))
            .min_w_0()
            .gap_5()
            .child(self.render_authentication(cx))
            .child(self.render_tls(cx))
            .child(self.render_logging())
            .child(Self::section(
                "Application",
                v_flex()
                    .gap_4()
                    .child(
                        Checkbox::new("remember-configuration")
                            .label("Remember configuration locally")
                            .checked(self.settings.remember_config)
                            .on_click(move |checked, _, cx| {
                                remember_view.update(cx, |state, cx| {
                                    state.settings.remember_config = *checked;
                                    state.persist_settings();
                                    cx.notify();
                                });
                            }),
                    )
                    .child(
                        v_flex()
                            .gap_2()
                            .child(div().text_sm().child("Close button behavior"))
                            .child(
                                h_flex()
                                    .gap_2()
                                    .child(
                                        Button::new("close-behavior-ask")
                                            .label("Ask")
                                            .selected(
                                                self.settings.close_action == CloseAction::Ask,
                                            )
                                            .on_click(move |_, _, cx| {
                                                ask_view.update(cx, |state, cx| {
                                                    state.settings.close_action = CloseAction::Ask;
                                                    state.persist_settings();
                                                    cx.notify();
                                                });
                                            }),
                                    )
                                    .child(
                                        Button::new("close-behavior-exit")
                                            .label("Exit")
                                            .selected(
                                                self.settings.close_action == CloseAction::Exit,
                                            )
                                            .on_click(move |_, _, cx| {
                                                exit_view.update(cx, |state, cx| {
                                                    state.settings.close_action = CloseAction::Exit;
                                                    state.persist_settings();
                                                    cx.notify();
                                                });
                                            }),
                                    )
                                    .child(
                                        Button::new("close-behavior-tray")
                                            .label("Close to tray")
                                            .selected(
                                                self.settings.close_action
                                                    == CloseAction::MinimizeToTray,
                                            )
                                            .on_click(move |_, _, cx| {
                                                tray_view.update(cx, |state, cx| {
                                                    state.settings.close_action =
                                                        CloseAction::MinimizeToTray;
                                                    state.persist_settings();
                                                    cx.notify();
                                                });
                                            }),
                                    ),
                            ),
                    )
                    .child(
                        v_flex()
                            .gap_2()
                            .child(div().text_sm().child("Console cache"))
                            .child(
                                h_flex()
                                    .gap_2()
                                    .child(
                                        Button::new("console-lines-500")
                                            .label("500 lines")
                                            .selected(self.settings.console_max_lines == 500)
                                            .on_click(move |_, _, cx| {
                                                lines_500_view.update(cx, |state, cx| {
                                                    state.settings.console_max_lines = 500;
                                                    state.trim_console();
                                                    state.persist_settings();
                                                    cx.notify();
                                                });
                                            }),
                                    )
                                    .child(
                                        Button::new("console-lines-1000")
                                            .label("1,000 lines")
                                            .selected(self.settings.console_max_lines == 1000)
                                            .on_click(move |_, _, cx| {
                                                lines_1000_view.update(cx, |state, cx| {
                                                    state.settings.console_max_lines = 1000;
                                                    state.trim_console();
                                                    state.persist_settings();
                                                    cx.notify();
                                                });
                                            }),
                                    )
                                    .child(
                                        Button::new("console-lines-5000")
                                            .label("5,000 lines")
                                            .selected(self.settings.console_max_lines == 5000)
                                            .on_click(move |_, _, cx| {
                                                lines_5000_view.update(cx, |state, cx| {
                                                    state.settings.console_max_lines = 5000;
                                                    state.trim_console();
                                                    state.persist_settings();
                                                    cx.notify();
                                                });
                                            }),
                                    ),
                            ),
                    ),
            ));
        let columns = if wide {
            h_flex()
                .w_full()
                .items_start()
                .gap_6()
                .child(left)
                .child(right)
        } else {
            h_flex()
                .w_full()
                .items_start()
                .child(v_flex().w_full().gap_5().child(left).child(right))
        };
        v_flex()
            .absolute()
            .top(px(24.))
            .right(px(24.))
            .bottom(px(24.))
            .left(px(24.))
            .gap_4()
            .child(header)
            .child(
                div()
                    .id("settings-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .overflow_scrollbar()
                    .pr_3()
                    .child(columns),
            )
            .when_some(self.error.clone(), |content, error| {
                content.child(
                    div()
                        .w_full()
                        .px_3()
                        .py_2()
                        .rounded(px(5.))
                        .bg(rgb(0xffe7e5))
                        .text_color(rgb(0xa4231d))
                        .text_sm()
                        .child(error),
                )
            })
    }
}

impl Drop for ClientView {
    fn drop(&mut self) {
        self.stop_client();
    }
}

impl Render for ClientView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.refresh_process_state();
        let viewport = window.viewport_size();
        let wide = viewport.width >= px(1040.);
        div()
            .w(viewport.width)
            .h(viewport.height)
            .relative()
            .bg(rgb(0xf7faf8))
            .text_color(rgb(0x1c2722))
            .when(self.show_settings, |content| {
                content.child(self.render_settings(wide, cx))
            })
            .when(!self.show_settings, |content| {
                content.child(self.render_main(cx))
            })
            .when(self.show_close_confirmation, |content| {
                content.child(self.render_close_confirmation(cx))
            })
    }
}

fn spawn_console_reader<R>(mut reader: R, prefix: &'static str, sender: SyncSender<String>)
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        let mut line = Vec::with_capacity(CONSOLE_MAX_LINE_BYTES);
        let mut truncated = false;
        let send_line = |line: &[u8], truncated: bool| {
            let suffix = if truncated { " ... [truncated]" } else { "" };
            let _ = sender.try_send(format!("{prefix}{}{suffix}", String::from_utf8_lossy(line)));
        };
        loop {
            let Ok(read) = reader.read(&mut buffer) else {
                break;
            };
            if read == 0 {
                break;
            }
            for byte in &buffer[..read] {
                if *byte == b'\n' {
                    send_line(&line, truncated);
                    line.clear();
                    truncated = false;
                } else if *byte != b'\r' {
                    if line.len() < CONSOLE_MAX_LINE_BYTES {
                        line.push(*byte);
                    } else {
                        truncated = true;
                    }
                }
            }
        }
        if !line.is_empty() || truncated {
            send_line(&line, truncated);
        }
    });
}

fn push_console_line(
    lines: &mut VecDeque<String>,
    bytes: &mut usize,
    max_lines: usize,
    line: String,
) {
    *bytes += line.len();
    lines.push_back(line);
    while lines.len() > max_lines || *bytes > CONSOLE_MAX_BYTES {
        let Some(removed) = lines.pop_front() else {
            break;
        };
        *bytes = bytes.saturating_sub(removed.len());
    }
}

fn read_toml<T>(path: &Path) -> Option<T>
where
    T: for<'de> Deserialize<'de>,
{
    fs::read_to_string(path)
        .ok()
        .and_then(|content| toml::from_str(&content).ok())
}

#[cfg(windows)]
fn set_window_visible(window: &mut Window, cx: &App, visible: bool) {
    let Ok(raw_handle) = window.window_handle() else {
        return;
    };
    let RawWindowHandle::Win32(win32_handle) = raw_handle.as_raw() else {
        return;
    };
    let command = if visible { SW_RESTORE } else { SW_HIDE };
    let _ = unsafe { ShowWindowAsync(win32_handle.hwnd.into(), command) };
    if visible {
        cx.activate(true);
        window.activate_window();
    }
}

#[cfg(windows)]
fn restore_window_if_hidden(window: &mut Window, cx: &App) {
    let Ok(raw_handle) = window.window_handle() else {
        return;
    };
    let RawWindowHandle::Win32(win32_handle) = raw_handle.as_raw() else {
        return;
    };
    if unsafe { IsWindowVisible(win32_handle.hwnd.into()) } == 0 {
        set_window_visible(window, cx, true);
    }
}

#[cfg(not(windows))]
fn set_window_visible(window: &mut Window, cx: &App, visible: bool) {
    if visible {
        cx.activate(true);
        window.activate_window();
    } else {
        cx.hide();
    }
}

#[cfg(windows)]
fn tray_available() -> bool {
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    let class_name = wide("my_window");
    let window_name = wide("rust_systray_window");
    let current_process = unsafe { GetCurrentProcessId() };
    let mut child_after = 0;
    loop {
        let window =
            unsafe { FindWindowExW(0, child_after, class_name.as_ptr(), window_name.as_ptr()) };
        if window == 0 {
            return false;
        }
        let mut process_id = 0;
        unsafe {
            GetWindowThreadProcessId(window, &mut process_id);
        }
        if process_id == current_process {
            return true;
        }
        child_after = window;
    }
}

#[cfg(not(windows))]
fn tray_available() -> bool {
    true
}

fn hide_to_tray(view: &Entity<ClientView>, window: &mut Window, cx: &mut App) {
    if tray_available() {
        set_window_visible(window, cx, false);
        return;
    }

    view.update(cx, |state, cx| {
        state.show_close_confirmation = false;
        state.error = Some(format!(
            "{TRAY_ERROR_PREFIX}; the window will stay open while it is restored."
        ));
        cx.notify();
    });
    set_window_visible(window, cx, true);
}

fn apply_close_choice(
    view: &Entity<ClientView>,
    action: CloseAction,
    window: &mut Window,
    cx: &mut App,
) {
    view.update(cx, |state, _| {
        state.show_close_confirmation = false;
        if state.remember_close_action {
            state.settings.close_action = action;
            state.persist_settings();
        }
        if action == CloseAction::Exit {
            state.exiting = true;
            state.stop_client();
        }
    });
    match action {
        CloseAction::MinimizeToTray => hide_to_tray(view, window, cx),
        CloseAction::Exit => {
            window.remove_window();
            cx.quit();
        }
        CloseAction::Ask => {}
    }
}

fn write_file(path: &Path, content: String) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(path, content).map_err(|error| error.to_string())
}

fn app_data_dir() -> PathBuf {
    if let Ok(path) = std::env::var("APPDATA") {
        return PathBuf::from(path).join("rama-proxy");
    }
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".config")
        })
        .join("rama-proxy")
}

fn default_client_config_path() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("config")
        .join("client.toml")
}

fn proxy_executable() -> PathBuf {
    let mut path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("proxy-gui"));
    path.set_file_name(if cfg!(windows) {
        "proxy-core.exe"
    } else {
        "proxy-core"
    });
    path
}

fn create_tray_with_receiver() -> Result<(TrayItem, Receiver<TrayCommand>), String> {
    let (sender, receiver) = mpsc::channel();
    let tray = create_tray(sender).map_err(|error| error.to_string())?;
    Ok((tray, receiver))
}

fn create_tray(sender: Sender<TrayCommand>) -> Result<TrayItem, tray_item::TIError> {
    // The Windows resource compiler preserves the quoted RC identifier.
    let mut tray = TrayItem::new(APP_NAME, IconSource::Resource("\"rama-proxy-ladder\""))?;
    let show = sender.clone();
    tray.add_menu_item("Open", move || {
        let _ = show.send(TrayCommand::Show);
    })?;
    tray.add_menu_item("Exit", move || {
        let _ = sender.send(TrayCommand::Quit);
    })?;
    Ok(tray)
}

fn handle_tray_commands(
    receiver: Receiver<TrayCommand>,
    view: Entity<ClientView>,
    window_handle: gpui_kit::AnyWindowHandle,
    cx: &mut App,
) {
    cx.spawn(async move |cx| {
        loop {
            cx.background_executor()
                .timer(Duration::from_millis(200))
                .await;
            let command = match receiver.try_recv() {
                Ok(command) => command,
                Err(TryRecvError::Empty) => continue,
                Err(TryRecvError::Disconnected) => break,
            };
            let should_continue = cx.update(|cx| match command {
                TrayCommand::Show => {
                    let _ = window_handle.update(cx, |_, window, window_cx| {
                        set_window_visible(window, window_cx, true);
                    });
                    true
                }
                TrayCommand::Quit => {
                    view.update(cx, |state, _| {
                        state.exiting = true;
                        state.stop_client();
                    });
                    let _ = window_handle.update(cx, |_, window, _| window.remove_window());
                    cx.quit();
                    false
                }
            });
            if !should_continue {
                break;
            }
        }
    })
    .detach();
}

fn monitor_tray(view: Entity<ClientView>, window_handle: gpui_kit::AnyWindowHandle, cx: &mut App) {
    cx.spawn(async move |cx| {
        loop {
            cx.background_executor().timer(TRAY_MONITOR_INTERVAL).await;
            let should_continue = cx.update(|cx| !view.read(cx).exiting);
            if !should_continue {
                break;
            }
            if tray_available() {
                continue;
            }

            match create_tray_with_receiver() {
                Ok((tray, receiver)) => {
                    cx.update(|cx| {
                        view.update(cx, |state, cx| {
                            let had_tray_error = state
                                .error
                                .as_deref()
                                .is_some_and(|error| error.starts_with(TRAY_ERROR_PREFIX));
                            state._tray = Some(tray);
                            if had_tray_error {
                                state.error = None;
                                cx.notify();
                            }
                        });
                    });
                    let handler_view = view.clone();
                    cx.update(|cx| {
                        handle_tray_commands(receiver, handler_view, window_handle, cx);
                    });
                }
                Err(error) => {
                    let message = format!(
                        "{TRAY_ERROR_PREFIX}: {error}; the window will stay open while retrying."
                    );
                    cx.update(|cx| {
                        view.update(cx, |state, cx| {
                            if state.error.as_deref() != Some(message.as_str()) {
                                state.error = Some(message.clone());
                                cx.notify();
                            }
                        });
                        let _ = window_handle.update(cx, |_, window, window_cx| {
                            restore_window_if_hidden(window, window_cx);
                        });
                    });
                }
            }
        }
    })
    .detach();
}

fn handle_console_output(receiver: Receiver<String>, view: Entity<ClientView>, cx: &mut App) {
    cx.spawn(async move |cx| {
        loop {
            cx.background_executor()
                .timer(Duration::from_millis(150))
                .await;
            let lines = receiver.try_iter().collect::<Vec<_>>();
            cx.update(|cx| {
                view.update(cx, |state, cx| {
                    let mut changed = state.refresh_process_state();
                    for line in lines {
                        state.append_console(line);
                        changed = true;
                    }
                    if changed {
                        cx.notify();
                    }
                });
            });
        }
    })
    .detach();
}

fn main() {
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(|cx| {
            gpui_kit::init(cx);
            let (console_tx, console_rx) = mpsc::sync_channel(CONSOLE_CHANNEL_CAPACITY);
            let (tray, tray_rx, tray_error) = match create_tray_with_receiver() {
                Ok((tray, receiver)) => (Some(tray), Some(receiver), None),
                Err(error) => (
                    None,
                    None,
                    Some(format!(
                        "{TRAY_ERROR_PREFIX}: {error}; retrying automatically."
                    )),
                ),
            };
            let bounds = Bounds::centered(None, size(px(1180.), px(760.)), cx);
            let mut client_view = None;
            let window_handle = cx
                .open_window(
                    WindowOptions {
                        window_bounds: Some(WindowBounds::Windowed(bounds)),
                        ..Default::default()
                    },
                    |window, cx| {
                        window.set_window_title(APP_NAME);
                        let view =
                            cx.new(|cx| ClientView::new(window, cx, tray, console_tx.clone()));
                        client_view = Some(view.clone());
                        let close_view = view.clone();
                        window.on_window_should_close(cx, move |window, cx| {
                            match close_view.read(cx).settings.close_action {
                                CloseAction::Exit => {
                                    close_view.update(cx, |state, _| {
                                        state.exiting = true;
                                        state.stop_client();
                                    });
                                    true
                                }
                                CloseAction::MinimizeToTray => {
                                    hide_to_tray(&close_view, window, cx);
                                    false
                                }
                                CloseAction::Ask => {
                                    close_view.update(cx, |state, cx| {
                                        if !state.show_close_confirmation {
                                            state.show_close_confirmation = true;
                                            cx.notify();
                                        }
                                    });
                                    false
                                }
                            }
                        });
                        cx.new(|cx| Root::new(view, window, cx).font_family("Segoe UI"))
                    },
                )
                .expect("Failed to open Rama Proxy window");
            cx.activate(true);
            let _ = window_handle.update(cx, |_, window, _| window.activate_window());
            let client_view = client_view.expect("Client view was not initialized");
            if let Some(error) = tray_error {
                client_view.update(cx, |state, cx| {
                    state.error = Some(error);
                    cx.notify();
                });
            }
            if let Some(receiver) = tray_rx {
                handle_tray_commands(receiver, client_view.clone(), window_handle.into(), cx);
            }
            monitor_tray(client_view.clone(), window_handle.into(), cx);
            handle_console_output(console_rx, client_view, cx);
        });
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::mpsc};

    use super::{
        CONSOLE_MAX_BYTES, CONSOLE_MAX_LINE_BYTES, ClientForm, create_tray,
        default_client_config_path, push_console_line, spawn_console_reader, tray_available,
    };

    fn valid_form() -> ClientForm {
        ClientForm {
            client_id: "client-01".to_string(),
            ..ClientForm::default()
        }
    }

    #[test]
    fn client_id_is_required() {
        let mut form = valid_form();
        form.client_id.clear();

        assert!(form.to_config().unwrap_err().contains("client_id"));
    }

    #[test]
    fn server_address_requires_ip_and_non_zero_port() {
        let mut form = valid_form();
        form.server_addr = "proxy.example.com:19090".to_string();
        assert!(form.to_config().unwrap_err().contains("server_addr"));

        form.server_addr = "127.0.0.1:0".to_string();
        assert!(form.to_config().unwrap_err().contains("greater than 0"));
    }

    #[test]
    fn listener_ip_and_ports_are_required() {
        let mut form = valid_form();
        form.socks_bind.clear();
        assert!(form.to_config().unwrap_err().contains("socks5.bind"));

        form.socks_bind = "127.0.0.1".to_string();
        form.socks_port = "0".to_string();
        assert!(form.to_config().unwrap_err().contains("greater than 0"));

        form.socks_port = "1080".to_string();
        form.http_enabled = true;
        form.http_bind.clear();
        assert!(form.to_config().unwrap_err().contains("http_connect.bind"));

        form.http_bind = "127.0.0.1".to_string();
        form.http_port = "0".to_string();
        assert!(form.to_config().unwrap_err().contains("greater than 0"));
    }

    #[test]
    fn console_cache_discards_oldest_lines_at_configured_limit() {
        let mut lines = VecDeque::new();
        let mut bytes = 0;
        for line in ["one", "two", "three"] {
            push_console_line(&mut lines, &mut bytes, 2, line.to_string());
        }

        assert_eq!(lines.into_iter().collect::<Vec<_>>(), ["two", "three"]);
        assert_eq!(bytes, 8);
    }

    #[test]
    fn console_cache_has_a_hard_byte_limit() {
        let mut lines = VecDeque::new();
        let mut bytes = 0;
        push_console_line(
            &mut lines,
            &mut bytes,
            usize::MAX,
            "a".repeat(CONSOLE_MAX_BYTES),
        );
        push_console_line(&mut lines, &mut bytes, usize::MAX, "next".to_string());

        assert_eq!(lines.into_iter().collect::<Vec<_>>(), ["next"]);
        assert_eq!(bytes, 4);
    }

    #[test]
    fn console_reader_truncates_oversized_lines() {
        let (sender, receiver) = mpsc::sync_channel(1);
        spawn_console_reader(
            std::io::Cursor::new(vec![b'x'; CONSOLE_MAX_LINE_BYTES + 100]),
            "",
            sender,
        );
        let line = receiver.recv().unwrap();

        assert_eq!(line, format!("{} ... [truncated]", "x".repeat(8192)));
    }

    #[cfg(windows)]
    #[test]
    fn tray_icon_resource_can_be_created() {
        let (sender, _receiver) = mpsc::channel();
        let tray = create_tray(sender).expect("tray icon resource must be loadable");
        assert!(tray_available());
        drop(tray);
        assert!(!tray_available());
    }

    #[test]
    fn client_config_uses_core_default_location() {
        assert_eq!(
            default_client_config_path(),
            std::env::current_dir()
                .unwrap()
                .join("config")
                .join("client.toml")
        );
    }
}
