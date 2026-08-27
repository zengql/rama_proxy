mod cli;
mod client_runtime;
mod config;
mod error;
mod http_connect_runtime;
mod logging;
mod server_runtime;
mod server_stats;
mod tls;
mod tunnel;
mod ui;

use std::ffi::OsString;
use std::path::Path;
use std::process::{Child, Command as ProcessCommand, Stdio};

use clap::Parser;

use crate::cli::{
    Cli, ClientCommand, Command, HttpConnectProxyCommand, ModeAction, ServerCommand, UiCommand,
};
use crate::config::{ClientConfigFile, ServerConfigFile};
use crate::error::AppError;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli = Cli::parse();

    match cli.command {
        Command::Server(cmd) => handle_server(cmd).await,
        Command::Client(cmd) => handle_client(cmd).await,
        Command::HttpConnectProxy(cmd) => handle_http_connect_proxy(cmd).await,
        Command::Ui(cmd) => handle_ui(cmd).await,
        Command::Version => {
            println!(
                "{} {} ({})",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
                option_env!("GIT_HASH").unwrap_or("git-hash-unavailable")
            );
            Ok(())
        }
        Command::Stop => stop_all(),
    }
}

async fn handle_server(cmd: ServerCommand) -> Result<(), AppError> {
    match cmd.action {
        Some(ModeAction::Stop) => stop_server_daemon(&cmd.config),
        Some(ModeAction::Init { output, force }) => {
            let output = output.unwrap_or_else(|| cmd.config.clone());
            ServerConfigFile::write_default_to_path(&output, force)?;
            println!("initialized server config: {}", output.display());
            Ok(())
        }
        Some(ModeAction::Check { config }) => {
            let path = config.unwrap_or(cmd.config);
            let config = ServerConfigFile::from_path(&path)?;
            config.validate()?;
            println!(
                "server config valid: bind={}:{}, outbound_ip_mode={}, tls={}",
                config.server.bind,
                config.server.port,
                config.server.outbound_ip_mode,
                config.tls.enabled
            );
            Ok(())
        }
        Some(ModeAction::Stats { stats_socket }) => {
            let path = stats_socket.unwrap_or(cmd.stats_socket);
            server_stats::print_snapshot(&path).await
        }
        None => {
            if cmd.daemon {
                if cmd.ui {
                    spawn_ui_daemon(&cmd.config, &cmd.stats_socket)?;
                }
                let mut extra_args = vec![
                    OsString::from("--stats-socket"),
                    cmd.stats_socket.as_os_str().to_os_string(),
                ];
                return spawn_daemon("server", &cmd.config, &extra_args);
            }
            let config = ServerConfigFile::from_path(&cmd.config)?;
            config.validate()?;
            logging::init(&config.log.level)?;
            let mut ui_child = if cmd.ui {
                Some(spawn_ui_child()?)
            } else {
                None
            };
            let result = server_runtime::run(config, cmd.stats_socket).await;
            if let Some(child) = ui_child.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            result
        }
    }
}

async fn handle_client(cmd: ClientCommand) -> Result<(), AppError> {
    match cmd.action {
        Some(ModeAction::Stop) => stop_daemon("client", &cmd.config),
        Some(ModeAction::Init { output, force }) => {
            let output = output.unwrap_or_else(|| cmd.config.clone());
            ClientConfigFile::write_default_to_path(&output, force)?;
            println!("initialized client config: {}", output.display());
            Ok(())
        }
        Some(ModeAction::Check { config }) => {
            let path = config.unwrap_or(cmd.config);
            let config = ClientConfigFile::from_path(&path)?;
            config.validate()?;
            println!(
                "client config valid: local_socks5={}:{}, server_addr={}, udp={}, tls={}",
                config.socks5.bind,
                config.socks5.port,
                config.client.server_addr,
                config.udp.enabled,
                config.tls.enabled
            );
            Ok(())
        }
        Some(ModeAction::Stats { .. }) => Err(AppError::InvalidConfig(
            "client stats is not supported; use `rama-proxy server stats`".to_string(),
        )),
        None => {
            if cmd.daemon {
                return spawn_daemon("client", &cmd.config, &[]);
            }
            let config = ClientConfigFile::from_path(&cmd.config)?;
            config.validate()?;
            logging::init(&config.log.level)?;
            let _http_connect_proxy_child = spawn_http_connect_proxy_child(&config, &cmd.config)?;
            client_runtime::run(config).await
        }
    }
}

async fn handle_http_connect_proxy(cmd: HttpConnectProxyCommand) -> Result<(), AppError> {
    let config = ClientConfigFile::from_path(&cmd.config)?;
    config.validate()?;
    logging::init(&config.log.level)?;
    http_connect_runtime::run(config).await
}

async fn handle_ui(cmd: UiCommand) -> Result<(), AppError> {
    match cmd.action {
        Some(cli::UiAction::Stop) => {
            return stop_pid_file(
                "ui",
                cmd.ui_pid_file
                    .as_deref()
                    .unwrap_or(Path::new("config/rama-proxy-ui.pid")),
            );
        }
        Some(cli::UiAction::Init { output, force }) => {
            let path = output.unwrap_or(cmd.config);
            ui::UiConfig::write_default_to_path(&path, force)?;
            println!("initialized ui config: {}", path.display());
            return Ok(());
        }
        None => {}
    }
    logging::init("info")?;
    if cmd.daemon {
        return spawn_daemon("ui", &cmd.config, &[]);
    }
    let config = ui::UiConfig::from_path(&cmd.config)?;
    ui::run(config.with_overrides(cmd)).await
}

fn spawn_daemon(mode: &str, config_path: &Path, extra_args: &[OsString]) -> Result<(), AppError> {
    let exe = std::env::current_exe()?;
    let stem = format!("rama-proxy-{mode}");

    let log_path = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("{stem}.out"));
    let pid_path = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("{stem}.pid"));

    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let err_file = log_file.try_clone()?;

    let mut cmd = std::process::Command::new(exe);
    cmd.arg(mode)
        .arg("--config")
        .arg(config_path)
        .args(extra_args)
        .stdout(log_file)
        .stderr(err_file)
        .stdin(std::process::Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let child = cmd.spawn()?;
    let pid = child.id();
    std::fs::write(&pid_path, pid.to_string())?;

    println!(
        "daemon started: mode={mode}, pid={pid}, log={}, pidfile={}",
        log_path.display(),
        pid_path.display()
    );
    Ok(())
}

fn stop_daemon(mode: &str, config_path: &Path) -> Result<(), AppError> {
    let pid_path = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("rama-proxy-{mode}.pid"));
    stop_pid_file(mode, &pid_path)
}

fn stop_server_daemon(config_path: &Path) -> Result<(), AppError> {
    let result = stop_daemon("server", config_path);
    let ui_pid_path = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("rama-proxy-ui.pid");
    let ui_result = stop_pid_file("ui", &ui_pid_path);
    let server_missing = matches!(&result, Err(err) if is_missing_pid_error(err));
    let ui_missing = matches!(&ui_result, Err(err) if is_missing_pid_error(err));

    if server_missing && ui_missing {
        return Err(result.expect_err("server stop result should be an error"));
    }
    if let Err(err) = result {
        if !server_missing {
            return Err(err);
        }
    }
    if let Err(err) = ui_result {
        if !ui_missing {
            return Err(err);
        }
    }
    Ok(())
}

fn spawn_ui_daemon(server_config_path: &Path, stats_socket: &Path) -> Result<(), AppError> {
    let ui_config_path = server_config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("ui.toml");
    let extra_args = [
        OsString::from("--stats-socket"),
        stats_socket.as_os_str().to_os_string(),
    ];
    spawn_daemon("ui", &ui_config_path, &extra_args)
}

fn is_missing_pid_error(error: &AppError) -> bool {
    matches!(error, AppError::Boxed(message) if message.starts_with("read ") && message.contains("pid file"))
}

fn spawn_ui_child() -> Result<Child, AppError> {
    let exe = std::env::current_exe()?;
    let child = ProcessCommand::new(exe)
        .arg("ui")
        .arg("--config")
        .arg("config/ui.toml")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    println!("ui child started: pid={}", child.id());
    Ok(child)
}

fn stop_pid_file(mode: &str, pid_path: &Path) -> Result<(), AppError> {
    let raw_pid = std::fs::read_to_string(pid_path).map_err(|err| {
        AppError::Boxed(format!(
            "read {mode} pid file {} failed: {err}",
            pid_path.display()
        ))
    })?;
    let pid = raw_pid
        .trim()
        .parse::<u32>()
        .map_err(|_| AppError::InvalidConfig(format!("invalid pid in {}", pid_path.display())))?;

    #[cfg(windows)]
    let status = ProcessCommand::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T"])
        .status()?;
    #[cfg(unix)]
    let status = ProcessCommand::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()?;

    if !status.success() {
        return Err(AppError::Boxed(format!(
            "failed to stop {mode} daemon pid {pid}"
        )));
    }
    let _ = std::fs::remove_file(pid_path);
    println!("stop requested: mode={mode}, pid={pid}");
    Ok(())
}

fn stop_all() -> Result<(), AppError> {
    let config_dir = Path::new("config");
    let mut stopped = 0;
    for (mode, pid_file) in [
        ("server", config_dir.join("rama-proxy-server.pid")),
        ("client", config_dir.join("rama-proxy-client.pid")),
        ("ui", config_dir.join("rama-proxy-ui.pid")),
    ] {
        match stop_pid_file(mode, &pid_file) {
            Ok(()) => stopped += 1,
            Err(AppError::Boxed(message))
                if message.starts_with("read ") && message.contains("pid file") =>
            {
                println!(
                    "stop skipped: mode={mode}, pidfile={} not found",
                    pid_file.display()
                );
            }
            Err(err) => return Err(err),
        }
    }
    println!("stop completed: stopped={stopped}");
    Ok(())
}

fn spawn_http_connect_proxy_child(
    config: &ClientConfigFile,
    config_path: &Path,
) -> Result<Option<Child>, AppError> {
    let Some(http_port) = config.http_connect.port else {
        return Ok(None);
    };

    let exe = std::env::current_exe()?;
    let child = ProcessCommand::new(exe)
        .arg("http-connect-proxy")
        .arg("--config")
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    println!(
        "http connect proxy started: pid={}, bind={}:{}, upstream_socks5={}:{}",
        child.id(),
        config.http_connect.bind,
        http_port,
        config.socks5.bind,
        config.socks5.port
    );

    Ok(Some(child))
}
