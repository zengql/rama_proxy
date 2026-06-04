mod cli;
mod client_runtime;
mod config;
mod error;
mod logging;
mod server_runtime;
mod server_stats;
mod tls;
mod tunnel;
mod ui;

use std::ffi::OsString;
use std::path::Path;

use clap::Parser;

use crate::cli::{Cli, ClientCommand, Command, ModeAction, ServerCommand, UiCommand};
use crate::config::{ClientConfigFile, ServerConfigFile};
use crate::error::AppError;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli = Cli::parse();

    match cli.command {
        Command::Server(cmd) => handle_server(cmd).await,
        Command::Client(cmd) => handle_client(cmd).await,
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
    }
}

async fn handle_server(cmd: ServerCommand) -> Result<(), AppError> {
    match cmd.action {
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
                let extra_args = vec![
                    OsString::from("--stats-socket"),
                    cmd.stats_socket.as_os_str().to_os_string(),
                ];
                return spawn_daemon("server", &cmd.config, &extra_args);
            }
            let config = ServerConfigFile::from_path(&cmd.config)?;
            config.validate()?;
            logging::init(&config.log.level)?;
            server_runtime::run(config, cmd.stats_socket).await
        }
    }
}

async fn handle_client(cmd: ClientCommand) -> Result<(), AppError> {
    match cmd.action {
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
            client_runtime::run(config).await
        }
    }
}

async fn handle_ui(cmd: UiCommand) -> Result<(), AppError> {
    logging::init("info")?;
    ui::run(cmd).await
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
