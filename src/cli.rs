use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "rama-proxy",
    version,
    about = "Long-lived client/server SOCKS5 TCP/UDP proxy"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run or manage the remote tunnel server.
    Server(ServerCommand),
    /// Run or manage the local Clash-facing client.
    Client(ClientCommand),
    /// Run the internal HTTP CONNECT adapter.
    #[command(hide = true)]
    HttpConnectProxy(HttpConnectProxyCommand),
    /// Run the built-in web UI for observing a server process.
    Ui(UiCommand),
    /// Print version information.
    Version,
    /// Stop all background rama-proxy processes.
    Stop,
}

#[derive(Debug, Args)]
pub struct ServerCommand {
    #[command(subcommand)]
    pub action: Option<ModeAction>,
    #[arg(short = 'c', long, default_value = "config/server.toml")]
    pub config: PathBuf,
    /// Local admin socket used to query live server stats.
    #[arg(long, default_value = "config/rama-proxy-server.stats.sock")]
    pub stats_socket: PathBuf,
    /// Detach and run as a background daemon process.
    #[arg(long, default_value_t = false)]
    pub daemon: bool,
}

#[derive(Debug, Args)]
pub struct ClientCommand {
    #[command(subcommand)]
    pub action: Option<ModeAction>,
    #[arg(short = 'c', long, default_value = "config/client.toml")]
    pub config: PathBuf,
    /// Detach and run as a background daemon process.
    #[arg(long, default_value_t = false)]
    pub daemon: bool,
}

#[derive(Debug, Args)]
pub struct HttpConnectProxyCommand {
    #[arg(short = 'c', long, default_value = "config/client.toml")]
    pub config: PathBuf,
}

#[derive(Debug, Args)]
pub struct UiCommand {
    #[command(subcommand)]
    pub action: Option<UiAction>,
    #[arg(short = 'c', long, default_value = "config/ui.toml")]
    pub config: PathBuf,
    /// Detach and run as a background daemon process.
    #[arg(long, default_value_t = false)]
    pub daemon: bool,
    /// Bind address for the web UI.
    #[arg(long)]
    pub bind: Option<String>,
    /// Listen port for the web UI.
    #[arg(long)]
    pub port: Option<u16>,
    /// PID file of the target rama-proxy server process.
    #[arg(long)]
    pub pid_file: Option<PathBuf>,
    /// PID file of the built-in UI process.
    #[arg(long)]
    pub ui_pid_file: Option<PathBuf>,
    /// Local admin socket used to query live server stats.
    #[arg(long)]
    pub stats_socket: Option<PathBuf>,
    /// Sampling interval in milliseconds.
    #[arg(long)]
    pub interval_ms: Option<u64>,
}

#[derive(Debug, Subcommand)]
pub enum UiAction {
    /// Initialize a default UI TOML config file.
    Init {
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Stop the background UI process.
    Stop,
}

#[derive(Debug, Subcommand)]
pub enum ModeAction {
    /// Gracefully stop the background daemon.
    Stop,
    /// Initialize a default TOML config file.
    Init {
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Validate a config file.
    Check {
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
    },
    /// Print the latest server stats snapshot JSON.
    Stats {
        #[arg(long)]
        stats_socket: Option<PathBuf>,
    },
}
