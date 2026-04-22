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
    /// Run the built-in web UI for observing a server process.
    Ui(UiCommand),
    /// Print version information.
    Version,
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
pub struct UiCommand {
    /// Bind address for the web UI.
    #[arg(long, default_value = "127.0.0.1")]
    pub bind: String,
    /// Listen port for the web UI.
    #[arg(long, default_value_t = 19091)]
    pub port: u16,
    /// PID file of the target rama-proxy server process.
    #[arg(long, default_value = "config/rama-proxy-server.pid")]
    pub pid_file: PathBuf,
    /// Local admin socket used to query live server stats.
    #[arg(long, default_value = "config/rama-proxy-server.stats.sock")]
    pub stats_socket: PathBuf,
    /// Sampling interval in milliseconds.
    #[arg(long, default_value_t = 2000)]
    pub interval_ms: u64,
}

#[derive(Debug, Subcommand)]
pub enum ModeAction {
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
