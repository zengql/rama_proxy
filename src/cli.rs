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
    /// Print version information.
    Version,
}

#[derive(Debug, Args)]
pub struct ServerCommand {
    #[command(subcommand)]
    pub action: Option<ModeAction>,
    #[arg(short = 'c', long, default_value = "config/server.toml")]
    pub config: PathBuf,
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
}
