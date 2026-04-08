use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("toml deserialize error: {0}")]
    TomlDeserialize(#[from] toml::de::Error),
    #[error("toml serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
    #[error("config already exists: {0}")]
    ConfigAlreadyExists(String),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("boxed error: {0}")]
    Boxed(String),
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
}
