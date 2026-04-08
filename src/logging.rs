use tracing_subscriber::EnvFilter;

use crate::error::AppError;

pub fn init(level: &str) -> Result<(), AppError> {
    let filter = EnvFilter::try_new(level.to_string())
        .or_else(|_| EnvFilter::try_new("info"))
        .map_err(|err| AppError::InvalidConfig(format!("invalid log.level: {err}")))?;

    tracing_subscriber::fmt().with_env_filter(filter).init();
    Ok(())
}
