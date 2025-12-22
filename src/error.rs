use thiserror::Error;

use crate::{config, proxy};

#[derive(Debug, Error)]
pub enum AppError {
    #[error("failed to create service: {0}")]
    MakeService(#[from] proxy::ProxyError),
    #[error("failed to parse config: {0}")]
    Config(#[from] config::ConfigError),
}

pub type Result<T> = std::result::Result<T, AppError>;
