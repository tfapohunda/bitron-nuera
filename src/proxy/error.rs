use axum::response::{IntoResponse, Response};
use http::StatusCode;
use thiserror::Error;

use crate::config::ConfigError;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("failed to create service: {0}")]
    Service(#[from] std::io::Error),
    #[error("failed to parse address: {0}")]
    Address(#[from] std::net::AddrParseError),
    #[error("failed to convert config to app state: {0}")]
    Config(#[from] ConfigError),
    #[error("failed to convert body to bytes: {0}")]
    BodyToBytes(#[from] axum_core::Error),
    #[error("failed to send upstream request: {0}")]
    UpstreamRequest(#[from] reqwest::Error),
    #[error("failed to build response: {0}")]
    ResponseBuild(#[from] http::Error),
    #[error("unauthorized")]
    Unauthorized,
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let status = match &self {
            ProxyError::Service(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ProxyError::Address(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ProxyError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ProxyError::BodyToBytes(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ProxyError::UpstreamRequest(_) => StatusCode::BAD_GATEWAY,
            ProxyError::ResponseBuild(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ProxyError::Unauthorized => StatusCode::UNAUTHORIZED,
        };
        (status, self.to_string()).into_response()
    }
}

pub type Result<T> = std::result::Result<T, ProxyError>;
