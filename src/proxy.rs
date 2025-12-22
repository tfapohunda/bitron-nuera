use axum::{Router, extract::Path, response::IntoResponse, routing::any};
use reqwest::StatusCode;
use std::net::SocketAddr;
use thiserror::Error;

use crate::config::Config;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("failed to create service: {0}")]
    Service(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ProxyError>;

pub struct Proxy {
    #[expect(dead_code)]
    config: Config,
}

impl Proxy {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    async fn proxy(Path(path): Path<String>) -> impl IntoResponse {
        tracing::debug!(?path, "Proxy request");
        StatusCode::OK
    }

    async fn proxy_root() -> impl IntoResponse {
        tracing::debug!("Proxy request root");
        StatusCode::OK
    }

    async fn fallback() -> impl IntoResponse {
        tracing::error!("Fallback not expected");
        StatusCode::NOT_FOUND
    }

    async fn health() -> impl IntoResponse {
        tracing::debug!("Health request");
        StatusCode::OK
    }
}

impl Proxy {
    pub async fn start(&self) -> Result<()> {
        let app = Router::new()
            .route("/", any(Self::proxy_root))
            .route("/{*wildcard}", any(Self::proxy))
            .route("/health", any(Self::health))
            .fallback(any(Self::fallback));

        let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
        tracing::debug!("Server listening on {}", addr);

        axum_server::bind(addr)
            .serve(app.into_make_service())
            .await?;

        tracing::debug!("Proxy server done");
        Ok(())
    }
}
