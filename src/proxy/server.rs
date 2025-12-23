use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self},
    response::{IntoResponse, Response},
    routing::any,
};
use reqwest::RequestBuilder;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::{
    config::Config,
    proxy::{
        AppState,
        error::{ProxyError, Result},
        middleware::{observability, request_id},
        rate_limit,
        utils::{build_downstream_response, build_upstream_request},
    },
};

pub struct ProxyServer {
    config: Config,
}

impl ProxyServer {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn start(&self) -> Result<()> {
        let app_state: Arc<AppState> = Arc::new(
            self.config
                .clone()
                .try_into()
                .inspect_err(|_| tracing::error!("config validation failed"))?,
        );

        let rate_limited_routes = Router::new()
            .route("/", any(Self::proxy))
            .route("/{*wildcard}", any(Self::proxy))
            .fallback(any(Self::fallback))
            .layer(middleware::from_fn_with_state(
                Arc::clone(&app_state),
                rate_limit,
            ));

        let app = Router::new()
            .route("/health", any(Self::health))
            .merge(rate_limited_routes)
            .with_state(app_state)
            .layer(middleware::from_fn(observability))
            .layer(middleware::from_fn(request_id));

        let addr = self.config.server.address.parse::<SocketAddr>()?;
        tracing::info!("Server listening on {}", addr);

        axum_server::bind(addr)
            .serve(app.into_make_service())
            .await?;

        Ok(())
    }

    async fn proxy(State(state): State<Arc<AppState>>, req: Request<Body>) -> Result<Response> {
        tracing::debug!("Proxy request");
        let upstream_req = build_upstream_request(&state, req)?;
        let response = Self::send_upstream_request(upstream_req).await?;
        let result = build_downstream_response(response)?;
        Ok(result)
    }

    async fn fallback() -> impl IntoResponse {
        tracing::error!("Fallback not expected");
        StatusCode::NOT_FOUND
    }

    async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
        tracing::debug!("Health request");
        match state
            .client
            .client
            .get(state.upstream_url.clone())
            .send()
            .await
        {
            Ok(_) => (StatusCode::OK, "ok"),
            Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "upstream unavailable"),
        }
    }

    async fn send_upstream_request(upstream_req: RequestBuilder) -> Result<reqwest::Response> {
        let response = upstream_req
            .send()
            .await
            .map_err(ProxyError::UpstreamRequest)?;
        Ok(response)
    }
}
