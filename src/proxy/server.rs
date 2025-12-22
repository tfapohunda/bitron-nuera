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

use crate::{
    config::Config,
    proxy::{
        AppState,
        error::{ProxyError, Result},
        middleware::{observability, request_id},
        rate_limit,
        utils::build_upstream_request,
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
        let app_state: AppState = self
            .config
            .clone()
            .try_into()
            .inspect_err(|_| tracing::error!("config validation failed"))?;
        let app = Router::new()
            .route("/", any(Self::proxy))
            .route("/{*wildcard}", any(Self::proxy))
            .route("/health", any(Self::health))
            .fallback(any(Self::fallback))
            .with_state(app_state.clone())
            .layer(middleware::from_fn_with_state(app_state, rate_limit))
            .layer(middleware::from_fn(observability))
            .layer(middleware::from_fn(request_id));

        let addr = self.config.server.address.parse::<SocketAddr>()?;
        tracing::info!("Server listening on {}", addr);

        axum_server::bind(addr)
            .serve(app.into_make_service())
            .await?;

        Ok(())
    }

    async fn proxy(State(state): State<AppState>, req: Request<Body>) -> Result<Response> {
        tracing::debug!("Proxy request");
        let upstream_req = build_upstream_request(&state, req).await?;
        let response = Self::send_upstream_request(upstream_req).await?;
        Self::build_downstream_response(response).await
    }

    async fn fallback() -> impl IntoResponse {
        tracing::error!("Fallback not expected");
        StatusCode::NOT_FOUND
    }

    async fn health() -> impl IntoResponse {
        tracing::debug!("Health request");
        (StatusCode::OK, "ok")
    }

    async fn send_upstream_request(upstream_req: RequestBuilder) -> Result<reqwest::Response> {
        let response = upstream_req
            .send()
            .await
            .map_err(ProxyError::UpstreamRequest)?;
        Ok(response)
    }

    async fn build_downstream_response(response: reqwest::Response) -> Result<Response> {
        let status = response.status();
        let resp_headers = response.headers().clone();
        let resp_body = response
            .bytes()
            .await
            .map_err(ProxyError::UpstreamRequest)?;

        let mut response = axum::response::Response::builder().status(status);
        for (name, value) in resp_headers.iter() {
            response = response.header(name, value);
        }
        let resp = response
            .body(Body::from(resp_body))
            .map_err(ProxyError::ResponseBuild)?;

        Ok(resp)
    }
}
