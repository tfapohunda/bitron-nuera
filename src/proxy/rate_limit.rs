use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::Response,
    middleware::Next,
};
use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};

use crate::proxy::utils::extract_auth_token;
use crate::proxy::{AppState, ProxyError, Result};

pub type TokenRateLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

#[derive(Debug)]
pub struct RateLimiterClient {
    limiter: TokenRateLimiter,
}

impl RateLimiterClient {
    pub fn new(requests_per_minute: NonZeroU32) -> Self {
        let quota = Quota::per_minute(requests_per_minute);
        let rate_limiter = RateLimiter::keyed(quota);
        Self {
            limiter: rate_limiter,
        }
    }

    pub fn check_key(&self, key: &str) -> Result<()> {
        self.limiter
            .check_key(&key.to_string())
            .map_err(|_| ProxyError::RateLimitExceeded)
    }
}

pub async fn rate_limit(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response<Body>> {
    tracing::debug!("Rate limiting middleware");
    let client_token = extract_auth_token(&state, req.headers())
        .inspect_err(|_| tracing::error!("failed to extract auth token"))?;

    state
        .rate_limiter
        .check_key(&client_token)
        .inspect_err(|_| {
            tracing::warn!(
                client_token = %client_token,
                "rate limit exceeded"
            )
        })?;

    Ok(next.run(req).await)
}
