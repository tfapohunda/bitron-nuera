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

use crate::proxy::{AppState, ProxyError, Result};
use crate::proxy::{UpstreamToken, utils::extract_auth_token};

/// Type alias for a keyed rate limiter that tracks request rates per token.
pub type TokenRateLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

/// A rate limiter client that enforces per-token request limits.
///
/// Uses the Governor crate's token bucket algorithm to limit requests
/// on a per-minute basis for each client token.
#[derive(Debug)]
pub struct RateLimiterClient {
    /// The underlying keyed rate limiter.
    limiter: TokenRateLimiter,
}

impl RateLimiterClient {
    /// Creates a new rate limiter with the specified requests-per-minute quota.
    pub fn new(requests_per_minute: NonZeroU32) -> Self {
        let quota = Quota::per_minute(requests_per_minute);
        let rate_limiter = RateLimiter::keyed(quota);
        Self {
            limiter: rate_limiter,
        }
    }

    /// Checks if a request is allowed for the given key.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::RateLimitExceeded`] if the rate limit has been exceeded.
    pub fn check_key(&self, key: &str) -> Result<()> {
        self.limiter
            .check_key(&key.to_string())
            .map_err(|_| ProxyError::RateLimitExceeded)
    }
}

/// Axum middleware that enforces rate limiting based on client tokens.
///
/// Extracts the client token from the request, checks the rate limit,
/// and injects the corresponding upstream token into the request extensions
/// for use by downstream handlers.
///
/// # Errors
///
/// Returns an error response if:
/// - The client token cannot be extracted (unauthorized)
/// - The rate limit has been exceeded for the token
pub async fn rate_limit(
    State(state): State<Arc<AppState>>,
    mut req: Request,
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

    req.extensions_mut()
        .insert(UpstreamToken::new(&client_token));

    Ok(next.run(req).await)
}
