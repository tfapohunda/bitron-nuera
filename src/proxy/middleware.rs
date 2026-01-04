use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, Response},
    middleware::Next,
};
use http::HeaderName;
use tracing::Instrument;

use crate::proxy::error::Result;
use crate::proxy::request_id::RequestId;

/// The HTTP header name used for request IDs.
static REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Axum middleware that generates and attaches a unique request ID.
///
/// Generates a UUID-based request ID, stores it in the request extensions
/// for use by other handlers and middleware, and adds it to the response
/// headers as `X-Request-Id`.
///
/// # Errors
///
/// Returns an error if the request ID cannot be converted to a valid header value.
pub async fn request_id(mut req: Request, next: Next) -> Result<Response<Body>> {
    tracing::debug!("Request ID middleware");
    let request_id = RequestId::new();
    req.extensions_mut().insert(request_id.clone());

    let mut response = next.run(req).await;

    response.headers_mut().insert(
        REQUEST_ID_HEADER.clone(),
        HeaderValue::from_str(request_id.as_str())?,
    );

    Ok(response)
}

/// Axum middleware that provides request logging and tracing.
///
/// Creates a tracing span for each request with the request ID, HTTP method,
/// and path. Logs request completion with latency and status code information.
pub async fn observability(req: Request, next: Next) -> Response<Body> {
    tracing::debug!("Observability middleware");
    let start = std::time::Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();

    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.as_str())
        .unwrap_or_else(|| "<missing>")
        .to_owned();

    let span = tracing::info_span!(
        "request",
        request_id = %request_id,
        method = %method,
        path = %uri.path(),
    );

    let response = async { next.run(req).await }.instrument(span).await;
    let elapsed_ms = start.elapsed().as_millis();
    let status = response.status().as_u16();

    tracing::info!(
        request_id = %request_id,
        method = %method,
        latency_ms = elapsed_ms,
        path = %uri.path(),
        status = status,
        "request"
    );

    response
}
