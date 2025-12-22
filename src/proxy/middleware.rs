use axum::{
    body::Body,
    extract::Request as ExtractRequest,
    http::{HeaderValue, Response},
    middleware::Next,
};
use http::HeaderName;
use tracing::Instrument;

use crate::proxy::request_id::RequestId;

static REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

pub async fn request_id(mut req: ExtractRequest, next: Next) -> Response<Body> {
    let request_id = RequestId::new();
    req.extensions_mut().insert(request_id.clone());

    let mut response = next.run(req).await;

    response.headers_mut().insert(
        REQUEST_ID_HEADER.clone(),
        HeaderValue::from_str(request_id.as_str()).unwrap(),
    );

    response
}

pub async fn observability(req: ExtractRequest, next: Next) -> Response<Body> {
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
        "http.request",
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
