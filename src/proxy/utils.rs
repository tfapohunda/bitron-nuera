use axum::{
    body::Body,
    http::{HeaderMap, Request, Uri},
};
use reqwest::{
    RequestBuilder,
    header::{AUTHORIZATION, HOST},
};
use url::Url;

use crate::proxy::AppState;
use crate::proxy::error::{ProxyError, Result};

pub fn extract_auth_token(state: &AppState, headers: &HeaderMap) -> Result<String> {
    let auth_header = headers.get(AUTHORIZATION).ok_or(ProxyError::Unauthorized)?;
    let auth_str = auth_header.to_str().map_err(|_| ProxyError::Unauthorized)?;

    let token = auth_str
        .strip_prefix("Bearer ")
        .ok_or(ProxyError::Unauthorized)?;

    state
        .tokens
        .get(token)
        .cloned()
        .ok_or(ProxyError::Unauthorized)
}

pub fn build_upstream_url(base_url: &Url, path: &Uri) -> Url {
    let mut url = base_url.clone();
    if let Some(path_query) = path.path_and_query() {
        url.set_path(path_query.path());
        url.set_query(path_query.query());
    }
    url
}

pub async fn build_upstream_request(
    state: &AppState,
    req: Request<Body>,
) -> Result<RequestBuilder> {
    let (parts, body) = req.into_parts();
    let uri = parts.uri.clone();
    let method = parts.method.clone();
    let headers = parts.headers.clone();

    let upstream_token = extract_auth_token(state, &headers)?;
    let upstream_url = build_upstream_url(&state.upstream_url, &uri);
    let body_bytes = axum::body::to_bytes(body, usize::MAX).await?;

    let mut upstream_req = state
        .client
        .client
        .request(method.clone(), upstream_url)
        .body(body_bytes);

    for (name, value) in headers.iter() {
        if name == AUTHORIZATION || name == HOST {
            continue;
        }
        upstream_req = upstream_req.header(name, value);
    }

    Ok(upstream_req.header(AUTHORIZATION, format!("Bearer {}", upstream_token)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use http::HeaderMap;
    use std::collections::HashMap;
    use std::num::NonZeroU32;

    use crate::proxy::RateLimiterClient;
    use crate::upstream::UpstreamClient;

    fn create_test_app_state() -> AppState {
        let mut tokens = HashMap::new();
        tokens.insert("client_token".to_string(), "upstream_token".to_string());
        tokens.insert("client_token_2".to_string(), "upstream_token_2".to_string());

        AppState {
            upstream_url: Url::parse("https://api.upstream.com").unwrap(),
            tokens,
            client: UpstreamClient::new().unwrap(),
            rate_limiter: RateLimiterClient::new(NonZeroU32::new(100).unwrap()),
        }
    }

    // ==================== build_upstream_url tests ====================

    #[test]
    fn test_build_upstream_url_with_path() {
        let base_url = Url::parse("https://api.upstream.com").unwrap();
        let uri: Uri = "/v1/users".parse().unwrap();

        let result = build_upstream_url(&base_url, &uri);

        assert_eq!(result.as_str(), "https://api.upstream.com/v1/users");
    }

    #[test]
    fn test_build_upstream_url_with_path_and_query() {
        let base_url = Url::parse("https://api.upstream.com").unwrap();
        let uri: Uri = "/v1/users?page=1&limit=10".parse().unwrap();

        let result = build_upstream_url(&base_url, &uri);

        assert_eq!(
            result.as_str(),
            "https://api.upstream.com/v1/users?page=1&limit=10"
        );
    }

    #[test]
    fn test_build_upstream_url_with_base_path() {
        let base_url = Url::parse("https://api.upstream.com/api/v2").unwrap();
        let uri: Uri = "/users/123".parse().unwrap();

        let result = build_upstream_url(&base_url, &uri);

        // The path from uri replaces the base path
        assert_eq!(result.as_str(), "https://api.upstream.com/users/123");
    }

    #[test]
    fn test_build_upstream_url_root_path() {
        let base_url = Url::parse("https://api.upstream.com").unwrap();
        let uri: Uri = "/".parse().unwrap();

        let result = build_upstream_url(&base_url, &uri);

        assert_eq!(result.as_str(), "https://api.upstream.com/");
    }

    // ==================== extract_upstream_token tests ====================

    #[test]
    fn test_extract_upstream_token_valid() {
        let state = create_test_app_state();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer client_token".parse().unwrap());

        let result = extract_auth_token(&state, &headers);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "upstream_token");
    }

    #[test]
    fn test_extract_upstream_token_different_token() {
        let state = create_test_app_state();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer client_token_2".parse().unwrap());

        let result = extract_auth_token(&state, &headers);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "upstream_token_2");
    }

    #[test]
    fn test_extract_upstream_token_missing_header() {
        let state = create_test_app_state();
        let headers = HeaderMap::new();

        let result = extract_auth_token(&state, &headers);

        assert!(result.is_err());
        assert!(matches!(result, Err(ProxyError::Unauthorized)));
    }

    #[test]
    fn test_extract_upstream_token_missing_bearer_prefix() {
        let state = create_test_app_state();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "client_token".parse().unwrap());

        let result = extract_auth_token(&state, &headers);

        assert!(result.is_err());
        assert!(matches!(result, Err(ProxyError::Unauthorized)));
    }

    #[test]
    fn test_extract_upstream_token_unknown_token() {
        let state = create_test_app_state();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer unknown_token".parse().unwrap());

        let result = extract_auth_token(&state, &headers);

        assert!(result.is_err());
        assert!(matches!(result, Err(ProxyError::Unauthorized)));
    }

    #[test]
    fn test_extract_upstream_token_basic_auth_rejected() {
        let state = create_test_app_state();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Basic dXNlcjpwYXNz".parse().unwrap());

        let result = extract_auth_token(&state, &headers);

        assert!(result.is_err());
        assert!(matches!(result, Err(ProxyError::Unauthorized)));
    }

    // ==================== build_upstream_request tests ====================

    #[tokio::test]
    async fn test_build_upstream_request_valid() {
        let state = create_test_app_state();
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/users")
            .header(AUTHORIZATION, "Bearer client_token")
            .header("X-Custom-Header", "custom_value")
            .body(Body::empty())
            .unwrap();

        let result = build_upstream_request(&state, req).await;

        assert!(result.is_ok());
        let request_builder = result.unwrap();
        let built_request = request_builder.build().unwrap();

        assert_eq!(built_request.method(), Method::GET);
        assert_eq!(
            built_request.url().as_str(),
            "https://api.upstream.com/api/users"
        );
        assert_eq!(
            built_request.headers().get(AUTHORIZATION).unwrap(),
            "Bearer upstream_token"
        );
        assert_eq!(
            built_request.headers().get("X-Custom-Header").unwrap(),
            "custom_value"
        );
    }

    #[tokio::test]
    async fn test_build_upstream_request_post_with_body() {
        let state = create_test_app_state();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/data")
            .header(AUTHORIZATION, "Bearer client_token")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"key": "value"}"#))
            .unwrap();

        let result = build_upstream_request(&state, req).await;

        assert!(result.is_ok());
        let request_builder = result.unwrap();
        let built_request = request_builder.build().unwrap();

        assert_eq!(built_request.method(), Method::POST);
        assert_eq!(
            built_request.headers().get("Content-Type").unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn test_build_upstream_request_strips_host_header() {
        let state = create_test_app_state();
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/users")
            .header(AUTHORIZATION, "Bearer client_token")
            .header(HOST, "original.host.com")
            .body(Body::empty())
            .unwrap();

        let result = build_upstream_request(&state, req).await;

        assert!(result.is_ok());
        let request_builder = result.unwrap();
        let built_request = request_builder.build().unwrap();

        // HOST header should not be forwarded (reqwest sets it automatically)
        assert!(built_request.headers().get(HOST).is_none());
    }

    #[tokio::test]
    async fn test_build_upstream_request_unauthorized() {
        let state = create_test_app_state();
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/users")
            // No AUTHORIZATION header
            .body(Body::empty())
            .unwrap();

        let result = build_upstream_request(&state, req).await;

        assert!(result.is_err());
        assert!(matches!(result, Err(ProxyError::Unauthorized)));
    }

    #[tokio::test]
    async fn test_build_upstream_request_with_query_params() {
        let state = create_test_app_state();
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/search?q=test&page=2")
            .header(AUTHORIZATION, "Bearer client_token")
            .body(Body::empty())
            .unwrap();

        let result = build_upstream_request(&state, req).await;

        assert!(result.is_ok());
        let request_builder = result.unwrap();
        let built_request = request_builder.build().unwrap();

        assert_eq!(
            built_request.url().as_str(),
            "https://api.upstream.com/api/search?q=test&page=2"
        );
    }
}
