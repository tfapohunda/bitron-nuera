//! Proxy module containing the core proxy server implementation.
//!
//! This module provides the HTTP reverse proxy functionality including:
//! - Request proxying to upstream servers
//! - Token-based authentication and authorization
//! - Rate limiting per client token
//! - Request/response middleware (observability, request IDs)

mod app_state;
mod error;
mod middleware;
mod rate_limit;
mod request_id;
mod server;
mod token;
mod utils;

pub use app_state::*;
pub use error::*;
pub use rate_limit::*;
pub use server::*;
pub use token::*;
