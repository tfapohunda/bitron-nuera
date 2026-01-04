use std::fmt::{Display, Formatter};

/// A wrapper type for upstream authentication tokens.
///
/// This type is used to pass the mapped upstream token through request
/// extensions after client authentication has been validated.
#[derive(Debug, Clone)]
pub struct UpstreamToken {
    /// The actual token string used to authenticate with the upstream server.
    token: String,
}

impl UpstreamToken {
    /// Creates a new upstream token from a string slice.
    pub fn new(token: &str) -> Self {
        Self {
            token: token.to_owned(),
        }
    }
}

impl Display for UpstreamToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.token)
    }
}
