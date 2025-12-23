use std::fmt::{Display, Formatter};

#[derive(Debug, Clone)]
pub struct UpstreamToken {
    token: String,
}

impl UpstreamToken {
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
