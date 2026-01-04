use uuid::Uuid;

/// A unique identifier for tracking requests through the system.
///
/// Generated as a UUID v4 and stored as a string for easy serialization
/// and inclusion in logs and response headers.
#[derive(Clone, Debug)]
pub struct RequestId(String);

impl RequestId {
    /// Generates a new unique request ID using UUID v4.
    pub fn new() -> Self {
        let id = Uuid::new_v4().to_string();
        Self(id)
    }

    /// Returns the request ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
