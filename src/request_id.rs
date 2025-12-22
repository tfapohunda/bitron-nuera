use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct RequestId(String);

impl RequestId {
    pub fn new() -> Self {
        let id = Uuid::new_v4().to_string();
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
