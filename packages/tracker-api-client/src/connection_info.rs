#[must_use]
pub fn connection_with_invalid_token(bind_address: &str) -> ConnectionInfo {
    ConnectionInfo::authenticated(bind_address, "invalid token")
}

#[must_use]
pub fn connection_with_no_token(bind_address: &str) -> ConnectionInfo {
    ConnectionInfo::anonymous(bind_address)
}

#[derive(Clone)]
pub struct ConnectionInfo {
    pub bind_address: String,
    pub api_token: Option<String>,
}

impl ConnectionInfo {
    #[must_use]
    pub fn authenticated(bind_address: &str, api_token: &str) -> Self {
        Self {
            bind_address: bind_address.to_string(),
            api_token: Some(api_token.to_string()),
        }
    }

    #[must_use]
    pub fn anonymous(bind_address: &str) -> Self {
        Self {
            bind_address: bind_address.to_string(),
            api_token: None,
        }
    }
}
