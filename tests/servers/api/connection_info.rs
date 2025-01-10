use torrust_tracker_api_client::connection_info::ConnectionInfo;

pub fn connection_with_invalid_token(bind_address: &str) -> ConnectionInfo {
    ConnectionInfo::authenticated(bind_address, "invalid token")
}

pub fn connection_with_no_token(bind_address: &str) -> ConnectionInfo {
    ConnectionInfo::anonymous(bind_address)
}
