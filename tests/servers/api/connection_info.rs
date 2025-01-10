use torrust_tracker_api_client::connection_info::{ConnectionInfo, Origin};

pub fn connection_with_invalid_token(origin: Origin) -> ConnectionInfo {
    ConnectionInfo::authenticated(origin, "invalid token")
}

pub fn connection_with_no_token(origin: Origin) -> ConnectionInfo {
    ConnectionInfo::anonymous(origin)
}
