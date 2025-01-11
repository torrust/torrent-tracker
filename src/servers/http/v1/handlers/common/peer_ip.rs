//! Logic to convert peer IP resolution errors into responses.
//!
//! The HTTP tracker may fail to resolve the peer IP address. This module
//! contains the logic to convert those
//! [`PeerIpResolutionError`](bittorrent_http_protocol::v1::services::peer_ip_resolver::PeerIpResolutionError)
//! errors into responses.

#[cfg(test)]
mod tests {
    use std::panic::Location;

    use bittorrent_http_protocol::v1::responses;
    use bittorrent_http_protocol::v1::services::peer_ip_resolver::PeerIpResolutionError;

    fn assert_error_response(error: &responses::error::Error, error_message: &str) {
        assert!(
            error.failure_reason.contains(error_message),
            "Error response does not contain message: '{error_message}'. Error: {error:?}"
        );
    }

    #[test]
    fn it_should_map_a_peer_ip_resolution_error_into_an_error_response() {
        let response = responses::error::Error::from(PeerIpResolutionError::MissingRightMostXForwardedForIp {
            location: Location::caller(),
        });

        assert_error_response(&response, "Error resolving peer IP");
    }
}
