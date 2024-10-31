//! Logging for UDP Tracker requests and responses.

use std::net::SocketAddr;
use std::time::Duration;

use aquatic_udp_protocol::{Request, Response, TransactionId};
use bittorrent_primitives::info_hash::InfoHash;

use super::handlers::RequestId;
use crate::servers::udp::UDP_TRACKER_LOG_TARGET;

pub fn log_request(request: &Request, request_id: &RequestId, server_socket_addr: &SocketAddr) {
    let action = map_action_name(request);

    match &request {
        Request::Connect(connect_request) => {
            let transaction_id = connect_request.transaction_id;
            let transaction_id_str = transaction_id.0.to_string();

            tracing::span!(
                target: UDP_TRACKER_LOG_TARGET,
                tracing::Level::INFO, "request", server_socket_addr = %server_socket_addr, action = %action, transaction_id = %transaction_id_str, request_id = %request_id);
        }
        Request::Announce(announce_request) => {
            let transaction_id = announce_request.transaction_id;
            let transaction_id_str = transaction_id.0.to_string();
            let connection_id_str = announce_request.connection_id.0.to_string();
            let info_hash_str = InfoHash::from_bytes(&announce_request.info_hash.0).to_hex_string();

            tracing::span!(
                target: UDP_TRACKER_LOG_TARGET,
                tracing::Level::INFO, "request", server_socket_addr = %server_socket_addr, action = %action, transaction_id = %transaction_id_str, request_id = %request_id, connection_id = %connection_id_str, info_hash = %info_hash_str);
        }
        Request::Scrape(scrape_request) => {
            let transaction_id = scrape_request.transaction_id;
            let transaction_id_str = transaction_id.0.to_string();
            let connection_id_str = scrape_request.connection_id.0.to_string();

            tracing::span!(
                target: UDP_TRACKER_LOG_TARGET,
                tracing::Level::INFO,
                "request",
                server_socket_addr = %server_socket_addr,
                action = %action,
                transaction_id = %transaction_id_str,
                request_id = %request_id,
                connection_id = %connection_id_str);
        }
    };
}

fn map_action_name(udp_request: &Request) -> String {
    match udp_request {
        Request::Connect(_connect_request) => "CONNECT".to_owned(),
        Request::Announce(_announce_request) => "ANNOUNCE".to_owned(),
        Request::Scrape(_scrape_request) => "SCRAPE".to_owned(),
    }
}

pub fn log_response(
    _response: &Response,
    transaction_id: &TransactionId,
    request_id: &RequestId,
    server_socket_addr: &SocketAddr,
    latency: Duration,
) {
    tracing::span!(
        target: UDP_TRACKER_LOG_TARGET,
        tracing::Level::INFO, 
        "response", 
        server_socket_addr = %server_socket_addr, 
        transaction_id = %transaction_id.0.to_string(), 
        request_id = %request_id,
        latency_ms = %latency.as_millis());
}

pub fn log_bad_request(request_id: &RequestId) {
    tracing::span!(
        target: UDP_TRACKER_LOG_TARGET,
        tracing::Level::INFO, "bad request", request_id = %request_id);
}

pub fn log_error_response(request_id: &RequestId) {
    tracing::span!(
        target: UDP_TRACKER_LOG_TARGET,
        tracing::Level::INFO, "response", request_id = %request_id);
}
