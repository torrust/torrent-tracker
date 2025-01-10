use std::str::FromStr;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_api_client::v1::client::{headers_with_request_id, Client};
use torrust_tracker_lib::servers::apis::v1::context::stats::resources::Stats;
use torrust_tracker_primitives::peer::fixture::PeerBuilder;
use torrust_tracker_test_helpers::configuration;
use uuid::Uuid;

use crate::common::logging::{self, logs_contains_a_line_with};
use crate::servers::api::connection_info::{connection_with_invalid_token, connection_with_no_token};
use crate::servers::api::v1::asserts::{assert_stats, assert_token_not_valid, assert_unauthorized};
use crate::servers::api::Started;

#[tokio::test]
async fn should_allow_getting_tracker_statistics() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    env.add_torrent_peer(
        &InfoHash::from_str("9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d").unwrap(),
        &PeerBuilder::default().into(),
    );

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .get_tracker_statistics(Some(headers_with_request_id(request_id)))
        .await;

    assert_stats(
        response,
        Stats {
            torrents: 1,
            seeders: 1,
            completed: 0,
            leechers: 0,
            // TCP
            tcp4_connections_handled: 0,
            tcp4_announces_handled: 0,
            tcp4_scrapes_handled: 0,
            tcp6_connections_handled: 0,
            tcp6_announces_handled: 0,
            tcp6_scrapes_handled: 0,
            // UDP
            udp_requests_aborted: 0,
            udp_requests_banned: 0,
            udp_banned_ips_total: 0,
            udp_avg_connect_processing_time_ns: 0,
            udp_avg_announce_processing_time_ns: 0,
            udp_avg_scrape_processing_time_ns: 0,
            // UDPv4
            udp4_requests: 0,
            udp4_connections_handled: 0,
            udp4_announces_handled: 0,
            udp4_scrapes_handled: 0,
            udp4_responses: 0,
            udp4_errors_handled: 0,
            // UDPv6
            udp6_requests: 0,
            udp6_connections_handled: 0,
            udp6_announces_handled: 0,
            udp6_scrapes_handled: 0,
            udp6_responses: 0,
            udp6_errors_handled: 0,
        },
    )
    .await;

    env.stop().await;
}

#[tokio::test]
async fn should_not_allow_getting_tracker_statistics_for_unauthenticated_users() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let request_id = Uuid::new_v4();

    let response = Client::new(connection_with_invalid_token(env.get_connection_info().bind_address.as_str()))
        .get_tracker_statistics(Some(headers_with_request_id(request_id)))
        .await;

    assert_token_not_valid(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    let request_id = Uuid::new_v4();

    let response = Client::new(connection_with_no_token(env.get_connection_info().bind_address.as_str()))
        .get_tracker_statistics(Some(headers_with_request_id(request_id)))
        .await;

    assert_unauthorized(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    env.stop().await;
}
