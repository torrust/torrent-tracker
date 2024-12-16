use std::str::FromStr;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker::servers::apis::v1::context::stats::resources::Stats;
use torrust_tracker_primitives::peer::fixture::PeerBuilder;
use torrust_tracker_test_helpers::configuration;
use tracing::level_filters::LevelFilter;

use crate::common::logging::{tracing_stderr_init, INIT};
use crate::servers::api::connection_info::{connection_with_invalid_token, connection_with_no_token};
use crate::servers::api::v1::asserts::{assert_stats, assert_token_not_valid, assert_unauthorized};
use crate::servers::api::v1::client::Client;
use crate::servers::api::Started;

#[tokio::test]
async fn should_allow_getting_tracker_statistics() {
    INIT.call_once(|| {
        tracing_stderr_init(LevelFilter::ERROR);
    });

    let env = Started::new(&configuration::ephemeral().into()).await;

    env.add_torrent_peer(
        &InfoHash::from_str("9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d").unwrap(),
        &PeerBuilder::default().into(),
    );

    let response = Client::new(env.get_connection_info()).get_tracker_statistics().await;

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
            udp4_requests: 0,
            udp4_connections_handled: 0,
            udp4_announces_handled: 0,
            udp4_scrapes_handled: 0,
            udp4_responses: 0,
            udp4_errors_handled: 0,
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
    INIT.call_once(|| {
        tracing_stderr_init(LevelFilter::ERROR);
    });

    let env = Started::new(&configuration::ephemeral().into()).await;

    let response = Client::new(connection_with_invalid_token(env.get_connection_info().bind_address.as_str()))
        .get_tracker_statistics()
        .await;

    assert_token_not_valid(response).await;

    let response = Client::new(connection_with_no_token(env.get_connection_info().bind_address.as_str()))
        .get_tracker_statistics()
        .await;

    assert_unauthorized(response).await;

    env.stop().await;
}
