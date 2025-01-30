// UDP tracker documentation:
//
// BEP 15. UDP Tracker Protocol for BitTorrent
// https://www.bittorrent.org/beps/bep_0015.html

use core::panic;

use aquatic_udp_protocol::{ConnectRequest, ConnectionId, Response, TransactionId};
use bittorrent_tracker_client::udp::client::UdpTrackerClient;
use torrust_tracker_configuration::DEFAULT_TIMEOUT;
use torrust_tracker_lib::shared::bit_torrent::tracker::udp::MAX_PACKET_SIZE;
use torrust_tracker_test_helpers::configuration;

use crate::common::logging;
use crate::servers::udp::asserts::get_error_response_message;
use crate::servers::udp::Started;

fn empty_udp_request() -> [u8; MAX_PACKET_SIZE] {
    [0; MAX_PACKET_SIZE]
}

async fn send_connection_request(transaction_id: TransactionId, client: &UdpTrackerClient) -> ConnectionId {
    let connect_request = ConnectRequest { transaction_id };

    match client.send(connect_request.into()).await {
        Ok(_) => (),
        Err(err) => panic!("{err}"),
    }

    let response = match client.receive().await {
        Ok(response) => response,
        Err(err) => panic!("{err}"),
    };

    match response {
        Response::Connect(connect_response) => connect_response.connection_id,
        _ => panic!("error connecting to udp server {:?}", response),
    }
}

#[tokio::test]
async fn should_return_a_bad_request_response_when_the_client_sends_an_empty_request() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let client = match UdpTrackerClient::new(env.bind_address(), DEFAULT_TIMEOUT).await {
        Ok(udp_client) => udp_client,
        Err(err) => panic!("{err}"),
    };

    match client.client.send(&empty_udp_request()).await {
        Ok(_) => (),
        Err(err) => panic!("{err}"),
    }

    let response = match client.client.receive().await {
        Ok(response) => response,
        Err(err) => panic!("{err}"),
    };

    let response = Response::parse_bytes(&response, true).unwrap();

    assert_eq!(get_error_response_message(&response).unwrap(), "Protocol identifier missing");

    env.stop().await;
}

mod receiving_a_connection_request {
    use aquatic_udp_protocol::{ConnectRequest, TransactionId};
    use bittorrent_tracker_client::udp::client::UdpTrackerClient;
    use torrust_tracker_configuration::DEFAULT_TIMEOUT;
    use torrust_tracker_test_helpers::configuration;

    use crate::common::logging;
    use crate::servers::udp::asserts::is_connect_response;
    use crate::servers::udp::Started;

    #[tokio::test]
    async fn should_return_a_connect_response() {
        logging::setup();

        let env = Started::new(&configuration::ephemeral().into()).await;

        let client = match UdpTrackerClient::new(env.bind_address(), DEFAULT_TIMEOUT).await {
            Ok(udp_tracker_client) => udp_tracker_client,
            Err(err) => panic!("{err}"),
        };

        let connect_request = ConnectRequest {
            transaction_id: TransactionId::new(123),
        };

        match client.send(connect_request.into()).await {
            Ok(_) => (),
            Err(err) => panic!("{err}"),
        }

        let response = match client.receive().await {
            Ok(response) => response,
            Err(err) => panic!("{err}"),
        };

        assert!(is_connect_response(&response, TransactionId::new(123)));

        env.stop().await;
    }
}

mod receiving_an_announce_request {
    use std::net::Ipv4Addr;

    use aquatic_udp_protocol::{
        AnnounceActionPlaceholder, AnnounceEvent, AnnounceRequest, ConnectionId, InfoHash, NumberOfBytes, NumberOfPeers, PeerId,
        PeerKey, Port, TransactionId,
    };
    use bittorrent_tracker_client::udp::client::UdpTrackerClient;
    use torrust_tracker_configuration::DEFAULT_TIMEOUT;
    use torrust_tracker_test_helpers::configuration;

    use crate::common::fixtures::{random_info_hash, random_transaction_id};
    use crate::common::logging::{self, logs_contains_a_line_with};
    use crate::servers::udp::asserts::is_ipv4_announce_response;
    use crate::servers::udp::contract::send_connection_request;
    use crate::servers::udp::Started;

    pub async fn assert_send_and_get_announce(
        tx_id: TransactionId,
        c_id: ConnectionId,
        info_hash: bittorrent_primitives::info_hash::InfoHash,
        client: &UdpTrackerClient,
    ) {
        let response = send_and_get_announce(tx_id, c_id, info_hash, client).await;
        assert!(is_ipv4_announce_response(&response));
    }

    pub async fn send_and_get_announce(
        tx_id: TransactionId,
        c_id: ConnectionId,
        info_hash: bittorrent_primitives::info_hash::InfoHash,
        client: &UdpTrackerClient,
    ) -> aquatic_udp_protocol::Response {
        let announce_request =
            build_sample_announce_request(tx_id, c_id, client.client.socket.local_addr().unwrap().port(), info_hash);

        match client.send(announce_request.into()).await {
            Ok(_) => (),
            Err(err) => panic!("{err}"),
        }

        match client.receive().await {
            Ok(response) => response,
            Err(err) => panic!("{err}"),
        }
    }

    fn build_sample_announce_request(
        tx_id: TransactionId,
        c_id: ConnectionId,
        port: u16,
        info_hash: bittorrent_primitives::info_hash::InfoHash,
    ) -> AnnounceRequest {
        AnnounceRequest {
            connection_id: ConnectionId(c_id.0),
            action_placeholder: AnnounceActionPlaceholder::default(),
            transaction_id: tx_id,
            info_hash: InfoHash(info_hash.0),
            peer_id: PeerId([255u8; 20]),
            bytes_downloaded: NumberOfBytes(0i64.into()),
            bytes_uploaded: NumberOfBytes(0i64.into()),
            bytes_left: NumberOfBytes(0i64.into()),
            event: AnnounceEvent::Started.into(),
            ip_address: Ipv4Addr::new(0, 0, 0, 0).into(),
            key: PeerKey::new(0i32),
            peers_wanted: NumberOfPeers(1i32.into()),
            port: Port(port.into()),
        }
    }

    #[tokio::test]
    async fn should_return_an_announce_response() {
        logging::setup();

        let env = Started::new(&configuration::ephemeral().into()).await;

        let client = match UdpTrackerClient::new(env.bind_address(), DEFAULT_TIMEOUT).await {
            Ok(udp_tracker_client) => udp_tracker_client,
            Err(err) => panic!("{err}"),
        };

        let tx_id = TransactionId::new(123);

        let c_id = send_connection_request(tx_id, &client).await;

        let info_hash = random_info_hash();

        assert_send_and_get_announce(tx_id, c_id, info_hash, &client).await;

        env.stop().await;
    }

    #[tokio::test]
    async fn should_return_many_announce_response() {
        logging::setup();

        let env = Started::new(&configuration::ephemeral().into()).await;

        let client = match UdpTrackerClient::new(env.bind_address(), DEFAULT_TIMEOUT).await {
            Ok(udp_tracker_client) => udp_tracker_client,
            Err(err) => panic!("{err}"),
        };

        let tx_id = TransactionId::new(123);

        let c_id = send_connection_request(tx_id, &client).await;

        let info_hash = random_info_hash();

        for x in 0..1000 {
            tracing::info!("req no: {x}");
            assert_send_and_get_announce(tx_id, c_id, info_hash, &client).await;
        }

        env.stop().await;
    }

    #[tokio::test]
    async fn should_ban_the_client_ip_if_it_sends_more_than_10_requests_with_a_cookie_value_not_normal() {
        logging::setup();

        let env = Started::new(&configuration::ephemeral().into()).await;
        let ban_service = env.udp_tracker_container.ban_service.clone();

        let client = match UdpTrackerClient::new(env.bind_address(), DEFAULT_TIMEOUT).await {
            Ok(udp_tracker_client) => udp_tracker_client,
            Err(err) => panic!("{err}"),
        };

        let udp_banned_ips_total_before = ban_service.read().await.get_banned_ips_total();

        // The eleven first requests should be fine

        let invalid_connection_id = ConnectionId::new(0); // Zero is one of the not normal values.

        let info_hash = random_info_hash();

        for x in 0..=10 {
            tracing::info!("req no: {x}");

            let tx_id = random_transaction_id();

            send_and_get_announce(tx_id, invalid_connection_id, info_hash, &client).await;

            let transaction_id = tx_id.0.to_string();

            assert!(
                logs_contains_a_line_with(&["ERROR", "UDP TRACKER", &transaction_id.to_string()]),
                "Expected logs to contain: ERROR ... UDP TRACKER ... transaction_id={transaction_id}"
            );
        }

        // The twelfth request should be banned (timeout error)

        let tx_id = random_transaction_id();

        let announce_request = build_sample_announce_request(
            tx_id,
            invalid_connection_id,
            client.client.socket.local_addr().unwrap().port(),
            info_hash,
        );

        let udp_requests_banned_before = env.stats_repository.get_stats().await.udp_requests_banned;

        // This should return a timeout error
        match client.send(announce_request.into()).await {
            Ok(_) => (),
            Err(err) => panic!("{err}"),
        }

        assert!(client.receive().await.is_err());

        let udp_requests_banned_after = env.stats_repository.get_stats().await.udp_requests_banned;
        let udp_banned_ips_total_after = ban_service.read().await.get_banned_ips_total();

        // UDP counter for banned requests should be increased by 1
        assert_eq!(udp_requests_banned_after, udp_requests_banned_before + 1);

        // UDP counter for banned IPs should be increased by 1
        assert_eq!(udp_banned_ips_total_after, udp_banned_ips_total_before + 1);

        env.stop().await;
    }
}

mod receiving_an_scrape_request {
    use aquatic_udp_protocol::{ConnectionId, InfoHash, ScrapeRequest, TransactionId};
    use bittorrent_tracker_client::udp::client::UdpTrackerClient;
    use torrust_tracker_configuration::DEFAULT_TIMEOUT;
    use torrust_tracker_test_helpers::configuration;

    use crate::common::logging;
    use crate::servers::udp::asserts::is_scrape_response;
    use crate::servers::udp::contract::send_connection_request;
    use crate::servers::udp::Started;

    #[tokio::test]
    async fn should_return_a_scrape_response() {
        logging::setup();

        let env = Started::new(&configuration::ephemeral().into()).await;

        let client = match UdpTrackerClient::new(env.bind_address(), DEFAULT_TIMEOUT).await {
            Ok(udp_tracker_client) => udp_tracker_client,
            Err(err) => panic!("{err}"),
        };

        let connection_id = send_connection_request(TransactionId::new(123), &client).await;

        // Send scrape request

        // Full scrapes are not allowed you need to pass an array of info hashes otherwise
        // it will return "bad request" error with empty vector

        let empty_info_hash = vec![InfoHash([0u8; 20])];

        let scrape_request = ScrapeRequest {
            connection_id: ConnectionId(connection_id.0),
            transaction_id: TransactionId::new(123i32),
            info_hashes: empty_info_hash,
        };

        match client.send(scrape_request.into()).await {
            Ok(_) => (),
            Err(err) => panic!("{err}"),
        }

        let response = match client.receive().await {
            Ok(response) => response,
            Err(err) => panic!("{err}"),
        };

        assert!(is_scrape_response(&response));

        env.stop().await;
    }
}
