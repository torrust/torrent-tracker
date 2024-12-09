// UDP tracker documentation:
//
// BEP 15. UDP Tracker Protocol for BitTorrent
// https://www.bittorrent.org/beps/bep_0015.html

use core::panic;

use aquatic_udp_protocol::{ConnectRequest, ConnectionId, Response, TransactionId};
use bittorrent_tracker_client::udp::client::UdpTrackerClient;
use torrust_tracker::shared::bit_torrent::tracker::udp::MAX_PACKET_SIZE;
use torrust_tracker_configuration::DEFAULT_TIMEOUT;
use torrust_tracker_test_helpers::configuration;
use tracing::level_filters::LevelFilter;

use crate::common::logging::{tracing_stderr_init, INIT};
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
    };

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
    INIT.call_once(|| {
        tracing_stderr_init(LevelFilter::ERROR);
    });

    let env = Started::new(&configuration::ephemeral().into()).await;

    let client = match UdpTrackerClient::new(env.bind_address(), DEFAULT_TIMEOUT).await {
        Ok(udp_client) => udp_client,
        Err(err) => panic!("{err}"),
    };

    match client.client.send(&empty_udp_request()).await {
        Ok(_) => (),
        Err(err) => panic!("{err}"),
    };

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
    use tracing::level_filters::LevelFilter;

    use crate::common::logging::{tracing_stderr_init, INIT};
    use crate::servers::udp::asserts::is_connect_response;
    use crate::servers::udp::Started;

    #[tokio::test]
    async fn should_return_a_connect_response() {
        INIT.call_once(|| {
            tracing_stderr_init(LevelFilter::ERROR);
        });

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
        };

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
    use tracing::level_filters::LevelFilter;

    use crate::common::logging::{tracing_stderr_init, INIT};
    use crate::servers::udp::asserts::is_ipv4_announce_response;
    use crate::servers::udp::contract::send_connection_request;
    use crate::servers::udp::Started;

    pub async fn assert_send_and_get_announce(tx_id: TransactionId, c_id: ConnectionId, client: &UdpTrackerClient) {
        let response = send_and_get_announce(tx_id, c_id, client).await;
        assert!(is_ipv4_announce_response(&response));
    }

    pub async fn send_and_get_announce(
        tx_id: TransactionId,
        c_id: ConnectionId,
        client: &UdpTrackerClient,
    ) -> aquatic_udp_protocol::Response {
        let announce_request = build_sample_announce_request(tx_id, c_id, client.client.socket.local_addr().unwrap().port());

        match client.send(announce_request.into()).await {
            Ok(_) => (),
            Err(err) => panic!("{err}"),
        };

        match client.receive().await {
            Ok(response) => response,
            Err(err) => panic!("{err}"),
        }
    }

    fn build_sample_announce_request(tx_id: TransactionId, c_id: ConnectionId, port: u16) -> AnnounceRequest {
        AnnounceRequest {
            connection_id: ConnectionId(c_id.0),
            action_placeholder: AnnounceActionPlaceholder::default(),
            transaction_id: tx_id,
            info_hash: InfoHash([0u8; 20]),
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
        INIT.call_once(|| {
            tracing_stderr_init(LevelFilter::ERROR);
        });

        let env = Started::new(&configuration::ephemeral().into()).await;

        let client = match UdpTrackerClient::new(env.bind_address(), DEFAULT_TIMEOUT).await {
            Ok(udp_tracker_client) => udp_tracker_client,
            Err(err) => panic!("{err}"),
        };

        let tx_id = TransactionId::new(123);

        let c_id = send_connection_request(tx_id, &client).await;

        assert_send_and_get_announce(tx_id, c_id, &client).await;

        env.stop().await;
    }

    #[tokio::test]
    async fn should_return_many_announce_response() {
        INIT.call_once(|| {
            tracing_stderr_init(LevelFilter::ERROR);
        });

        let env = Started::new(&configuration::ephemeral().into()).await;

        let client = match UdpTrackerClient::new(env.bind_address(), DEFAULT_TIMEOUT).await {
            Ok(udp_tracker_client) => udp_tracker_client,
            Err(err) => panic!("{err}"),
        };

        let tx_id = TransactionId::new(123);

        let c_id = send_connection_request(tx_id, &client).await;

        for x in 0..1000 {
            tracing::info!("req no: {x}");
            assert_send_and_get_announce(tx_id, c_id, &client).await;
        }

        env.stop().await;
    }

    #[tokio::test]
    async fn should_ban_the_client_ip_if_it_sends_more_than_10_requests_with_a_cookie_value_not_normal() {
        INIT.call_once(|| {
            tracing_stderr_init(LevelFilter::ERROR);
        });

        let env = Started::new(&configuration::ephemeral().into()).await;

        let client = match UdpTrackerClient::new(env.bind_address(), DEFAULT_TIMEOUT).await {
            Ok(udp_tracker_client) => udp_tracker_client,
            Err(err) => panic!("{err}"),
        };

        let tx_id = TransactionId::new(123);

        // The eleven first requests should be fine

        let invalid_connection_id = ConnectionId::new(0); // Zero is one of the not normal values.

        for x in 0..=10 {
            tracing::info!("req no: {x}");
            send_and_get_announce(tx_id, invalid_connection_id, &client).await;
        }

        // The twelfth request should be banned (timeout error)

        let announce_request = build_sample_announce_request(
            tx_id,
            invalid_connection_id,
            client.client.socket.local_addr().unwrap().port(),
        );

        match client.send(announce_request.into()).await {
            Ok(_) => (),
            Err(err) => panic!("{err}"),
        };

        assert!(client.receive().await.is_err());

        env.stop().await;
    }
}

mod receiving_an_scrape_request {
    use aquatic_udp_protocol::{ConnectionId, InfoHash, ScrapeRequest, TransactionId};
    use bittorrent_tracker_client::udp::client::UdpTrackerClient;
    use torrust_tracker_configuration::DEFAULT_TIMEOUT;
    use torrust_tracker_test_helpers::configuration;
    use tracing::level_filters::LevelFilter;

    use crate::common::logging::{tracing_stderr_init, INIT};
    use crate::servers::udp::asserts::is_scrape_response;
    use crate::servers::udp::contract::send_connection_request;
    use crate::servers::udp::Started;

    #[tokio::test]
    async fn should_return_a_scrape_response() {
        INIT.call_once(|| {
            tracing_stderr_init(LevelFilter::ERROR);
        });

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
        };

        let response = match client.receive().await {
            Ok(response) => response,
            Err(err) => panic!("{err}"),
        };

        assert!(is_scrape_response(&response));

        env.stop().await;
    }
}
