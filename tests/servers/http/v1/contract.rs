use torrust_tracker_test_helpers::configuration;

use crate::common::logging;
use crate::servers::http::Started;

#[tokio::test]
async fn environment_should_be_started_and_stopped() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    env.stop().await;
}

mod for_all_config_modes {

    use torrust_tracker_lib::servers::http::v1::handlers::health_check::{Report, Status};
    use torrust_tracker_test_helpers::configuration;

    use crate::common::logging;
    use crate::servers::http::client::Client;
    use crate::servers::http::Started;

    #[tokio::test]
    async fn health_check_endpoint_should_return_ok_if_the_http_tracker_is_running() {
        logging::setup();

        let env = Started::new(&configuration::ephemeral_with_reverse_proxy().into()).await;

        let response = Client::new(*env.bind_address()).health_check().await;

        assert_eq!(response.status(), 200);
        assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
        assert_eq!(response.json::<Report>().await.unwrap(), Report { status: Status::Ok });

        env.stop().await;
    }

    mod and_running_on_reverse_proxy {
        use torrust_tracker_test_helpers::configuration;

        use crate::common::logging;
        use crate::servers::http::asserts::assert_could_not_find_remote_address_on_x_forwarded_for_header_error_response;
        use crate::servers::http::client::Client;
        use crate::servers::http::requests::announce::QueryBuilder;
        use crate::servers::http::Started;

        #[tokio::test]
        async fn should_fail_when_the_http_request_does_not_include_the_xff_http_request_header() {
            logging::setup();

            // If the tracker is running behind a reverse proxy, the peer IP is the
            // right most IP in the `X-Forwarded-For` HTTP header, which is the IP of the proxy's client.

            let env = Started::new(&configuration::ephemeral_with_reverse_proxy().into()).await;

            let params = QueryBuilder::default().query().params();

            let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

            assert_could_not_find_remote_address_on_x_forwarded_for_header_error_response(response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_the_xff_http_request_header_contains_an_invalid_ip() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_with_reverse_proxy().into()).await;

            let params = QueryBuilder::default().query().params();

            let response = Client::new(*env.bind_address())
                .get_with_header(&format!("announce?{params}"), "X-Forwarded-For", "INVALID IP")
                .await;

            assert_could_not_find_remote_address_on_x_forwarded_for_header_error_response(response).await;

            env.stop().await;
        }
    }

    mod receiving_an_announce_request {

        // Announce request documentation:
        //
        // BEP 03. The BitTorrent Protocol Specification
        // https://www.bittorrent.org/beps/bep_0003.html
        //
        // BEP 23. Tracker Returns Compact Peer Lists
        // https://www.bittorrent.org/beps/bep_0023.html
        //
        // Vuze (bittorrent client) docs:
        // https://wiki.vuze.com/w/Announce

        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
        use std::str::FromStr;

        use aquatic_udp_protocol::PeerId;
        use bittorrent_primitives::info_hash::InfoHash;
        use local_ip_address::local_ip;
        use reqwest::{Response, StatusCode};
        use tokio::net::TcpListener;
        use torrust_tracker_primitives::peer::fixture::PeerBuilder;
        use torrust_tracker_test_helpers::configuration;

        use crate::common::fixtures::invalid_info_hashes;
        use crate::common::logging;
        use crate::servers::http::asserts::{
            assert_announce_response, assert_bad_announce_request_error_response, assert_cannot_parse_query_param_error_response,
            assert_cannot_parse_query_params_error_response, assert_compact_announce_response, assert_empty_announce_response,
            assert_is_announce_response, assert_missing_query_params_for_announce_request_error_response,
        };
        use crate::servers::http::client::Client;
        use crate::servers::http::requests::announce::{Compact, QueryBuilder};
        use crate::servers::http::responses::announce::{Announce, CompactPeer, CompactPeerList, DictionaryPeer};
        use crate::servers::http::{responses, Started};

        #[tokio::test]
        async fn it_should_start_and_stop() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;
            env.stop().await;
        }

        #[tokio::test]
        async fn should_respond_if_only_the_mandatory_fields_are_provided() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral().into()).await;

            let mut params = QueryBuilder::default().query().params();

            params.remove_optional_params();

            let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

            assert_is_announce_response(response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_the_url_query_component_is_empty() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral().into()).await;

            let response = Client::new(*env.bind_address()).get("announce").await;

            assert_missing_query_params_for_announce_request_error_response(response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_url_query_parameters_are_invalid() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral().into()).await;

            let invalid_query_param = "a=b=c";

            let response = Client::new(*env.bind_address())
                .get(&format!("announce?{invalid_query_param}"))
                .await;

            assert_cannot_parse_query_param_error_response(response, "invalid param a=b=c").await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_a_mandatory_field_is_missing() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral().into()).await;

            // Without `info_hash` param

            let mut params = QueryBuilder::default().query().params();

            params.info_hash = None;

            let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

            assert_bad_announce_request_error_response(response, "missing param info_hash").await;

            // Without `peer_id` param

            let mut params = QueryBuilder::default().query().params();

            params.peer_id = None;

            let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

            assert_bad_announce_request_error_response(response, "missing param peer_id").await;

            // Without `port` param

            let mut params = QueryBuilder::default().query().params();

            params.port = None;

            let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

            assert_bad_announce_request_error_response(response, "missing param port").await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_the_info_hash_param_is_invalid() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral().into()).await;

            let mut params = QueryBuilder::default().query().params();

            for invalid_value in &invalid_info_hashes() {
                params.set("info_hash", invalid_value);

                let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

                assert_cannot_parse_query_params_error_response(response, "").await;
            }

            env.stop().await;
        }

        #[tokio::test]
        async fn should_not_fail_when_the_peer_address_param_is_invalid() {
            logging::setup();

            // AnnounceQuery does not even contain the `peer_addr`
            // The peer IP is obtained in two ways:
            // 1. If tracker is NOT running `on_reverse_proxy` from the remote client IP.
            // 2. If tracker is     running `on_reverse_proxy` from `X-Forwarded-For` request HTTP header.

            let env = Started::new(&configuration::ephemeral().into()).await;

            let mut params = QueryBuilder::default().query().params();

            params.peer_addr = Some("INVALID-IP-ADDRESS".to_string());

            let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

            assert_is_announce_response(response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_the_downloaded_param_is_invalid() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral().into()).await;

            let mut params = QueryBuilder::default().query().params();

            let invalid_values = ["-1", "1.1", "a"];

            for invalid_value in invalid_values {
                params.set("downloaded", invalid_value);

                let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

                assert_bad_announce_request_error_response(response, "invalid param value").await;
            }

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_the_uploaded_param_is_invalid() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral().into()).await;

            let mut params = QueryBuilder::default().query().params();

            let invalid_values = ["-1", "1.1", "a"];

            for invalid_value in invalid_values {
                params.set("uploaded", invalid_value);

                let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

                assert_bad_announce_request_error_response(response, "invalid param value").await;
            }

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_the_peer_id_param_is_invalid() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral().into()).await;

            let mut params = QueryBuilder::default().query().params();

            let invalid_values = [
                "0",
                "-1",
                "1.1",
                "a",
                "-qB0000000000000000",   // 19 bytes
                "-qB000000000000000000", // 21 bytes
            ];

            for invalid_value in invalid_values {
                params.set("peer_id", invalid_value);

                let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

                assert_bad_announce_request_error_response(response, "invalid param value").await;
            }

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_the_port_param_is_invalid() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral().into()).await;

            let mut params = QueryBuilder::default().query().params();

            let invalid_values = ["-1", "1.1", "a"];

            for invalid_value in invalid_values {
                params.set("port", invalid_value);

                let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

                assert_bad_announce_request_error_response(response, "invalid param value").await;
            }

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_the_left_param_is_invalid() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral().into()).await;

            let mut params = QueryBuilder::default().query().params();

            let invalid_values = ["-1", "1.1", "a"];

            for invalid_value in invalid_values {
                params.set("left", invalid_value);

                let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

                assert_bad_announce_request_error_response(response, "invalid param value").await;
            }

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_the_event_param_is_invalid() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral().into()).await;

            let mut params = QueryBuilder::default().query().params();

            let invalid_values = [
                "0",
                "-1",
                "1.1",
                "a",
                "Started",   // It should be lowercase to be valid: `started`
                "Stopped",   // It should be lowercase to be valid: `stopped`
                "Completed", // It should be lowercase to be valid: `completed`
            ];

            for invalid_value in invalid_values {
                params.set("event", invalid_value);

                let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

                assert_bad_announce_request_error_response(response, "invalid param value").await;
            }

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_the_compact_param_is_invalid() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral().into()).await;

            let mut params = QueryBuilder::default().query().params();

            let invalid_values = ["-1", "1.1", "a"];

            for invalid_value in invalid_values {
                params.set("compact", invalid_value);

                let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

                assert_bad_announce_request_error_response(response, "invalid param value").await;
            }

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_the_numwant_param_is_invalid() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral().into()).await;

            let mut params = QueryBuilder::default().query().params();

            let invalid_values = ["-1", "1.1", "a"];

            for invalid_value in invalid_values {
                params.set("numwant", invalid_value);

                let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

                assert_bad_announce_request_error_response(response, "invalid param value").await;
            }

            env.stop().await;
        }

        #[tokio::test]
        async fn should_return_no_peers_if_the_announced_peer_is_the_first_one() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            let response = Client::new(*env.bind_address())
                .announce(
                    &QueryBuilder::default()
                        .with_info_hash(&InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap())
                        .query(),
                )
                .await;

            let announce_policy = env.tracker.get_announce_policy();

            assert_announce_response(
                response,
                &Announce {
                    complete: 1, // the peer for this test
                    incomplete: 0,
                    interval: announce_policy.interval,
                    min_interval: announce_policy.interval_min,
                    peers: vec![],
                },
            )
            .await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_return_the_list_of_previously_announced_peers() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            // Peer 1
            let previously_announced_peer = PeerBuilder::default().with_peer_id(&PeerId(*b"-qB00000000000000001")).build();

            // Add the Peer 1
            env.add_torrent_peer(&info_hash, &previously_announced_peer);

            // Announce the new Peer 2. This new peer is non included on the response peer list
            let response = Client::new(*env.bind_address())
                .announce(
                    &QueryBuilder::default()
                        .with_info_hash(&info_hash)
                        .with_peer_id(&PeerId(*b"-qB00000000000000002"))
                        .query(),
                )
                .await;

            let announce_policy = env.tracker.get_announce_policy();

            // It should only contain the previously announced peer
            assert_announce_response(
                response,
                &Announce {
                    complete: 2,
                    incomplete: 0,
                    interval: announce_policy.interval,
                    min_interval: announce_policy.interval_min,
                    peers: vec![DictionaryPeer::from(previously_announced_peer)],
                },
            )
            .await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_return_the_list_of_previously_announced_peers_including_peers_using_ipv4_and_ipv6() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            // Announce a peer using IPV4
            let peer_using_ipv4 = PeerBuilder::default()
                .with_peer_id(&PeerId(*b"-qB00000000000000001"))
                .with_peer_addr(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0x69, 0x69, 0x69, 0x69)), 8080))
                .build();
            env.add_torrent_peer(&info_hash, &peer_using_ipv4);

            // Announce a peer using IPV6
            let peer_using_ipv6 = PeerBuilder::default()
                .with_peer_id(&PeerId(*b"-qB00000000000000002"))
                .with_peer_addr(&SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969)),
                    8080,
                ))
                .build();
            env.add_torrent_peer(&info_hash, &peer_using_ipv6);

            // Announce the new Peer.
            let response = Client::new(*env.bind_address())
                .announce(
                    &QueryBuilder::default()
                        .with_info_hash(&info_hash)
                        .with_peer_id(&PeerId(*b"-qB00000000000000003"))
                        .query(),
                )
                .await;

            let announce_policy = env.tracker.get_announce_policy();

            // The newly announced peer is not included on the response peer list,
            // but all the previously announced peers should be included regardless the IP version they are using.
            assert_announce_response(
                response,
                &Announce {
                    complete: 3,
                    incomplete: 0,
                    interval: announce_policy.interval,
                    min_interval: announce_policy.interval_min,
                    peers: vec![DictionaryPeer::from(peer_using_ipv4), DictionaryPeer::from(peer_using_ipv6)],
                },
            )
            .await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_consider_two_peers_to_be_the_same_when_they_have_the_same_peer_id_even_if_the_ip_is_different() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();
            let peer = PeerBuilder::default().build();

            // Add a peer
            env.add_torrent_peer(&info_hash, &peer);

            let announce_query = QueryBuilder::default()
                .with_info_hash(&info_hash)
                .with_peer_id(&peer.peer_id)
                .query();

            assert_ne!(peer.peer_addr.ip(), announce_query.peer_addr);

            let response = Client::new(*env.bind_address()).announce(&announce_query).await;

            assert_empty_announce_response(response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_return_the_compact_response() {
            logging::setup();

            // Tracker Returns Compact Peer Lists
            // https://www.bittorrent.org/beps/bep_0023.html

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            // Peer 1
            let previously_announced_peer = PeerBuilder::default().with_peer_id(&PeerId(*b"-qB00000000000000001")).build();

            // Add the Peer 1
            env.add_torrent_peer(&info_hash, &previously_announced_peer);

            // Announce the new Peer 2 accepting compact responses
            let response = Client::new(*env.bind_address())
                .announce(
                    &QueryBuilder::default()
                        .with_info_hash(&info_hash)
                        .with_peer_id(&PeerId(*b"-qB00000000000000002"))
                        .with_compact(Compact::Accepted)
                        .query(),
                )
                .await;

            let expected_response = responses::announce::Compact {
                complete: 2,
                incomplete: 0,
                interval: 120,
                min_interval: 120,
                peers: CompactPeerList::new([CompactPeer::new(&previously_announced_peer.peer_addr)].to_vec()),
            };

            assert_compact_announce_response(response, &expected_response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_not_return_the_compact_response_by_default() {
            logging::setup();

            // code-review: the HTTP tracker does not return the compact response by default if the "compact"
            // param is not provided in the announce URL. The BEP 23 suggest to do so.

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            // Peer 1
            let previously_announced_peer = PeerBuilder::default().with_peer_id(&PeerId(*b"-qB00000000000000001")).build();

            // Add the Peer 1
            env.add_torrent_peer(&info_hash, &previously_announced_peer);

            // Announce the new Peer 2 without passing the "compact" param
            // By default it should respond with the compact peer list
            // https://www.bittorrent.org/beps/bep_0023.html
            let response = Client::new(*env.bind_address())
                .announce(
                    &QueryBuilder::default()
                        .with_info_hash(&info_hash)
                        .with_peer_id(&PeerId(*b"-qB00000000000000002"))
                        .without_compact()
                        .query(),
                )
                .await;

            assert!(!is_a_compact_announce_response(response).await);

            env.stop().await;
        }

        async fn is_a_compact_announce_response(response: Response) -> bool {
            let bytes = response.bytes().await.unwrap();
            let compact_announce = serde_bencode::from_bytes::<responses::announce::DeserializedCompact>(&bytes);
            compact_announce.is_ok()
        }

        #[tokio::test]
        async fn should_increase_the_number_of_tcp4_connections_handled_in_statistics() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            Client::new(*env.bind_address())
                .announce(&QueryBuilder::default().query())
                .await;

            let stats = env.stats_repository.get_stats().await;

            assert_eq!(stats.tcp4_connections_handled, 1);

            drop(stats);

            env.stop().await;
        }

        #[tokio::test]
        async fn should_increase_the_number_of_tcp6_connections_handled_in_statistics() {
            logging::setup();

            if TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
                .await
                .is_err()
            {
                return; // we cannot bind to a ipv6 socket, so we will skip this test
            }

            let env = Started::new(&configuration::ephemeral_ipv6().into()).await;

            Client::bind(*env.bind_address(), IpAddr::from_str("::1").unwrap())
                .announce(&QueryBuilder::default().query())
                .await;

            let stats = env.stats_repository.get_stats().await;

            assert_eq!(stats.tcp6_connections_handled, 1);

            drop(stats);

            env.stop().await;
        }

        #[tokio::test]
        async fn should_not_increase_the_number_of_tcp6_connections_handled_if_the_client_is_not_using_an_ipv6_ip() {
            logging::setup();

            // The tracker ignores the peer address in the request param. It uses the client remote ip address.

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            Client::new(*env.bind_address())
                .announce(
                    &QueryBuilder::default()
                        .with_peer_addr(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
                        .query(),
                )
                .await;

            let stats = env.stats_repository.get_stats().await;

            assert_eq!(stats.tcp6_connections_handled, 0);

            drop(stats);

            env.stop().await;
        }

        #[tokio::test]
        async fn should_increase_the_number_of_tcp4_announce_requests_handled_in_statistics() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            Client::new(*env.bind_address())
                .announce(&QueryBuilder::default().query())
                .await;

            let stats = env.stats_repository.get_stats().await;

            assert_eq!(stats.tcp4_announces_handled, 1);

            drop(stats);

            env.stop().await;
        }

        #[tokio::test]
        async fn should_increase_the_number_of_tcp6_announce_requests_handled_in_statistics() {
            logging::setup();

            if TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
                .await
                .is_err()
            {
                return; // we cannot bind to a ipv6 socket, so we will skip this test
            }

            let env = Started::new(&configuration::ephemeral_ipv6().into()).await;

            Client::bind(*env.bind_address(), IpAddr::from_str("::1").unwrap())
                .announce(&QueryBuilder::default().query())
                .await;

            let stats = env.stats_repository.get_stats().await;

            assert_eq!(stats.tcp6_announces_handled, 1);

            drop(stats);

            env.stop().await;
        }

        #[tokio::test]
        async fn should_not_increase_the_number_of_tcp6_announce_requests_handled_if_the_client_is_not_using_an_ipv6_ip() {
            logging::setup();

            // The tracker ignores the peer address in the request param. It uses the client remote ip address.

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            Client::new(*env.bind_address())
                .announce(
                    &QueryBuilder::default()
                        .with_peer_addr(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
                        .query(),
                )
                .await;

            let stats = env.stats_repository.get_stats().await;

            assert_eq!(stats.tcp6_announces_handled, 0);

            drop(stats);

            env.stop().await;
        }

        #[tokio::test]
        async fn should_assign_to_the_peer_ip_the_remote_client_ip_instead_of_the_peer_address_in_the_request_param() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();
            let client_ip = local_ip().unwrap();

            let announce_query = QueryBuilder::default()
                .with_info_hash(&info_hash)
                .with_peer_addr(&IpAddr::from_str("2.2.2.2").unwrap())
                .query();

            {
                let client = Client::bind(*env.bind_address(), client_ip);
                let status = client.announce(&announce_query).await.status();

                assert_eq!(status, StatusCode::OK);
            }

            let peers = env.tracker.get_torrent_peers(&info_hash);
            let peer_addr = peers[0].peer_addr;

            assert_eq!(peer_addr.ip(), client_ip);
            assert_ne!(peer_addr.ip(), IpAddr::from_str("2.2.2.2").unwrap());

            env.stop().await;
        }

        #[tokio::test]
        async fn when_the_client_ip_is_a_loopback_ipv4_it_should_assign_to_the_peer_ip_the_external_ip_in_the_tracker_configuration(
        ) {
            logging::setup();

            /*  We assume that both the client and tracker share the same public IP.

                client     <-> tracker                      <-> Internet
                127.0.0.1      external_ip = "2.137.87.41"
            */
            let env =
                Started::new(&configuration::ephemeral_with_external_ip(IpAddr::from_str("2.137.87.41").unwrap()).into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();
            let loopback_ip = IpAddr::from_str("127.0.0.1").unwrap();
            let client_ip = loopback_ip;

            let announce_query = QueryBuilder::default()
                .with_info_hash(&info_hash)
                .with_peer_addr(&IpAddr::from_str("2.2.2.2").unwrap())
                .query();

            {
                let client = Client::bind(*env.bind_address(), client_ip);
                let status = client.announce(&announce_query).await.status();

                assert_eq!(status, StatusCode::OK);
            }

            let peers = env.tracker.get_torrent_peers(&info_hash);
            let peer_addr = peers[0].peer_addr;

            assert_eq!(peer_addr.ip(), env.tracker.get_maybe_external_ip().unwrap());
            assert_ne!(peer_addr.ip(), IpAddr::from_str("2.2.2.2").unwrap());

            env.stop().await;
        }

        #[tokio::test]
        async fn when_the_client_ip_is_a_loopback_ipv6_it_should_assign_to_the_peer_ip_the_external_ip_in_the_tracker_configuration(
        ) {
            logging::setup();

            /* We assume that both the client and tracker share the same public IP.

               client     <-> tracker                                                  <-> Internet
               ::1            external_ip = "2345:0425:2CA1:0000:0000:0567:5673:23b5"
            */

            let env = Started::new(
                &configuration::ephemeral_with_external_ip(IpAddr::from_str("2345:0425:2CA1:0000:0000:0567:5673:23b5").unwrap())
                    .into(),
            )
            .await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();
            let loopback_ip = IpAddr::from_str("127.0.0.1").unwrap();
            let client_ip = loopback_ip;

            let announce_query = QueryBuilder::default()
                .with_info_hash(&info_hash)
                .with_peer_addr(&IpAddr::from_str("2.2.2.2").unwrap())
                .query();

            {
                let client = Client::bind(*env.bind_address(), client_ip);
                let status = client.announce(&announce_query).await.status();

                assert_eq!(status, StatusCode::OK);
            }

            let peers = env.tracker.get_torrent_peers(&info_hash);
            let peer_addr = peers[0].peer_addr;

            assert_eq!(peer_addr.ip(), env.tracker.get_maybe_external_ip().unwrap());
            assert_ne!(peer_addr.ip(), IpAddr::from_str("2.2.2.2").unwrap());

            env.stop().await;
        }

        #[tokio::test]
        async fn when_the_tracker_is_behind_a_reverse_proxy_it_should_assign_to_the_peer_ip_the_ip_in_the_x_forwarded_for_http_header(
        ) {
            logging::setup();

            /*
            client          <-> http proxy                       <-> tracker                   <-> Internet
            ip:                 header:                              config:                       peer addr:
            145.254.214.256     X-Forwarded-For = 145.254.214.256    on_reverse_proxy = true       145.254.214.256
            */

            let env = Started::new(&configuration::ephemeral_with_reverse_proxy().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            let announce_query = QueryBuilder::default().with_info_hash(&info_hash).query();

            {
                let client = Client::new(*env.bind_address());
                let status = client
                    .announce_with_header(
                        &announce_query,
                        "X-Forwarded-For",
                        "203.0.113.195,2001:db8:85a3:8d3:1319:8a2e:370:7348,150.172.238.178",
                    )
                    .await
                    .status();

                assert_eq!(status, StatusCode::OK);
            }

            let peers = env.tracker.get_torrent_peers(&info_hash);
            let peer_addr = peers[0].peer_addr;

            assert_eq!(peer_addr.ip(), IpAddr::from_str("150.172.238.178").unwrap());

            env.stop().await;
        }
    }

    mod receiving_an_scrape_request {

        // Scrape documentation:
        //
        // BEP 48. Tracker Protocol Extension: Scrape
        // https://www.bittorrent.org/beps/bep_0048.html
        //
        // Vuze (bittorrent client) docs:
        // https://wiki.vuze.com/w/Scrape

        use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
        use std::str::FromStr;

        use aquatic_udp_protocol::PeerId;
        use bittorrent_primitives::info_hash::InfoHash;
        use tokio::net::TcpListener;
        use torrust_tracker_primitives::peer::fixture::PeerBuilder;
        use torrust_tracker_test_helpers::configuration;

        use crate::common::fixtures::invalid_info_hashes;
        use crate::common::logging;
        use crate::servers::http::asserts::{
            assert_cannot_parse_query_params_error_response, assert_missing_query_params_for_scrape_request_error_response,
            assert_scrape_response,
        };
        use crate::servers::http::client::Client;
        use crate::servers::http::requests::scrape::QueryBuilder;
        use crate::servers::http::responses::scrape::{self, File, ResponseBuilder};
        use crate::servers::http::{requests, Started};

        #[tokio::test]
        #[allow(dead_code)]
        async fn should_fail_when_the_request_is_empty() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;
            let response = Client::new(*env.bind_address()).get("scrape").await;

            assert_missing_query_params_for_scrape_request_error_response(response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_when_the_info_hash_param_is_invalid() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            let mut params = QueryBuilder::default().query().params();

            for invalid_value in &invalid_info_hashes() {
                params.set_one_info_hash_param(invalid_value);

                let response = Client::new(*env.bind_address()).get(&format!("announce?{params}")).await;

                assert_cannot_parse_query_params_error_response(response, "").await;
            }

            env.stop().await;
        }

        #[tokio::test]
        async fn should_return_the_file_with_the_incomplete_peer_when_there_is_one_peer_with_bytes_pending_to_download() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            env.add_torrent_peer(
                &info_hash,
                &PeerBuilder::default()
                    .with_peer_id(&PeerId(*b"-qB00000000000000001"))
                    .with_bytes_pending_to_download(1)
                    .build(),
            );

            let response = Client::new(*env.bind_address())
                .scrape(
                    &requests::scrape::QueryBuilder::default()
                        .with_one_info_hash(&info_hash)
                        .query(),
                )
                .await;

            let expected_scrape_response = ResponseBuilder::default()
                .add_file(
                    info_hash.bytes(),
                    File {
                        complete: 0,
                        downloaded: 0,
                        incomplete: 1,
                    },
                )
                .build();

            assert_scrape_response(response, &expected_scrape_response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_return_the_file_with_the_complete_peer_when_there_is_one_peer_with_no_bytes_pending_to_download() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            env.add_torrent_peer(
                &info_hash,
                &PeerBuilder::default()
                    .with_peer_id(&PeerId(*b"-qB00000000000000001"))
                    .with_no_bytes_pending_to_download()
                    .build(),
            );

            let response = Client::new(*env.bind_address())
                .scrape(
                    &requests::scrape::QueryBuilder::default()
                        .with_one_info_hash(&info_hash)
                        .query(),
                )
                .await;

            let expected_scrape_response = ResponseBuilder::default()
                .add_file(
                    info_hash.bytes(),
                    File {
                        complete: 1,
                        downloaded: 0,
                        incomplete: 0,
                    },
                )
                .build();

            assert_scrape_response(response, &expected_scrape_response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_return_a_file_with_zeroed_values_when_there_are_no_peers() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            let response = Client::new(*env.bind_address())
                .scrape(
                    &requests::scrape::QueryBuilder::default()
                        .with_one_info_hash(&info_hash)
                        .query(),
                )
                .await;

            assert_scrape_response(response, &scrape::Response::with_one_file(info_hash.bytes(), File::zeroed())).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_accept_multiple_infohashes() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            let info_hash1 = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();
            let info_hash2 = InfoHash::from_str("3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0").unwrap();

            let response = Client::new(*env.bind_address())
                .scrape(
                    &requests::scrape::QueryBuilder::default()
                        .add_info_hash(&info_hash1)
                        .add_info_hash(&info_hash2)
                        .query(),
                )
                .await;

            let expected_scrape_response = ResponseBuilder::default()
                .add_file(info_hash1.bytes(), File::zeroed())
                .add_file(info_hash2.bytes(), File::zeroed())
                .build();

            assert_scrape_response(response, &expected_scrape_response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_increase_the_number_ot_tcp4_scrape_requests_handled_in_statistics() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_public().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            Client::new(*env.bind_address())
                .scrape(
                    &requests::scrape::QueryBuilder::default()
                        .with_one_info_hash(&info_hash)
                        .query(),
                )
                .await;

            let stats = env.stats_repository.get_stats().await;

            assert_eq!(stats.tcp4_scrapes_handled, 1);

            drop(stats);

            env.stop().await;
        }

        #[tokio::test]
        async fn should_increase_the_number_ot_tcp6_scrape_requests_handled_in_statistics() {
            logging::setup();

            if TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
                .await
                .is_err()
            {
                return; // we cannot bind to a ipv6 socket, so we will skip this test
            }

            let env = Started::new(&configuration::ephemeral_ipv6().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            Client::bind(*env.bind_address(), IpAddr::from_str("::1").unwrap())
                .scrape(
                    &requests::scrape::QueryBuilder::default()
                        .with_one_info_hash(&info_hash)
                        .query(),
                )
                .await;

            let stats = env.stats_repository.get_stats().await;

            assert_eq!(stats.tcp6_scrapes_handled, 1);

            drop(stats);

            env.stop().await;
        }
    }
}

mod configured_as_whitelisted {

    mod and_receiving_an_announce_request {
        use std::str::FromStr;

        use bittorrent_primitives::info_hash::InfoHash;
        use torrust_tracker_test_helpers::configuration;
        use uuid::Uuid;

        use crate::common::fixtures::random_info_hash;
        use crate::common::logging::{self, logs_contains_a_line_with};
        use crate::servers::http::asserts::{assert_is_announce_response, assert_torrent_not_in_whitelist_error_response};
        use crate::servers::http::client::Client;
        use crate::servers::http::requests::announce::QueryBuilder;
        use crate::servers::http::Started;

        #[tokio::test]
        async fn should_fail_if_the_torrent_is_not_in_the_whitelist() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_listed().into()).await;

            let request_id = Uuid::new_v4();
            let info_hash = random_info_hash();

            let response = Client::new(*env.bind_address())
                .announce_with_header(
                    &QueryBuilder::default().with_info_hash(&info_hash).query(),
                    "x-request-id",
                    &request_id.to_string(),
                )
                .await;

            assert_torrent_not_in_whitelist_error_response(response).await;

            assert!(
                logs_contains_a_line_with(&["ERROR", &format!("{info_hash}"), "is not whitelisted"]),
                "Expected logs to contain: ERROR ... {info_hash} is not whitelisted"
            );

            env.stop().await;
        }

        #[tokio::test]
        async fn should_allow_announcing_a_whitelisted_torrent() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_listed().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            env.whitelist_manager
                .add_torrent_to_whitelist(&info_hash)
                .await
                .expect("should add the torrent to the whitelist");

            let response = Client::new(*env.bind_address())
                .announce(&QueryBuilder::default().with_info_hash(&info_hash).query())
                .await;

            assert_is_announce_response(response).await;

            env.stop().await;
        }
    }

    mod receiving_an_scrape_request {
        use std::str::FromStr;

        use aquatic_udp_protocol::PeerId;
        use bittorrent_primitives::info_hash::InfoHash;
        use torrust_tracker_primitives::peer::fixture::PeerBuilder;
        use torrust_tracker_test_helpers::configuration;

        use crate::common::fixtures::random_info_hash;
        use crate::common::logging::{self, logs_contains_a_line_with};
        use crate::servers::http::asserts::assert_scrape_response;
        use crate::servers::http::client::Client;
        use crate::servers::http::responses::scrape::{File, ResponseBuilder};
        use crate::servers::http::{requests, Started};

        #[tokio::test]
        async fn should_return_the_zeroed_file_when_the_requested_file_is_not_whitelisted() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_listed().into()).await;

            let info_hash = random_info_hash();

            env.add_torrent_peer(
                &info_hash,
                &PeerBuilder::default()
                    .with_peer_id(&PeerId(*b"-qB00000000000000001"))
                    .with_bytes_pending_to_download(1)
                    .build(),
            );

            let response = Client::new(*env.bind_address())
                .scrape(
                    &requests::scrape::QueryBuilder::default()
                        .with_one_info_hash(&info_hash)
                        .query(),
                )
                .await;

            let expected_scrape_response = ResponseBuilder::default().add_file(info_hash.bytes(), File::zeroed()).build();

            assert_scrape_response(response, &expected_scrape_response).await;

            assert!(
                logs_contains_a_line_with(&["ERROR", &format!("{info_hash}"), "is not whitelisted"]),
                "Expected logs to contain: ERROR ... {info_hash} is not whitelisted"
            );

            env.stop().await;
        }

        #[tokio::test]
        async fn should_return_the_file_stats_when_the_requested_file_is_whitelisted() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_listed().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            env.add_torrent_peer(
                &info_hash,
                &PeerBuilder::default()
                    .with_peer_id(&PeerId(*b"-qB00000000000000001"))
                    .with_bytes_pending_to_download(1)
                    .build(),
            );

            env.whitelist_manager
                .add_torrent_to_whitelist(&info_hash)
                .await
                .expect("should add the torrent to the whitelist");

            let response = Client::new(*env.bind_address())
                .scrape(
                    &requests::scrape::QueryBuilder::default()
                        .with_one_info_hash(&info_hash)
                        .query(),
                )
                .await;

            let expected_scrape_response = ResponseBuilder::default()
                .add_file(
                    info_hash.bytes(),
                    File {
                        complete: 0,
                        downloaded: 0,
                        incomplete: 1,
                    },
                )
                .build();

            assert_scrape_response(response, &expected_scrape_response).await;

            env.stop().await;
        }
    }
}

mod configured_as_private {

    mod and_receiving_an_announce_request {
        use std::str::FromStr;
        use std::time::Duration;

        use bittorrent_primitives::info_hash::InfoHash;
        use torrust_tracker_lib::core::auth::Key;
        use torrust_tracker_test_helpers::configuration;

        use crate::common::logging;
        use crate::servers::http::asserts::{assert_authentication_error_response, assert_is_announce_response};
        use crate::servers::http::client::Client;
        use crate::servers::http::requests::announce::QueryBuilder;
        use crate::servers::http::Started;

        #[tokio::test]
        async fn should_respond_to_authenticated_peers() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_private().into()).await;

            let expiring_key = env.tracker.generate_auth_key(Some(Duration::from_secs(60))).await.unwrap();

            let response = Client::authenticated(*env.bind_address(), expiring_key.key())
                .announce(&QueryBuilder::default().query())
                .await;

            assert_is_announce_response(response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_if_the_peer_has_not_provided_the_authentication_key() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_private().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            let response = Client::new(*env.bind_address())
                .announce(&QueryBuilder::default().with_info_hash(&info_hash).query())
                .await;

            assert_authentication_error_response(response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_fail_if_the_key_query_param_cannot_be_parsed() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_private().into()).await;

            let invalid_key = "INVALID_KEY";

            let response = Client::new(*env.bind_address())
                    .get(&format!(
                        "announce/{invalid_key}?info_hash=%81%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00&peer_addr=2.137.87.41&downloaded=0&uploaded=0&peer_id=-qB00000000000000001&port=17548&left=0&event=completed&compact=0"
                    ))
                    .await;

            assert_authentication_error_response(response).await;
        }

        #[tokio::test]
        async fn should_fail_if_the_peer_cannot_be_authenticated_with_the_provided_key() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_private().into()).await;

            // The tracker does not have this key
            let unregistered_key = Key::from_str("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap();

            let response = Client::authenticated(*env.bind_address(), unregistered_key)
                .announce(&QueryBuilder::default().query())
                .await;

            assert_authentication_error_response(response).await;

            env.stop().await;
        }
    }

    mod receiving_an_scrape_request {

        use std::str::FromStr;
        use std::time::Duration;

        use aquatic_udp_protocol::PeerId;
        use bittorrent_primitives::info_hash::InfoHash;
        use torrust_tracker_lib::core::auth::Key;
        use torrust_tracker_primitives::peer::fixture::PeerBuilder;
        use torrust_tracker_test_helpers::configuration;

        use crate::common::logging;
        use crate::servers::http::asserts::{assert_authentication_error_response, assert_scrape_response};
        use crate::servers::http::client::Client;
        use crate::servers::http::responses::scrape::{File, ResponseBuilder};
        use crate::servers::http::{requests, Started};

        #[tokio::test]
        async fn should_fail_if_the_key_query_param_cannot_be_parsed() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_private().into()).await;

            let invalid_key = "INVALID_KEY";

            let response = Client::new(*env.bind_address())
                .get(&format!(
                    "scrape/{invalid_key}?info_hash=%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0"
                ))
                .await;

            assert_authentication_error_response(response).await;
        }

        #[tokio::test]
        async fn should_return_the_zeroed_file_when_the_client_is_not_authenticated() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_private().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            env.add_torrent_peer(
                &info_hash,
                &PeerBuilder::default()
                    .with_peer_id(&PeerId(*b"-qB00000000000000001"))
                    .with_bytes_pending_to_download(1)
                    .build(),
            );

            let response = Client::new(*env.bind_address())
                .scrape(
                    &requests::scrape::QueryBuilder::default()
                        .with_one_info_hash(&info_hash)
                        .query(),
                )
                .await;

            let expected_scrape_response = ResponseBuilder::default().add_file(info_hash.bytes(), File::zeroed()).build();

            assert_scrape_response(response, &expected_scrape_response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_return_the_real_file_stats_when_the_client_is_authenticated() {
            logging::setup();

            let env = Started::new(&configuration::ephemeral_private().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            env.add_torrent_peer(
                &info_hash,
                &PeerBuilder::default()
                    .with_peer_id(&PeerId(*b"-qB00000000000000001"))
                    .with_bytes_pending_to_download(1)
                    .build(),
            );

            let expiring_key = env.tracker.generate_auth_key(Some(Duration::from_secs(60))).await.unwrap();

            let response = Client::authenticated(*env.bind_address(), expiring_key.key())
                .scrape(
                    &requests::scrape::QueryBuilder::default()
                        .with_one_info_hash(&info_hash)
                        .query(),
                )
                .await;

            let expected_scrape_response = ResponseBuilder::default()
                .add_file(
                    info_hash.bytes(),
                    File {
                        complete: 0,
                        downloaded: 0,
                        incomplete: 1,
                    },
                )
                .build();

            assert_scrape_response(response, &expected_scrape_response).await;

            env.stop().await;
        }

        #[tokio::test]
        async fn should_return_the_zeroed_file_when_the_authentication_key_provided_by_the_client_is_invalid() {
            logging::setup();

            // There is not authentication error
            // code-review: should this really be this way?

            let env = Started::new(&configuration::ephemeral_private().into()).await;

            let info_hash = InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap();

            env.add_torrent_peer(
                &info_hash,
                &PeerBuilder::default()
                    .with_peer_id(&PeerId(*b"-qB00000000000000001"))
                    .with_bytes_pending_to_download(1)
                    .build(),
            );

            let false_key: Key = "YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ".parse().unwrap();

            let response = Client::authenticated(*env.bind_address(), false_key)
                .scrape(
                    &requests::scrape::QueryBuilder::default()
                        .with_one_info_hash(&info_hash)
                        .query(),
                )
                .await;

            let expected_scrape_response = ResponseBuilder::default().add_file(info_hash.bytes(), File::zeroed()).build();

            assert_scrape_response(response, &expected_scrape_response).await;

            env.stop().await;
        }
    }
}

mod configured_as_private_and_whitelisted {

    mod and_receiving_an_announce_request {}

    mod receiving_an_scrape_request {}
}
