use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic::Location;
use std::sync::Arc;

use aquatic_udp_protocol::{
    AnnounceInterval, AnnounceRequest, AnnounceResponse, ConnectRequest, ConnectResponse, ErrorResponse, NumberOfDownloads,
    NumberOfPeers, Port, Request, Response, ResponsePeer, ScrapeRequest, ScrapeResponse, TorrentScrapeStatistics, TransactionId,
};
use log::debug;

use super::connection_cookie::{check, from_connection_id, into_connection_id, make};
use crate::protocol::common::MAX_SCRAPE_TORRENTS;
use crate::protocol::info_hash::InfoHash;
use crate::tracker::{self, statistics};
use crate::udp::error::Error;
use crate::udp::peer_builder;
use crate::udp::request::AnnounceWrapper;

pub async fn handle_packet(remote_addr: SocketAddr, payload: Vec<u8>, tracker: Arc<tracker::Tracker>) -> Response {
    match Request::from_bytes(&payload[..payload.len()], MAX_SCRAPE_TORRENTS).map_err(|e| Error::InternalServer {
        message: format!("{e:?}"),
        location: Location::caller(),
    }) {
        Ok(request) => {
            let transaction_id = match &request {
                Request::Connect(connect_request) => connect_request.transaction_id,
                Request::Announce(announce_request) => announce_request.transaction_id,
                Request::Scrape(scrape_request) => scrape_request.transaction_id,
            };

            match handle_request(request, remote_addr, tracker).await {
                Ok(response) => response,
                Err(e) => handle_error(&e, transaction_id),
            }
        }
        // bad request
        Err(e) => handle_error(
            &Error::BadRequest {
                source: (Arc::new(e) as Arc<dyn std::error::Error + Send + Sync>).into(),
            },
            TransactionId(0),
        ),
    }
}

/// # Errors
///
/// If a error happens in the `handle_request` function, it will just return the  `ServerError`.
pub async fn handle_request(
    request: Request,
    remote_addr: SocketAddr,
    tracker: Arc<tracker::Tracker>,
) -> Result<Response, Error> {
    match request {
        Request::Connect(connect_request) => handle_connect(remote_addr, &connect_request, tracker).await,
        Request::Announce(announce_request) => handle_announce(remote_addr, &announce_request, tracker).await,
        Request::Scrape(scrape_request) => handle_scrape(remote_addr, &scrape_request, tracker).await,
    }
}

/// # Errors
///
/// This function dose not ever return an error.
pub async fn handle_connect(
    remote_addr: SocketAddr,
    request: &ConnectRequest,
    tracker: Arc<tracker::Tracker>,
) -> Result<Response, Error> {
    let connection_cookie = make(&remote_addr);
    let connection_id = into_connection_id(&connection_cookie);

    let response = Response::from(ConnectResponse {
        transaction_id: request.transaction_id,
        connection_id,
    });

    // send stats event
    match remote_addr {
        SocketAddr::V4(_) => {
            tracker.send_stats_event(statistics::Event::Udp4Connect).await;
        }
        SocketAddr::V6(_) => {
            tracker.send_stats_event(statistics::Event::Udp6Connect).await;
        }
    }

    Ok(response)
}

/// # Errors
///
/// Will return `Error` if unable to `authenticate_request`.
pub async fn authenticate(info_hash: &InfoHash, tracker: Arc<tracker::Tracker>) -> Result<(), Error> {
    tracker
        .authenticate_request(info_hash, &None)
        .await
        .map_err(|e| Error::TrackerError {
            source: (Arc::new(e) as Arc<dyn std::error::Error + Send + Sync>).into(),
        })
}

/// # Errors
///
/// If a error happens in the `handle_announce` function, it will just return the  `ServerError`.
pub async fn handle_announce(
    remote_addr: SocketAddr,
    announce_request: &AnnounceRequest,
    tracker: Arc<tracker::Tracker>,
) -> Result<Response, Error> {
    debug!("udp announce request: {:#?}", announce_request);

    check(&remote_addr, &from_connection_id(&announce_request.connection_id))?;

    let wrapped_announce_request = AnnounceWrapper::new(announce_request);

    let info_hash = wrapped_announce_request.info_hash;
    let remote_client_ip = remote_addr.ip();

    authenticate(&info_hash, tracker.clone()).await?;

    let mut peer = peer_builder::from_request(&wrapped_announce_request, &remote_client_ip);

    let response = tracker.announce(&info_hash, &mut peer, &remote_client_ip).await;

    match remote_client_ip {
        IpAddr::V4(_) => {
            tracker.send_stats_event(statistics::Event::Udp4Announce).await;
        }
        IpAddr::V6(_) => {
            tracker.send_stats_event(statistics::Event::Udp6Announce).await;
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    let announce_response = if remote_addr.is_ipv4() {
        Response::from(AnnounceResponse {
            transaction_id: wrapped_announce_request.announce_request.transaction_id,
            announce_interval: AnnounceInterval(i64::from(tracker.config.announce_interval) as i32),
            leechers: NumberOfPeers(i64::from(response.swam_stats.leechers) as i32),
            seeders: NumberOfPeers(i64::from(response.swam_stats.seeders) as i32),
            peers: response
                .peers
                .iter()
                .filter_map(|peer| {
                    if let IpAddr::V4(ip) = peer.peer_addr.ip() {
                        Some(ResponsePeer::<Ipv4Addr> {
                            ip_address: ip,
                            port: Port(peer.peer_addr.port()),
                        })
                    } else {
                        None
                    }
                })
                .collect(),
        })
    } else {
        Response::from(AnnounceResponse {
            transaction_id: wrapped_announce_request.announce_request.transaction_id,
            announce_interval: AnnounceInterval(i64::from(tracker.config.announce_interval) as i32),
            leechers: NumberOfPeers(i64::from(response.swam_stats.leechers) as i32),
            seeders: NumberOfPeers(i64::from(response.swam_stats.seeders) as i32),
            peers: response
                .peers
                .iter()
                .filter_map(|peer| {
                    if let IpAddr::V6(ip) = peer.peer_addr.ip() {
                        Some(ResponsePeer::<Ipv6Addr> {
                            ip_address: ip,
                            port: Port(peer.peer_addr.port()),
                        })
                    } else {
                        None
                    }
                })
                .collect(),
        })
    };

    Ok(announce_response)
}

/// # Errors
///
/// This function dose not ever return an error.
///
/// TODO: refactor this, db lock can be a lot shorter
pub async fn handle_scrape(
    remote_addr: SocketAddr,
    request: &ScrapeRequest,
    tracker: Arc<tracker::Tracker>,
) -> Result<Response, Error> {
    let db = tracker.get_torrents().await;

    let mut torrent_stats: Vec<TorrentScrapeStatistics> = Vec::new();

    for info_hash in &request.info_hashes {
        let info_hash = InfoHash(info_hash.0);

        let scrape_entry = match db.get(&info_hash) {
            Some(torrent_info) => {
                if tracker.authenticate_request(&info_hash, &None).await.is_ok() {
                    let (seeders, completed, leechers) = torrent_info.get_stats();

                    #[allow(clippy::cast_possible_truncation)]
                    TorrentScrapeStatistics {
                        seeders: NumberOfPeers(i64::from(seeders) as i32),
                        completed: NumberOfDownloads(i64::from(completed) as i32),
                        leechers: NumberOfPeers(i64::from(leechers) as i32),
                    }
                } else {
                    TorrentScrapeStatistics {
                        seeders: NumberOfPeers(0),
                        completed: NumberOfDownloads(0),
                        leechers: NumberOfPeers(0),
                    }
                }
            }
            None => TorrentScrapeStatistics {
                seeders: NumberOfPeers(0),
                completed: NumberOfDownloads(0),
                leechers: NumberOfPeers(0),
            },
        };

        torrent_stats.push(scrape_entry);
    }

    drop(db);

    // send stats event
    match remote_addr {
        SocketAddr::V4(_) => {
            tracker.send_stats_event(statistics::Event::Udp4Scrape).await;
        }
        SocketAddr::V6(_) => {
            tracker.send_stats_event(statistics::Event::Udp6Scrape).await;
        }
    }

    Ok(Response::from(ScrapeResponse {
        transaction_id: request.transaction_id,
        torrent_stats,
    }))
}

fn handle_error(e: &Error, transaction_id: TransactionId) -> Response {
    let message = e.to_string();
    Response::from(ErrorResponse {
        transaction_id,
        message: message.into(),
    })
}

#[cfg(test)]
mod tests {

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;

    use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes};
    use torrust_tracker_configuration::Configuration;
    use torrust_tracker_primitives::TrackerMode;
    use torrust_tracker_test_helpers::configuration::ephemeral;

    use crate::protocol::clock::{Current, Time};
    use crate::tracker::{self, peer, statistics};

    fn tracker_configuration() -> Arc<Configuration> {
        Arc::new(default_testing_tracker_configuration())
    }

    fn default_testing_tracker_configuration() -> Configuration {
        ephemeral()
    }

    fn initialized_public_tracker() -> Arc<tracker::Tracker> {
        let configuration = Arc::new(TrackerConfigurationBuilder::default().with_mode(TrackerMode::Public).into());
        initialized_tracker(&configuration)
    }

    fn initialized_private_tracker() -> Arc<tracker::Tracker> {
        let configuration = Arc::new(TrackerConfigurationBuilder::default().with_mode(TrackerMode::Private).into());
        initialized_tracker(&configuration)
    }

    fn initialized_whitelisted_tracker() -> Arc<tracker::Tracker> {
        let configuration = Arc::new(TrackerConfigurationBuilder::default().with_mode(TrackerMode::Listed).into());
        initialized_tracker(&configuration)
    }

    fn initialized_tracker(configuration: &Arc<Configuration>) -> Arc<tracker::Tracker> {
        let (stats_event_sender, stats_repository) = statistics::Keeper::new_active_instance();
        Arc::new(tracker::Tracker::new(configuration, Some(stats_event_sender), stats_repository).unwrap())
    }

    fn sample_ipv4_remote_addr() -> SocketAddr {
        sample_ipv4_socket_address()
    }

    fn sample_ipv6_remote_addr() -> SocketAddr {
        sample_ipv6_socket_address()
    }

    fn sample_ipv4_socket_address() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    fn sample_ipv6_socket_address() -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080)
    }

    struct TorrentPeerBuilder {
        peer: peer::Peer,
    }

    impl TorrentPeerBuilder {
        pub fn default() -> TorrentPeerBuilder {
            let default_peer = peer::Peer {
                peer_id: peer::Id([255u8; 20]),
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080),
                updated: Current::now(),
                uploaded: NumberOfBytes(0),
                downloaded: NumberOfBytes(0),
                left: NumberOfBytes(0),
                event: AnnounceEvent::Started,
            };
            TorrentPeerBuilder { peer: default_peer }
        }

        pub fn with_peer_id(mut self, peer_id: peer::Id) -> Self {
            self.peer.peer_id = peer_id;
            self
        }

        pub fn with_peer_addr(mut self, peer_addr: SocketAddr) -> Self {
            self.peer.peer_addr = peer_addr;
            self
        }

        pub fn with_bytes_left(mut self, left: i64) -> Self {
            self.peer.left = NumberOfBytes(left);
            self
        }

        pub fn into(self) -> peer::Peer {
            self.peer
        }
    }

    struct TrackerConfigurationBuilder {
        configuration: Configuration,
    }

    impl TrackerConfigurationBuilder {
        pub fn default() -> TrackerConfigurationBuilder {
            let default_configuration = default_testing_tracker_configuration();
            TrackerConfigurationBuilder {
                configuration: default_configuration,
            }
        }

        pub fn with_external_ip(mut self, external_ip: &str) -> Self {
            self.configuration.external_ip = Some(external_ip.to_owned());
            self
        }

        pub fn with_mode(mut self, mode: TrackerMode) -> Self {
            self.configuration.mode = mode;
            self
        }

        pub fn into(self) -> Configuration {
            self.configuration
        }
    }

    mod connect_request {

        use std::future;
        use std::sync::Arc;

        use aquatic_udp_protocol::{ConnectRequest, ConnectResponse, Response, TransactionId};
        use mockall::predicate::eq;

        use super::{sample_ipv4_socket_address, sample_ipv6_remote_addr, tracker_configuration};
        use crate::tracker::{self, statistics};
        use crate::udp::connection_cookie::{into_connection_id, make};
        use crate::udp::handlers::handle_connect;
        use crate::udp::handlers::tests::{initialized_public_tracker, sample_ipv4_remote_addr};

        fn sample_connect_request() -> ConnectRequest {
            ConnectRequest {
                transaction_id: TransactionId(0i32),
            }
        }

        #[tokio::test]
        async fn a_connect_response_should_contain_the_same_transaction_id_as_the_connect_request() {
            let request = ConnectRequest {
                transaction_id: TransactionId(0i32),
            };

            let response = handle_connect(sample_ipv4_remote_addr(), &request, initialized_public_tracker())
                .await
                .unwrap();

            assert_eq!(
                response,
                Response::Connect(ConnectResponse {
                    connection_id: into_connection_id(&make(&sample_ipv4_remote_addr())),
                    transaction_id: request.transaction_id
                })
            );
        }

        #[tokio::test]
        async fn a_connect_response_should_contain_a_new_connection_id() {
            let request = ConnectRequest {
                transaction_id: TransactionId(0i32),
            };

            let response = handle_connect(sample_ipv4_remote_addr(), &request, initialized_public_tracker())
                .await
                .unwrap();

            assert_eq!(
                response,
                Response::Connect(ConnectResponse {
                    connection_id: into_connection_id(&make(&sample_ipv4_remote_addr())),
                    transaction_id: request.transaction_id
                })
            );
        }

        #[tokio::test]
        async fn it_should_send_the_upd4_connect_event_when_a_client_tries_to_connect_using_a_ip4_socket_address() {
            let mut stats_event_sender_mock = statistics::MockEventSender::new();
            stats_event_sender_mock
                .expect_send_event()
                .with(eq(statistics::Event::Udp4Connect))
                .times(1)
                .returning(|_| Box::pin(future::ready(Some(Ok(())))));
            let stats_event_sender = Box::new(stats_event_sender_mock);

            let client_socket_address = sample_ipv4_socket_address();

            let torrent_tracker = Arc::new(
                tracker::Tracker::new(&tracker_configuration(), Some(stats_event_sender), statistics::Repo::new()).unwrap(),
            );
            handle_connect(client_socket_address, &sample_connect_request(), torrent_tracker)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn it_should_send_the_upd6_connect_event_when_a_client_tries_to_connect_using_a_ip6_socket_address() {
            let mut stats_event_sender_mock = statistics::MockEventSender::new();
            stats_event_sender_mock
                .expect_send_event()
                .with(eq(statistics::Event::Udp6Connect))
                .times(1)
                .returning(|_| Box::pin(future::ready(Some(Ok(())))));
            let stats_event_sender = Box::new(stats_event_sender_mock);

            let torrent_tracker = Arc::new(
                tracker::Tracker::new(&tracker_configuration(), Some(stats_event_sender), statistics::Repo::new()).unwrap(),
            );
            handle_connect(sample_ipv6_remote_addr(), &sample_connect_request(), torrent_tracker)
                .await
                .unwrap();
        }
    }

    mod announce_request {

        use std::net::Ipv4Addr;

        use aquatic_udp_protocol::{
            AnnounceEvent, AnnounceRequest, ConnectionId, NumberOfBytes, NumberOfPeers, PeerId as AquaticPeerId, PeerKey, Port,
            TransactionId,
        };

        use crate::udp::connection_cookie::{into_connection_id, make};
        use crate::udp::handlers::tests::sample_ipv4_remote_addr;

        struct AnnounceRequestBuilder {
            request: AnnounceRequest,
        }

        impl AnnounceRequestBuilder {
            pub fn default() -> AnnounceRequestBuilder {
                let client_ip = Ipv4Addr::new(126, 0, 0, 1);
                let client_port = 8080;
                let info_hash_aquatic = aquatic_udp_protocol::InfoHash([0u8; 20]);

                let default_request = AnnounceRequest {
                    connection_id: into_connection_id(&make(&sample_ipv4_remote_addr())),
                    transaction_id: TransactionId(0i32),
                    info_hash: info_hash_aquatic,
                    peer_id: AquaticPeerId([255u8; 20]),
                    bytes_downloaded: NumberOfBytes(0i64),
                    bytes_uploaded: NumberOfBytes(0i64),
                    bytes_left: NumberOfBytes(0i64),
                    event: AnnounceEvent::Started,
                    ip_address: Some(client_ip),
                    key: PeerKey(0u32),
                    peers_wanted: NumberOfPeers(1i32),
                    port: Port(client_port),
                };
                AnnounceRequestBuilder {
                    request: default_request,
                }
            }

            pub fn with_connection_id(mut self, connection_id: ConnectionId) -> Self {
                self.request.connection_id = connection_id;
                self
            }

            pub fn with_info_hash(mut self, info_hash: aquatic_udp_protocol::InfoHash) -> Self {
                self.request.info_hash = info_hash;
                self
            }

            pub fn with_peer_id(mut self, peer_id: AquaticPeerId) -> Self {
                self.request.peer_id = peer_id;
                self
            }

            pub fn with_ip_address(mut self, ip_address: Ipv4Addr) -> Self {
                self.request.ip_address = Some(ip_address);
                self
            }

            pub fn with_port(mut self, port: u16) -> Self {
                self.request.port = Port(port);
                self
            }

            pub fn into(self) -> AnnounceRequest {
                self.request
            }
        }

        mod using_ipv4 {

            use std::future;
            use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
            use std::sync::Arc;

            use aquatic_udp_protocol::{
                AnnounceInterval, AnnounceResponse, InfoHash as AquaticInfoHash, NumberOfPeers, PeerId as AquaticPeerId,
                Response, ResponsePeer,
            };
            use mockall::predicate::eq;

            use crate::tracker::{self, peer, statistics};
            use crate::udp::connection_cookie::{into_connection_id, make};
            use crate::udp::handlers::handle_announce;
            use crate::udp::handlers::tests::announce_request::AnnounceRequestBuilder;
            use crate::udp::handlers::tests::{
                initialized_public_tracker, sample_ipv4_socket_address, tracker_configuration, TorrentPeerBuilder,
            };

            #[tokio::test]
            async fn an_announced_peer_should_be_added_to_the_tracker() {
                let tracker = initialized_public_tracker();

                let client_ip = Ipv4Addr::new(126, 0, 0, 1);
                let client_port = 8080;
                let info_hash = AquaticInfoHash([0u8; 20]);
                let peer_id = AquaticPeerId([255u8; 20]);

                let remote_addr = SocketAddr::new(IpAddr::V4(client_ip), client_port);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .with_info_hash(info_hash)
                    .with_peer_id(peer_id)
                    .with_ip_address(client_ip)
                    .with_port(client_port)
                    .into();

                handle_announce(remote_addr, &request, tracker.clone()).await.unwrap();

                let peers = tracker.get_all_torrent_peers(&info_hash.0.into()).await;

                let expected_peer = TorrentPeerBuilder::default()
                    .with_peer_id(peer::Id(peer_id.0))
                    .with_peer_addr(SocketAddr::new(IpAddr::V4(client_ip), client_port))
                    .into();

                assert_eq!(peers[0], expected_peer);
            }

            #[tokio::test]
            async fn the_announced_peer_should_not_be_included_in_the_response() {
                let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .into();

                let response = handle_announce(remote_addr, &request, initialized_public_tracker())
                    .await
                    .unwrap();

                let empty_peer_vector: Vec<aquatic_udp_protocol::ResponsePeer<Ipv4Addr>> = vec![];
                assert_eq!(
                    response,
                    Response::from(AnnounceResponse {
                        transaction_id: request.transaction_id,
                        announce_interval: AnnounceInterval(120i32),
                        leechers: NumberOfPeers(0i32),
                        seeders: NumberOfPeers(1i32),
                        peers: empty_peer_vector
                    })
                );
            }

            #[tokio::test]
            async fn the_tracker_should_always_use_the_remote_client_ip_but_not_the_port_in_the_udp_request_header_instead_of_the_peer_address_in_the_announce_request(
            ) {
                // From the BEP 15 (https://www.bittorrent.org/beps/bep_0015.html):
                // "Do note that most trackers will only honor the IP address field under limited circumstances."

                let tracker = initialized_public_tracker();

                let info_hash = AquaticInfoHash([0u8; 20]);
                let peer_id = AquaticPeerId([255u8; 20]);
                let client_port = 8080;

                let remote_client_ip = Ipv4Addr::new(126, 0, 0, 1);
                let remote_client_port = 8081;
                let peer_address = Ipv4Addr::new(126, 0, 0, 2);

                let remote_addr = SocketAddr::new(IpAddr::V4(remote_client_ip), remote_client_port);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .with_info_hash(info_hash)
                    .with_peer_id(peer_id)
                    .with_ip_address(peer_address)
                    .with_port(client_port)
                    .into();

                handle_announce(remote_addr, &request, tracker.clone()).await.unwrap();

                let peers = tracker.get_all_torrent_peers(&info_hash.0.into()).await;

                assert_eq!(peers[0].peer_addr, SocketAddr::new(IpAddr::V4(remote_client_ip), client_port));
            }

            async fn add_a_torrent_peer_using_ipv6(tracker: Arc<tracker::Tracker>) {
                let info_hash = AquaticInfoHash([0u8; 20]);

                let client_ip_v4 = Ipv4Addr::new(126, 0, 0, 1);
                let client_ip_v6 = client_ip_v4.to_ipv6_compatible();
                let client_port = 8080;
                let peer_id = AquaticPeerId([255u8; 20]);

                let peer_using_ipv6 = TorrentPeerBuilder::default()
                    .with_peer_id(peer::Id(peer_id.0))
                    .with_peer_addr(SocketAddr::new(IpAddr::V6(client_ip_v6), client_port))
                    .into();

                tracker
                    .update_torrent_with_peer_and_get_stats(&info_hash.0.into(), &peer_using_ipv6)
                    .await;
            }

            async fn announce_a_new_peer_using_ipv4(tracker: Arc<tracker::Tracker>) -> Response {
                let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080);
                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .into();

                handle_announce(remote_addr, &request, tracker.clone()).await.unwrap()
            }

            #[tokio::test]
            async fn when_the_announce_request_comes_from_a_client_using_ipv4_the_response_should_not_include_peers_using_ipv6() {
                let tracker = initialized_public_tracker();

                add_a_torrent_peer_using_ipv6(tracker.clone()).await;

                let response = announce_a_new_peer_using_ipv4(tracker.clone()).await;

                // The response should not contain the peer using IPV6
                let peers: Option<Vec<ResponsePeer<Ipv6Addr>>> = match response {
                    Response::AnnounceIpv6(announce_response) => Some(announce_response.peers),
                    _ => None,
                };
                let no_ipv6_peers = peers.is_none();
                assert!(no_ipv6_peers);
            }

            #[tokio::test]
            async fn should_send_the_upd4_announce_event() {
                let mut stats_event_sender_mock = statistics::MockEventSender::new();
                stats_event_sender_mock
                    .expect_send_event()
                    .with(eq(statistics::Event::Udp4Announce))
                    .times(1)
                    .returning(|_| Box::pin(future::ready(Some(Ok(())))));
                let stats_event_sender = Box::new(stats_event_sender_mock);

                let tracker = Arc::new(
                    tracker::Tracker::new(&tracker_configuration(), Some(stats_event_sender), statistics::Repo::new()).unwrap(),
                );

                handle_announce(
                    sample_ipv4_socket_address(),
                    &AnnounceRequestBuilder::default().into(),
                    tracker.clone(),
                )
                .await
                .unwrap();
            }

            mod from_a_loopback_ip {
                use std::net::{IpAddr, Ipv4Addr, SocketAddr};

                use aquatic_udp_protocol::{InfoHash as AquaticInfoHash, PeerId as AquaticPeerId};

                use crate::tracker::peer;
                use crate::udp::connection_cookie::{into_connection_id, make};
                use crate::udp::handlers::handle_announce;
                use crate::udp::handlers::tests::announce_request::AnnounceRequestBuilder;
                use crate::udp::handlers::tests::{initialized_public_tracker, TorrentPeerBuilder};

                #[tokio::test]
                async fn the_peer_ip_should_be_changed_to_the_external_ip_in_the_tracker_configuration_if_defined() {
                    let tracker = initialized_public_tracker();

                    let client_ip = Ipv4Addr::new(127, 0, 0, 1);
                    let client_port = 8080;
                    let info_hash = AquaticInfoHash([0u8; 20]);
                    let peer_id = AquaticPeerId([255u8; 20]);

                    let remote_addr = SocketAddr::new(IpAddr::V4(client_ip), client_port);

                    let request = AnnounceRequestBuilder::default()
                        .with_connection_id(into_connection_id(&make(&remote_addr)))
                        .with_info_hash(info_hash)
                        .with_peer_id(peer_id)
                        .with_ip_address(client_ip)
                        .with_port(client_port)
                        .into();

                    handle_announce(remote_addr, &request, tracker.clone()).await.unwrap();

                    let peers = tracker.get_all_torrent_peers(&info_hash.0.into()).await;

                    let external_ip_in_tracker_configuration =
                        tracker.config.external_ip.clone().unwrap().parse::<Ipv4Addr>().unwrap();

                    let expected_peer = TorrentPeerBuilder::default()
                        .with_peer_id(peer::Id(peer_id.0))
                        .with_peer_addr(SocketAddr::new(IpAddr::V4(external_ip_in_tracker_configuration), client_port))
                        .into();

                    assert_eq!(peers[0], expected_peer);
                }
            }
        }

        mod using_ipv6 {

            use std::future;
            use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
            use std::sync::Arc;

            use aquatic_udp_protocol::{
                AnnounceInterval, AnnounceResponse, InfoHash as AquaticInfoHash, NumberOfPeers, PeerId as AquaticPeerId,
                Response, ResponsePeer,
            };
            use mockall::predicate::eq;

            use crate::tracker::{self, peer, statistics};
            use crate::udp::connection_cookie::{into_connection_id, make};
            use crate::udp::handlers::handle_announce;
            use crate::udp::handlers::tests::announce_request::AnnounceRequestBuilder;
            use crate::udp::handlers::tests::{
                initialized_public_tracker, sample_ipv6_remote_addr, tracker_configuration, TorrentPeerBuilder,
            };

            #[tokio::test]
            async fn an_announced_peer_should_be_added_to_the_tracker() {
                let tracker = initialized_public_tracker();

                let client_ip_v4 = Ipv4Addr::new(126, 0, 0, 1);
                let client_ip_v6 = client_ip_v4.to_ipv6_compatible();
                let client_port = 8080;
                let info_hash = AquaticInfoHash([0u8; 20]);
                let peer_id = AquaticPeerId([255u8; 20]);

                let remote_addr = SocketAddr::new(IpAddr::V6(client_ip_v6), client_port);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .with_info_hash(info_hash)
                    .with_peer_id(peer_id)
                    .with_ip_address(client_ip_v4)
                    .with_port(client_port)
                    .into();

                handle_announce(remote_addr, &request, tracker.clone()).await.unwrap();

                let peers = tracker.get_all_torrent_peers(&info_hash.0.into()).await;

                let expected_peer = TorrentPeerBuilder::default()
                    .with_peer_id(peer::Id(peer_id.0))
                    .with_peer_addr(SocketAddr::new(IpAddr::V6(client_ip_v6), client_port))
                    .into();

                assert_eq!(peers[0], expected_peer);
            }

            #[tokio::test]
            async fn the_announced_peer_should_not_be_included_in_the_response() {
                let client_ip_v4 = Ipv4Addr::new(126, 0, 0, 1);
                let client_ip_v6 = client_ip_v4.to_ipv6_compatible();

                let remote_addr = SocketAddr::new(IpAddr::V6(client_ip_v6), 8080);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .into();

                let response = handle_announce(remote_addr, &request, initialized_public_tracker())
                    .await
                    .unwrap();

                let empty_peer_vector: Vec<aquatic_udp_protocol::ResponsePeer<Ipv6Addr>> = vec![];
                assert_eq!(
                    response,
                    Response::from(AnnounceResponse {
                        transaction_id: request.transaction_id,
                        announce_interval: AnnounceInterval(120i32),
                        leechers: NumberOfPeers(0i32),
                        seeders: NumberOfPeers(1i32),
                        peers: empty_peer_vector
                    })
                );
            }

            #[tokio::test]
            async fn the_tracker_should_always_use_the_remote_client_ip_but_not_the_port_in_the_udp_request_header_instead_of_the_peer_address_in_the_announce_request(
            ) {
                // From the BEP 15 (https://www.bittorrent.org/beps/bep_0015.html):
                // "Do note that most trackers will only honor the IP address field under limited circumstances."

                let tracker = initialized_public_tracker();

                let info_hash = AquaticInfoHash([0u8; 20]);
                let peer_id = AquaticPeerId([255u8; 20]);
                let client_port = 8080;

                let remote_client_ip = "::100".parse().unwrap(); // IPV4 ::0.0.1.0 -> IPV6 = ::100 = ::ffff:0:100 = 0:0:0:0:0:ffff:0:0100
                let remote_client_port = 8081;
                let peer_address = "126.0.0.1".parse().unwrap();

                let remote_addr = SocketAddr::new(IpAddr::V6(remote_client_ip), remote_client_port);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .with_info_hash(info_hash)
                    .with_peer_id(peer_id)
                    .with_ip_address(peer_address)
                    .with_port(client_port)
                    .into();

                handle_announce(remote_addr, &request, tracker.clone()).await.unwrap();

                let peers = tracker.get_all_torrent_peers(&info_hash.0.into()).await;

                // When using IPv6 the tracker converts the remote client ip into a IPv4 address
                assert_eq!(peers[0].peer_addr, SocketAddr::new(IpAddr::V6(remote_client_ip), client_port));
            }

            async fn add_a_torrent_peer_using_ipv4(tracker: Arc<tracker::Tracker>) {
                let info_hash = AquaticInfoHash([0u8; 20]);

                let client_ip_v4 = Ipv4Addr::new(126, 0, 0, 1);
                let client_port = 8080;
                let peer_id = AquaticPeerId([255u8; 20]);

                let peer_using_ipv4 = TorrentPeerBuilder::default()
                    .with_peer_id(peer::Id(peer_id.0))
                    .with_peer_addr(SocketAddr::new(IpAddr::V4(client_ip_v4), client_port))
                    .into();

                tracker
                    .update_torrent_with_peer_and_get_stats(&info_hash.0.into(), &peer_using_ipv4)
                    .await;
            }

            async fn announce_a_new_peer_using_ipv6(tracker: Arc<tracker::Tracker>) -> Response {
                let client_ip_v4 = Ipv4Addr::new(126, 0, 0, 1);
                let client_ip_v6 = client_ip_v4.to_ipv6_compatible();
                let client_port = 8080;
                let remote_addr = SocketAddr::new(IpAddr::V6(client_ip_v6), client_port);
                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .into();

                handle_announce(remote_addr, &request, tracker.clone()).await.unwrap()
            }

            #[tokio::test]
            async fn when_the_announce_request_comes_from_a_client_using_ipv6_the_response_should_not_include_peers_using_ipv4() {
                let tracker = initialized_public_tracker();

                add_a_torrent_peer_using_ipv4(tracker.clone()).await;

                let response = announce_a_new_peer_using_ipv6(tracker.clone()).await;

                // The response should not contain the peer using IPV4
                let peers: Option<Vec<ResponsePeer<Ipv4Addr>>> = match response {
                    Response::AnnounceIpv4(announce_response) => Some(announce_response.peers),
                    _ => None,
                };
                let no_ipv4_peers = peers.is_none();
                assert!(no_ipv4_peers);
            }

            #[tokio::test]
            async fn should_send_the_upd6_announce_event() {
                let mut stats_event_sender_mock = statistics::MockEventSender::new();
                stats_event_sender_mock
                    .expect_send_event()
                    .with(eq(statistics::Event::Udp6Announce))
                    .times(1)
                    .returning(|_| Box::pin(future::ready(Some(Ok(())))));
                let stats_event_sender = Box::new(stats_event_sender_mock);

                let tracker = Arc::new(
                    tracker::Tracker::new(&tracker_configuration(), Some(stats_event_sender), statistics::Repo::new()).unwrap(),
                );

                let remote_addr = sample_ipv6_remote_addr();

                let announce_request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .into();

                handle_announce(remote_addr, &announce_request, tracker.clone())
                    .await
                    .unwrap();
            }

            mod from_a_loopback_ip {
                use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
                use std::sync::Arc;

                use aquatic_udp_protocol::{InfoHash as AquaticInfoHash, PeerId as AquaticPeerId};

                use crate::tracker;
                use crate::tracker::statistics::Keeper;
                use crate::udp::connection_cookie::{into_connection_id, make};
                use crate::udp::handlers::handle_announce;
                use crate::udp::handlers::tests::announce_request::AnnounceRequestBuilder;
                use crate::udp::handlers::tests::TrackerConfigurationBuilder;

                #[tokio::test]
                async fn the_peer_ip_should_be_changed_to_the_external_ip_in_the_tracker_configuration() {
                    let configuration = Arc::new(TrackerConfigurationBuilder::default().with_external_ip("::126.0.0.1").into());
                    let (stats_event_sender, stats_repository) = Keeper::new_active_instance();
                    let tracker =
                        Arc::new(tracker::Tracker::new(&configuration, Some(stats_event_sender), stats_repository).unwrap());

                    let loopback_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
                    let loopback_ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

                    let client_ip_v4 = loopback_ipv4;
                    let client_ip_v6 = loopback_ipv6;
                    let client_port = 8080;

                    let info_hash = AquaticInfoHash([0u8; 20]);
                    let peer_id = AquaticPeerId([255u8; 20]);

                    let remote_addr = SocketAddr::new(IpAddr::V6(client_ip_v6), client_port);

                    let request = AnnounceRequestBuilder::default()
                        .with_connection_id(into_connection_id(&make(&remote_addr)))
                        .with_info_hash(info_hash)
                        .with_peer_id(peer_id)
                        .with_ip_address(client_ip_v4)
                        .with_port(client_port)
                        .into();

                    handle_announce(remote_addr, &request, tracker.clone()).await.unwrap();

                    let peers = tracker.get_all_torrent_peers(&info_hash.0.into()).await;

                    let _external_ip_in_tracker_configuration =
                        tracker.config.external_ip.clone().unwrap().parse::<Ipv6Addr>().unwrap();

                    // There's a special type of IPv6 addresses that provide compatibility with IPv4.
                    // The last 32 bits of these addresses represent an IPv4, and are represented like this:
                    // 1111:2222:3333:4444:5555:6666:1.2.3.4
                    //
                    // ::127.0.0.1 is the IPV6 representation for the IPV4 address 127.0.0.1.
                    assert_eq!(Ok(peers[0].peer_addr.ip()), "::126.0.0.1".parse());
                }
            }
        }
    }

    mod scrape_request {
        use std::net::SocketAddr;
        use std::sync::Arc;

        use aquatic_udp_protocol::{
            InfoHash, NumberOfDownloads, NumberOfPeers, Response, ScrapeRequest, ScrapeResponse, TorrentScrapeStatistics,
            TransactionId,
        };

        use super::TorrentPeerBuilder;
        use crate::tracker::{self, peer};
        use crate::udp::connection_cookie::{into_connection_id, make};
        use crate::udp::handlers::handle_scrape;
        use crate::udp::handlers::tests::{initialized_public_tracker, sample_ipv4_remote_addr};

        fn zeroed_torrent_statistics() -> TorrentScrapeStatistics {
            TorrentScrapeStatistics {
                seeders: NumberOfPeers(0),
                completed: NumberOfDownloads(0),
                leechers: NumberOfPeers(0),
            }
        }

        #[tokio::test]
        async fn should_return_no_stats_when_the_tracker_does_not_have_any_torrent() {
            let remote_addr = sample_ipv4_remote_addr();

            let info_hash = InfoHash([0u8; 20]);
            let info_hashes = vec![info_hash];

            let request = ScrapeRequest {
                connection_id: into_connection_id(&make(&remote_addr)),
                transaction_id: TransactionId(0i32),
                info_hashes,
            };

            let response = handle_scrape(remote_addr, &request, initialized_public_tracker())
                .await
                .unwrap();

            let expected_torrent_stats = vec![zeroed_torrent_statistics()];

            assert_eq!(
                response,
                Response::from(ScrapeResponse {
                    transaction_id: request.transaction_id,
                    torrent_stats: expected_torrent_stats
                })
            );
        }

        async fn add_a_seeder(tracker: Arc<tracker::Tracker>, remote_addr: &SocketAddr, info_hash: &InfoHash) {
            let peer_id = peer::Id([255u8; 20]);

            let peer = TorrentPeerBuilder::default()
                .with_peer_id(peer::Id(peer_id.0))
                .with_peer_addr(*remote_addr)
                .with_bytes_left(0)
                .into();

            tracker
                .update_torrent_with_peer_and_get_stats(&info_hash.0.into(), &peer)
                .await;
        }

        fn build_scrape_request(remote_addr: &SocketAddr, info_hash: &InfoHash) -> ScrapeRequest {
            let info_hashes = vec![*info_hash];

            ScrapeRequest {
                connection_id: into_connection_id(&make(remote_addr)),
                transaction_id: TransactionId(0i32),
                info_hashes,
            }
        }

        async fn add_a_sample_seeder_and_scrape(tracker: Arc<tracker::Tracker>) -> Response {
            let remote_addr = sample_ipv4_remote_addr();
            let info_hash = InfoHash([0u8; 20]);

            add_a_seeder(tracker.clone(), &remote_addr, &info_hash).await;

            let request = build_scrape_request(&remote_addr, &info_hash);

            handle_scrape(remote_addr, &request, tracker.clone()).await.unwrap()
        }

        fn match_scrape_response(response: Response) -> Option<ScrapeResponse> {
            match response {
                Response::Scrape(scrape_response) => Some(scrape_response),
                _ => None,
            }
        }

        mod with_a_public_tracker {
            use aquatic_udp_protocol::{NumberOfDownloads, NumberOfPeers, TorrentScrapeStatistics};

            use crate::udp::handlers::tests::initialized_public_tracker;
            use crate::udp::handlers::tests::scrape_request::{add_a_sample_seeder_and_scrape, match_scrape_response};

            #[tokio::test]
            async fn should_return_torrent_statistics_when_the_tracker_has_the_requested_torrent() {
                let tracker = initialized_public_tracker();

                let torrent_stats = match_scrape_response(add_a_sample_seeder_and_scrape(tracker.clone()).await);

                let expected_torrent_stats = vec![TorrentScrapeStatistics {
                    seeders: NumberOfPeers(1),
                    completed: NumberOfDownloads(0),
                    leechers: NumberOfPeers(0),
                }];

                assert_eq!(torrent_stats.unwrap().torrent_stats, expected_torrent_stats);
            }
        }

        mod with_a_private_tracker {

            use aquatic_udp_protocol::InfoHash;

            use crate::udp::handlers::handle_scrape;
            use crate::udp::handlers::tests::scrape_request::{
                add_a_sample_seeder_and_scrape, build_scrape_request, match_scrape_response, zeroed_torrent_statistics,
            };
            use crate::udp::handlers::tests::{initialized_private_tracker, sample_ipv4_remote_addr};

            #[tokio::test]
            async fn should_return_zeroed_statistics_when_the_tracker_does_not_have_the_requested_torrent() {
                let tracker = initialized_private_tracker();

                let remote_addr = sample_ipv4_remote_addr();
                let non_existing_info_hash = InfoHash([0u8; 20]);

                let request = build_scrape_request(&remote_addr, &non_existing_info_hash);

                let torrent_stats =
                    match_scrape_response(handle_scrape(remote_addr, &request, tracker.clone()).await.unwrap()).unwrap();

                let expected_torrent_stats = vec![zeroed_torrent_statistics()];

                assert_eq!(torrent_stats.torrent_stats, expected_torrent_stats);
            }

            #[tokio::test]
            async fn should_return_zeroed_statistics_when_the_tracker_has_the_requested_torrent_because_authenticated_requests_are_not_supported_in_udp_tracker(
            ) {
                let tracker = initialized_private_tracker();

                let torrent_stats = match_scrape_response(add_a_sample_seeder_and_scrape(tracker.clone()).await).unwrap();

                let expected_torrent_stats = vec![zeroed_torrent_statistics()];

                assert_eq!(torrent_stats.torrent_stats, expected_torrent_stats);
            }
        }

        mod with_a_whitelisted_tracker {
            use aquatic_udp_protocol::{InfoHash, NumberOfDownloads, NumberOfPeers, TorrentScrapeStatistics};

            use crate::udp::handlers::handle_scrape;
            use crate::udp::handlers::tests::scrape_request::{
                add_a_seeder, build_scrape_request, match_scrape_response, zeroed_torrent_statistics,
            };
            use crate::udp::handlers::tests::{initialized_whitelisted_tracker, sample_ipv4_remote_addr};

            #[tokio::test]
            async fn should_return_the_torrent_statistics_when_the_requested_torrent_is_whitelisted() {
                let tracker = initialized_whitelisted_tracker();

                let remote_addr = sample_ipv4_remote_addr();
                let info_hash = InfoHash([0u8; 20]);

                add_a_seeder(tracker.clone(), &remote_addr, &info_hash).await;

                tracker.add_torrent_to_memory_whitelist(&info_hash.0.into()).await;

                let request = build_scrape_request(&remote_addr, &info_hash);

                let torrent_stats =
                    match_scrape_response(handle_scrape(remote_addr, &request, tracker.clone()).await.unwrap()).unwrap();

                let expected_torrent_stats = vec![TorrentScrapeStatistics {
                    seeders: NumberOfPeers(1),
                    completed: NumberOfDownloads(0),
                    leechers: NumberOfPeers(0),
                }];

                assert_eq!(torrent_stats.torrent_stats, expected_torrent_stats);
            }

            #[tokio::test]
            async fn should_return_zeroed_statistics_when_the_requested_torrent_is_not_whitelisted() {
                let tracker = initialized_whitelisted_tracker();

                let remote_addr = sample_ipv4_remote_addr();
                let info_hash = InfoHash([0u8; 20]);

                add_a_seeder(tracker.clone(), &remote_addr, &info_hash).await;

                let request = build_scrape_request(&remote_addr, &info_hash);

                let torrent_stats =
                    match_scrape_response(handle_scrape(remote_addr, &request, tracker.clone()).await.unwrap()).unwrap();

                let expected_torrent_stats = vec![zeroed_torrent_statistics()];

                assert_eq!(torrent_stats.torrent_stats, expected_torrent_stats);
            }
        }

        fn sample_scrape_request(remote_addr: &SocketAddr) -> ScrapeRequest {
            let info_hash = InfoHash([0u8; 20]);
            let info_hashes = vec![info_hash];

            ScrapeRequest {
                connection_id: into_connection_id(&make(remote_addr)),
                transaction_id: TransactionId(0i32),
                info_hashes,
            }
        }

        mod using_ipv4 {
            use std::future;
            use std::sync::Arc;

            use mockall::predicate::eq;

            use super::sample_scrape_request;
            use crate::tracker::{self, statistics};
            use crate::udp::handlers::handle_scrape;
            use crate::udp::handlers::tests::{sample_ipv4_remote_addr, tracker_configuration};

            #[tokio::test]
            async fn should_send_the_upd4_scrape_event() {
                let mut stats_event_sender_mock = statistics::MockEventSender::new();
                stats_event_sender_mock
                    .expect_send_event()
                    .with(eq(statistics::Event::Udp4Scrape))
                    .times(1)
                    .returning(|_| Box::pin(future::ready(Some(Ok(())))));
                let stats_event_sender = Box::new(stats_event_sender_mock);

                let remote_addr = sample_ipv4_remote_addr();
                let tracker = Arc::new(
                    tracker::Tracker::new(&tracker_configuration(), Some(stats_event_sender), statistics::Repo::new()).unwrap(),
                );

                handle_scrape(remote_addr, &sample_scrape_request(&remote_addr), tracker.clone())
                    .await
                    .unwrap();
            }
        }

        mod using_ipv6 {
            use std::future;
            use std::sync::Arc;

            use mockall::predicate::eq;

            use super::sample_scrape_request;
            use crate::tracker::{self, statistics};
            use crate::udp::handlers::handle_scrape;
            use crate::udp::handlers::tests::{sample_ipv6_remote_addr, tracker_configuration};

            #[tokio::test]
            async fn should_send_the_upd6_scrape_event() {
                let mut stats_event_sender_mock = statistics::MockEventSender::new();
                stats_event_sender_mock
                    .expect_send_event()
                    .with(eq(statistics::Event::Udp6Scrape))
                    .times(1)
                    .returning(|_| Box::pin(future::ready(Some(Ok(())))));
                let stats_event_sender = Box::new(stats_event_sender_mock);

                let remote_addr = sample_ipv6_remote_addr();
                let tracker = Arc::new(
                    tracker::Tracker::new(&tracker_configuration(), Some(stats_event_sender), statistics::Repo::new()).unwrap(),
                );

                handle_scrape(remote_addr, &sample_scrape_request(&remote_addr), tracker.clone())
                    .await
                    .unwrap();
            }
        }
    }
}
