//! Handlers for the UDP server.
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::panic::Location;
use std::sync::Arc;
use std::time::Instant;

use aquatic_udp_protocol::{
    AnnounceInterval, AnnounceRequest, AnnounceResponse, AnnounceResponseFixedData, ConnectRequest, ConnectResponse,
    ErrorResponse, Ipv4AddrBytes, Ipv6AddrBytes, NumberOfDownloads, NumberOfPeers, Port, Request, Response, ResponsePeer,
    ScrapeRequest, ScrapeResponse, TorrentScrapeStatistics, TransactionId,
};
use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_located_error::DynError;
use tracing::{instrument, Level};
use uuid::Uuid;
use zerocopy::network_endian::I32;

use super::connection_cookie::{check, from_connection_id, into_connection_id, make};
use super::RawRequest;
use crate::core::{statistics, PeersWanted, ScrapeData, Tracker};
use crate::servers::udp::error::Error;
use crate::servers::udp::logging::{log_bad_request, log_error_response, log_request, log_response};
use crate::servers::udp::peer_builder;
use crate::shared::bit_torrent::common::MAX_SCRAPE_TORRENTS;

/// It handles the incoming UDP packets.
///
/// It's responsible for:
///
/// - Parsing the incoming packet.
/// - Delegating the request to the correct handler depending on the request type.
///
/// It will return an `Error` response if the request is invalid.
#[instrument(skip(udp_request, tracker, local_addr), ret(level = Level::TRACE))]
pub(crate) async fn handle_packet(udp_request: RawRequest, tracker: &Tracker, local_addr: SocketAddr) -> Response {
    tracing::debug!("Handling Packets: {udp_request:?}");

    let start_time = Instant::now();

    let request_id = RequestId::make(&udp_request);

    match Request::parse_bytes(&udp_request.payload[..udp_request.payload.len()], MAX_SCRAPE_TORRENTS).map_err(|e| {
        Error::InternalServer {
            message: format!("{e:?}"),
            location: Location::caller(),
        }
    }) {
        Ok(request) => {
            log_request(&request, &request_id, &local_addr);

            let transaction_id = match &request {
                Request::Connect(connect_request) => connect_request.transaction_id,
                Request::Announce(announce_request) => announce_request.transaction_id,
                Request::Scrape(scrape_request) => scrape_request.transaction_id,
            };

            let response = match handle_request(request, udp_request.from, tracker).await {
                Ok(response) => response,
                Err(e) => handle_error(&e, transaction_id),
            };

            let latency = start_time.elapsed();

            log_response(&response, &transaction_id, &request_id, &local_addr, latency);

            response
        }
        Err(e) => {
            log_bad_request(&request_id);

            let response = handle_error(
                &Error::BadRequest {
                    source: (Arc::new(e) as DynError).into(),
                },
                TransactionId(I32::new(0)),
            );

            log_error_response(&request_id);

            response
        }
    }
}

/// It dispatches the request to the correct handler.
///
/// # Errors
///
/// If a error happens in the `handle_request` function, it will just return the  `ServerError`.
#[instrument(skip(request, remote_addr, tracker))]
pub async fn handle_request(request: Request, remote_addr: SocketAddr, tracker: &Tracker) -> Result<Response, Error> {
    tracing::trace!("handle request");

    match request {
        Request::Connect(connect_request) => handle_connect(remote_addr, &connect_request, tracker).await,
        Request::Announce(announce_request) => handle_announce(remote_addr, &announce_request, tracker).await,
        Request::Scrape(scrape_request) => handle_scrape(remote_addr, &scrape_request, tracker).await,
    }
}

/// It handles the `Connect` request. Refer to [`Connect`](crate::servers::udp#connect)
/// request for more information.
///
/// # Errors
///
/// This function does not ever return an error.
#[instrument(skip(tracker), err, ret(level = Level::TRACE))]
pub async fn handle_connect(remote_addr: SocketAddr, request: &ConnectRequest, tracker: &Tracker) -> Result<Response, Error> {
    tracing::trace!("handle connect");

    let connection_cookie = make(&remote_addr);
    let connection_id = into_connection_id(&connection_cookie);

    let response = ConnectResponse {
        transaction_id: request.transaction_id,
        connection_id,
    };

    // send stats event
    match remote_addr {
        SocketAddr::V4(_) => {
            tracker.send_stats_event(statistics::Event::Udp4Connect).await;
        }
        SocketAddr::V6(_) => {
            tracker.send_stats_event(statistics::Event::Udp6Connect).await;
        }
    }

    Ok(Response::from(response))
}

/// It handles the `Announce` request. Refer to [`Announce`](crate::servers::udp#announce)
/// request for more information.
///
/// # Errors
///
/// If a error happens in the `handle_announce` function, it will just return the  `ServerError`.
#[instrument(skip(tracker), err, ret(level = Level::TRACE))]
pub async fn handle_announce(
    remote_addr: SocketAddr,
    announce_request: &AnnounceRequest,
    tracker: &Tracker,
) -> Result<Response, Error> {
    tracing::trace!("handle announce");

    // Authentication
    if tracker.requires_authentication() {
        return Err(Error::TrackerAuthenticationRequired {
            location: Location::caller(),
        });
    }

    check(&remote_addr, &from_connection_id(&announce_request.connection_id))?;

    let info_hash = announce_request.info_hash.into();
    let remote_client_ip = remote_addr.ip();

    // Authorization
    tracker.authorize(&info_hash).await.map_err(|e| Error::TrackerError {
        source: (Arc::new(e) as Arc<dyn std::error::Error + Send + Sync>).into(),
    })?;

    let mut peer = peer_builder::from_request(announce_request, &remote_client_ip);
    let peers_wanted: PeersWanted = i32::from(announce_request.peers_wanted.0).into();

    let response = tracker.announce(&info_hash, &mut peer, &remote_client_ip, &peers_wanted);

    match remote_client_ip {
        IpAddr::V4(_) => {
            tracker.send_stats_event(statistics::Event::Udp4Announce).await;
        }
        IpAddr::V6(_) => {
            tracker.send_stats_event(statistics::Event::Udp6Announce).await;
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    if remote_addr.is_ipv4() {
        let announce_response = AnnounceResponse {
            fixed: AnnounceResponseFixedData {
                transaction_id: announce_request.transaction_id,
                announce_interval: AnnounceInterval(I32::new(i64::from(tracker.get_announce_policy().interval) as i32)),
                leechers: NumberOfPeers(I32::new(i64::from(response.stats.incomplete) as i32)),
                seeders: NumberOfPeers(I32::new(i64::from(response.stats.complete) as i32)),
            },
            peers: response
                .peers
                .iter()
                .filter_map(|peer| {
                    if let IpAddr::V4(ip) = peer.peer_addr.ip() {
                        Some(ResponsePeer::<Ipv4AddrBytes> {
                            ip_address: ip.into(),
                            port: Port(peer.peer_addr.port().into()),
                        })
                    } else {
                        None
                    }
                })
                .collect(),
        };

        Ok(Response::from(announce_response))
    } else {
        let announce_response = AnnounceResponse {
            fixed: AnnounceResponseFixedData {
                transaction_id: announce_request.transaction_id,
                announce_interval: AnnounceInterval(I32::new(i64::from(tracker.get_announce_policy().interval) as i32)),
                leechers: NumberOfPeers(I32::new(i64::from(response.stats.incomplete) as i32)),
                seeders: NumberOfPeers(I32::new(i64::from(response.stats.complete) as i32)),
            },
            peers: response
                .peers
                .iter()
                .filter_map(|peer| {
                    if let IpAddr::V6(ip) = peer.peer_addr.ip() {
                        Some(ResponsePeer::<Ipv6AddrBytes> {
                            ip_address: ip.into(),
                            port: Port(peer.peer_addr.port().into()),
                        })
                    } else {
                        None
                    }
                })
                .collect(),
        };

        Ok(Response::from(announce_response))
    }
}

/// It handles the `Scrape` request. Refer to [`Scrape`](crate::servers::udp#scrape)
/// request for more information.
///
/// # Errors
///
/// This function does not ever return an error.
#[instrument(skip(tracker), err, ret(level = Level::TRACE))]
pub async fn handle_scrape(remote_addr: SocketAddr, request: &ScrapeRequest, tracker: &Tracker) -> Result<Response, Error> {
    tracing::trace!("handle scrape");

    // Convert from aquatic infohashes
    let mut info_hashes: Vec<InfoHash> = vec![];
    for info_hash in &request.info_hashes {
        info_hashes.push((*info_hash).into());
    }

    let scrape_data = if tracker.requires_authentication() {
        ScrapeData::zeroed(&info_hashes)
    } else {
        tracker.scrape(&info_hashes).await
    };

    let mut torrent_stats: Vec<TorrentScrapeStatistics> = Vec::new();

    for file in &scrape_data.files {
        let swarm_metadata = file.1;

        #[allow(clippy::cast_possible_truncation)]
        let scrape_entry = {
            TorrentScrapeStatistics {
                seeders: NumberOfPeers(I32::new(i64::from(swarm_metadata.complete) as i32)),
                completed: NumberOfDownloads(I32::new(i64::from(swarm_metadata.downloaded) as i32)),
                leechers: NumberOfPeers(I32::new(i64::from(swarm_metadata.incomplete) as i32)),
            }
        };

        torrent_stats.push(scrape_entry);
    }

    // send stats event
    match remote_addr {
        SocketAddr::V4(_) => {
            tracker.send_stats_event(statistics::Event::Udp4Scrape).await;
        }
        SocketAddr::V6(_) => {
            tracker.send_stats_event(statistics::Event::Udp6Scrape).await;
        }
    }

    let response = ScrapeResponse {
        transaction_id: request.transaction_id,
        torrent_stats,
    };

    Ok(Response::from(response))
}

fn handle_error(e: &Error, transaction_id: TransactionId) -> Response {
    let message = e.to_string();
    Response::from(ErrorResponse {
        transaction_id,
        message: message.into(),
    })
}

/// An identifier for a request.
#[derive(Debug, Clone)]
pub struct RequestId(Uuid);

impl RequestId {
    fn make(_request: &RawRequest) -> RequestId {
        RequestId(Uuid::new_v4())
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;

    use aquatic_udp_protocol::{NumberOfBytes, PeerId};
    use torrust_tracker_clock::clock::Time;
    use torrust_tracker_configuration::Configuration;
    use torrust_tracker_primitives::peer;
    use torrust_tracker_test_helpers::configuration;

    use crate::core::services::tracker_factory;
    use crate::core::Tracker;
    use crate::CurrentClock;

    fn tracker_configuration() -> Configuration {
        default_testing_tracker_configuration()
    }

    fn default_testing_tracker_configuration() -> Configuration {
        configuration::ephemeral()
    }

    fn public_tracker() -> Arc<Tracker> {
        initialized_tracker(&configuration::ephemeral_public())
    }

    fn private_tracker() -> Arc<Tracker> {
        initialized_tracker(&configuration::ephemeral_private())
    }

    fn whitelisted_tracker() -> Arc<Tracker> {
        initialized_tracker(&configuration::ephemeral_listed())
    }

    fn initialized_tracker(configuration: &Configuration) -> Arc<Tracker> {
        tracker_factory(configuration).into()
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

    #[derive(Debug, Default)]
    pub struct TorrentPeerBuilder {
        peer: peer::Peer,
    }

    impl TorrentPeerBuilder {
        #[must_use]
        pub fn new() -> Self {
            Self {
                peer: peer::Peer {
                    updated: CurrentClock::now(),
                    ..Default::default()
                },
            }
        }

        #[must_use]
        pub fn with_peer_address(mut self, peer_addr: SocketAddr) -> Self {
            self.peer.peer_addr = peer_addr;
            self
        }

        #[must_use]
        pub fn with_peer_id(mut self, peer_id: PeerId) -> Self {
            self.peer.peer_id = peer_id;
            self
        }

        #[must_use]
        pub fn with_number_of_bytes_left(mut self, left: i64) -> Self {
            self.peer.left = NumberOfBytes::new(left);
            self
        }

        #[must_use]
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
            self.configuration.core.net.external_ip = Some(external_ip.to_owned().parse().expect("valid IP address"));
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
        use crate::core::{self, statistics};
        use crate::servers::udp::connection_cookie::{into_connection_id, make};
        use crate::servers::udp::handlers::handle_connect;
        use crate::servers::udp::handlers::tests::{public_tracker, sample_ipv4_remote_addr};

        fn sample_connect_request() -> ConnectRequest {
            ConnectRequest {
                transaction_id: TransactionId(0i32.into()),
            }
        }

        #[tokio::test]
        async fn a_connect_response_should_contain_the_same_transaction_id_as_the_connect_request() {
            let request = ConnectRequest {
                transaction_id: TransactionId(0i32.into()),
            };

            let response = handle_connect(sample_ipv4_remote_addr(), &request, &public_tracker())
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
                transaction_id: TransactionId(0i32.into()),
            };

            let response = handle_connect(sample_ipv4_remote_addr(), &request, &public_tracker())
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
                core::Tracker::new(
                    &tracker_configuration().core,
                    Some(stats_event_sender),
                    statistics::Repo::new(),
                )
                .unwrap(),
            );
            handle_connect(client_socket_address, &sample_connect_request(), &torrent_tracker)
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
                core::Tracker::new(
                    &tracker_configuration().core,
                    Some(stats_event_sender),
                    statistics::Repo::new(),
                )
                .unwrap(),
            );
            handle_connect(sample_ipv6_remote_addr(), &sample_connect_request(), &torrent_tracker)
                .await
                .unwrap();
        }
    }

    mod announce_request {

        use std::net::Ipv4Addr;
        use std::num::NonZeroU16;

        use aquatic_udp_protocol::{
            AnnounceActionPlaceholder, AnnounceEvent, AnnounceRequest, ConnectionId, NumberOfBytes, NumberOfPeers,
            PeerId as AquaticPeerId, PeerKey, Port, TransactionId,
        };

        use crate::servers::udp::connection_cookie::{into_connection_id, make};
        use crate::servers::udp::handlers::tests::sample_ipv4_remote_addr;

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
                    action_placeholder: AnnounceActionPlaceholder::default(),
                    transaction_id: TransactionId(0i32.into()),
                    info_hash: info_hash_aquatic,
                    peer_id: AquaticPeerId([255u8; 20]),
                    bytes_downloaded: NumberOfBytes(0i64.into()),
                    bytes_uploaded: NumberOfBytes(0i64.into()),
                    bytes_left: NumberOfBytes(0i64.into()),
                    event: AnnounceEvent::Started.into(),
                    ip_address: client_ip.into(),
                    key: PeerKey::new(0i32),
                    peers_wanted: NumberOfPeers::new(1i32),
                    port: Port::new(NonZeroU16::new(client_port).expect("a non-zero client port")),
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
                self.request.ip_address = ip_address.into();
                self
            }

            pub fn with_port(mut self, port: u16) -> Self {
                self.request.port = Port(port.into());
                self
            }

            pub fn into(self) -> AnnounceRequest {
                self.request
            }
        }

        mod using_ipv4 {

            use std::future;
            use std::net::{IpAddr, Ipv4Addr, SocketAddr};
            use std::sync::Arc;

            use aquatic_udp_protocol::{
                AnnounceInterval, AnnounceResponse, InfoHash as AquaticInfoHash, Ipv4AddrBytes, Ipv6AddrBytes, NumberOfPeers,
                PeerId as AquaticPeerId, Response, ResponsePeer,
            };
            use mockall::predicate::eq;

            use crate::core::{self, statistics};
            use crate::servers::udp::connection_cookie::{into_connection_id, make};
            use crate::servers::udp::handlers::tests::announce_request::AnnounceRequestBuilder;
            use crate::servers::udp::handlers::tests::{
                public_tracker, sample_ipv4_socket_address, tracker_configuration, TorrentPeerBuilder,
            };
            use crate::servers::udp::handlers::{handle_announce, AnnounceResponseFixedData};

            #[tokio::test]
            async fn an_announced_peer_should_be_added_to_the_tracker() {
                let tracker = public_tracker();

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

                handle_announce(remote_addr, &request, &tracker).await.unwrap();

                let peers = tracker.get_torrent_peers(&info_hash.0.into());

                let expected_peer = TorrentPeerBuilder::new()
                    .with_peer_id(peer_id)
                    .with_peer_address(SocketAddr::new(IpAddr::V4(client_ip), client_port))
                    .into();

                assert_eq!(peers[0], Arc::new(expected_peer));
            }

            #[tokio::test]
            async fn the_announced_peer_should_not_be_included_in_the_response() {
                let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .into();

                let response = handle_announce(remote_addr, &request, &public_tracker()).await.unwrap();

                let empty_peer_vector: Vec<ResponsePeer<Ipv4AddrBytes>> = vec![];
                assert_eq!(
                    response,
                    Response::from(AnnounceResponse {
                        fixed: AnnounceResponseFixedData {
                            transaction_id: request.transaction_id,
                            announce_interval: AnnounceInterval(120i32.into()),
                            leechers: NumberOfPeers(0i32.into()),
                            seeders: NumberOfPeers(1i32.into()),
                        },
                        peers: empty_peer_vector
                    })
                );
            }

            #[tokio::test]
            async fn the_tracker_should_always_use_the_remote_client_ip_but_not_the_port_in_the_udp_request_header_instead_of_the_peer_address_in_the_announce_request(
            ) {
                // From the BEP 15 (https://www.bittorrent.org/beps/bep_0015.html):
                // "Do note that most trackers will only honor the IP address field under limited circumstances."

                let tracker = public_tracker();

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

                handle_announce(remote_addr, &request, &tracker).await.unwrap();

                let peers = tracker.get_torrent_peers(&info_hash.0.into());

                assert_eq!(peers[0].peer_addr, SocketAddr::new(IpAddr::V4(remote_client_ip), client_port));
            }

            fn add_a_torrent_peer_using_ipv6(tracker: &Arc<core::Tracker>) {
                let info_hash = AquaticInfoHash([0u8; 20]);

                let client_ip_v4 = Ipv4Addr::new(126, 0, 0, 1);
                let client_ip_v6 = client_ip_v4.to_ipv6_compatible();
                let client_port = 8080;
                let peer_id = AquaticPeerId([255u8; 20]);

                let peer_using_ipv6 = TorrentPeerBuilder::new()
                    .with_peer_id(peer_id)
                    .with_peer_address(SocketAddr::new(IpAddr::V6(client_ip_v6), client_port))
                    .into();

                tracker.upsert_peer_and_get_stats(&info_hash.0.into(), &peer_using_ipv6);
            }

            async fn announce_a_new_peer_using_ipv4(tracker: Arc<core::Tracker>) -> Response {
                let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080);
                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .into();

                handle_announce(remote_addr, &request, &tracker).await.unwrap()
            }

            #[tokio::test]
            async fn when_the_announce_request_comes_from_a_client_using_ipv4_the_response_should_not_include_peers_using_ipv6() {
                let tracker = public_tracker();

                add_a_torrent_peer_using_ipv6(&tracker);

                let response = announce_a_new_peer_using_ipv4(tracker.clone()).await;

                // The response should not contain the peer using IPV6
                let peers: Option<Vec<ResponsePeer<Ipv6AddrBytes>>> = match response {
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
                    core::Tracker::new(
                        &tracker_configuration().core,
                        Some(stats_event_sender),
                        statistics::Repo::new(),
                    )
                    .unwrap(),
                );

                handle_announce(
                    sample_ipv4_socket_address(),
                    &AnnounceRequestBuilder::default().into(),
                    &tracker,
                )
                .await
                .unwrap();
            }

            mod from_a_loopback_ip {
                use std::net::{IpAddr, Ipv4Addr, SocketAddr};
                use std::sync::Arc;

                use aquatic_udp_protocol::{InfoHash as AquaticInfoHash, PeerId as AquaticPeerId};

                use crate::servers::udp::connection_cookie::{into_connection_id, make};
                use crate::servers::udp::handlers::handle_announce;
                use crate::servers::udp::handlers::tests::announce_request::AnnounceRequestBuilder;
                use crate::servers::udp::handlers::tests::{public_tracker, TorrentPeerBuilder};

                #[tokio::test]
                async fn the_peer_ip_should_be_changed_to_the_external_ip_in_the_tracker_configuration_if_defined() {
                    let tracker = public_tracker();

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

                    handle_announce(remote_addr, &request, &tracker).await.unwrap();

                    let peers = tracker.get_torrent_peers(&info_hash.0.into());

                    let external_ip_in_tracker_configuration = tracker.get_maybe_external_ip().unwrap();

                    let expected_peer = TorrentPeerBuilder::new()
                        .with_peer_id(peer_id)
                        .with_peer_address(SocketAddr::new(external_ip_in_tracker_configuration, client_port))
                        .into();

                    assert_eq!(peers[0], Arc::new(expected_peer));
                }
            }
        }

        mod using_ipv6 {

            use std::future;
            use std::net::{IpAddr, Ipv4Addr, SocketAddr};
            use std::sync::Arc;

            use aquatic_udp_protocol::{
                AnnounceInterval, AnnounceResponse, InfoHash as AquaticInfoHash, Ipv4AddrBytes, Ipv6AddrBytes, NumberOfPeers,
                PeerId as AquaticPeerId, Response, ResponsePeer,
            };
            use mockall::predicate::eq;

            use crate::core::{self, statistics};
            use crate::servers::udp::connection_cookie::{into_connection_id, make};
            use crate::servers::udp::handlers::tests::announce_request::AnnounceRequestBuilder;
            use crate::servers::udp::handlers::tests::{
                public_tracker, sample_ipv6_remote_addr, tracker_configuration, TorrentPeerBuilder,
            };
            use crate::servers::udp::handlers::{handle_announce, AnnounceResponseFixedData};

            #[tokio::test]
            async fn an_announced_peer_should_be_added_to_the_tracker() {
                let tracker = public_tracker();

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

                handle_announce(remote_addr, &request, &tracker).await.unwrap();

                let peers = tracker.get_torrent_peers(&info_hash.0.into());

                let expected_peer = TorrentPeerBuilder::new()
                    .with_peer_id(peer_id)
                    .with_peer_address(SocketAddr::new(IpAddr::V6(client_ip_v6), client_port))
                    .into();

                assert_eq!(peers[0], Arc::new(expected_peer));
            }

            #[tokio::test]
            async fn the_announced_peer_should_not_be_included_in_the_response() {
                let client_ip_v4 = Ipv4Addr::new(126, 0, 0, 1);
                let client_ip_v6 = client_ip_v4.to_ipv6_compatible();

                let remote_addr = SocketAddr::new(IpAddr::V6(client_ip_v6), 8080);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .into();

                let response = handle_announce(remote_addr, &request, &public_tracker()).await.unwrap();

                let empty_peer_vector: Vec<ResponsePeer<Ipv6AddrBytes>> = vec![];
                assert_eq!(
                    response,
                    Response::from(AnnounceResponse {
                        fixed: AnnounceResponseFixedData {
                            transaction_id: request.transaction_id,
                            announce_interval: AnnounceInterval(120i32.into()),
                            leechers: NumberOfPeers(0i32.into()),
                            seeders: NumberOfPeers(1i32.into()),
                        },
                        peers: empty_peer_vector
                    })
                );
            }

            #[tokio::test]
            async fn the_tracker_should_always_use_the_remote_client_ip_but_not_the_port_in_the_udp_request_header_instead_of_the_peer_address_in_the_announce_request(
            ) {
                // From the BEP 15 (https://www.bittorrent.org/beps/bep_0015.html):
                // "Do note that most trackers will only honor the IP address field under limited circumstances."

                let tracker = public_tracker();

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

                handle_announce(remote_addr, &request, &tracker).await.unwrap();

                let peers = tracker.get_torrent_peers(&info_hash.0.into());

                // When using IPv6 the tracker converts the remote client ip into a IPv4 address
                assert_eq!(peers[0].peer_addr, SocketAddr::new(IpAddr::V6(remote_client_ip), client_port));
            }

            fn add_a_torrent_peer_using_ipv4(tracker: &Arc<core::Tracker>) {
                let info_hash = AquaticInfoHash([0u8; 20]);

                let client_ip_v4 = Ipv4Addr::new(126, 0, 0, 1);
                let client_port = 8080;
                let peer_id = AquaticPeerId([255u8; 20]);

                let peer_using_ipv4 = TorrentPeerBuilder::new()
                    .with_peer_id(peer_id)
                    .with_peer_address(SocketAddr::new(IpAddr::V4(client_ip_v4), client_port))
                    .into();

                tracker.upsert_peer_and_get_stats(&info_hash.0.into(), &peer_using_ipv4);
            }

            async fn announce_a_new_peer_using_ipv6(tracker: Arc<core::Tracker>) -> Response {
                let client_ip_v4 = Ipv4Addr::new(126, 0, 0, 1);
                let client_ip_v6 = client_ip_v4.to_ipv6_compatible();
                let client_port = 8080;
                let remote_addr = SocketAddr::new(IpAddr::V6(client_ip_v6), client_port);
                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .into();

                handle_announce(remote_addr, &request, &tracker).await.unwrap()
            }

            #[tokio::test]
            async fn when_the_announce_request_comes_from_a_client_using_ipv6_the_response_should_not_include_peers_using_ipv4() {
                let tracker = public_tracker();

                add_a_torrent_peer_using_ipv4(&tracker);

                let response = announce_a_new_peer_using_ipv6(tracker.clone()).await;

                // The response should not contain the peer using IPV4
                let peers: Option<Vec<ResponsePeer<Ipv4AddrBytes>>> = match response {
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
                    core::Tracker::new(
                        &tracker_configuration().core,
                        Some(stats_event_sender),
                        statistics::Repo::new(),
                    )
                    .unwrap(),
                );

                let remote_addr = sample_ipv6_remote_addr();

                let announce_request = AnnounceRequestBuilder::default()
                    .with_connection_id(into_connection_id(&make(&remote_addr)))
                    .into();

                handle_announce(remote_addr, &announce_request, &tracker).await.unwrap();
            }

            mod from_a_loopback_ip {
                use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
                use std::sync::Arc;

                use aquatic_udp_protocol::{InfoHash as AquaticInfoHash, PeerId as AquaticPeerId};

                use crate::core;
                use crate::core::statistics::Keeper;
                use crate::servers::udp::connection_cookie::{into_connection_id, make};
                use crate::servers::udp::handlers::handle_announce;
                use crate::servers::udp::handlers::tests::announce_request::AnnounceRequestBuilder;
                use crate::servers::udp::handlers::tests::TrackerConfigurationBuilder;

                #[tokio::test]
                async fn the_peer_ip_should_be_changed_to_the_external_ip_in_the_tracker_configuration() {
                    let configuration = Arc::new(TrackerConfigurationBuilder::default().with_external_ip("::126.0.0.1").into());
                    let (stats_event_sender, stats_repository) = Keeper::new_active_instance();
                    let tracker =
                        Arc::new(core::Tracker::new(&configuration.core, Some(stats_event_sender), stats_repository).unwrap());

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

                    handle_announce(remote_addr, &request, &tracker).await.unwrap();

                    let peers = tracker.get_torrent_peers(&info_hash.0.into());

                    let external_ip_in_tracker_configuration = tracker.get_maybe_external_ip().unwrap();

                    assert!(external_ip_in_tracker_configuration.is_ipv6());

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
            InfoHash, NumberOfDownloads, NumberOfPeers, PeerId, Response, ScrapeRequest, ScrapeResponse, TorrentScrapeStatistics,
            TransactionId,
        };

        use super::TorrentPeerBuilder;
        use crate::core::{self};
        use crate::servers::udp::connection_cookie::{into_connection_id, make};
        use crate::servers::udp::handlers::handle_scrape;
        use crate::servers::udp::handlers::tests::{public_tracker, sample_ipv4_remote_addr};

        fn zeroed_torrent_statistics() -> TorrentScrapeStatistics {
            TorrentScrapeStatistics {
                seeders: NumberOfPeers(0.into()),
                completed: NumberOfDownloads(0.into()),
                leechers: NumberOfPeers(0.into()),
            }
        }

        #[tokio::test]
        async fn should_return_no_stats_when_the_tracker_does_not_have_any_torrent() {
            let remote_addr = sample_ipv4_remote_addr();

            let info_hash = InfoHash([0u8; 20]);
            let info_hashes = vec![info_hash];

            let request = ScrapeRequest {
                connection_id: into_connection_id(&make(&remote_addr)),
                transaction_id: TransactionId(0i32.into()),
                info_hashes,
            };

            let response = handle_scrape(remote_addr, &request, &public_tracker()).await.unwrap();

            let expected_torrent_stats = vec![zeroed_torrent_statistics()];

            assert_eq!(
                response,
                Response::from(ScrapeResponse {
                    transaction_id: request.transaction_id,
                    torrent_stats: expected_torrent_stats
                })
            );
        }

        async fn add_a_seeder(tracker: Arc<core::Tracker>, remote_addr: &SocketAddr, info_hash: &InfoHash) {
            let peer_id = PeerId([255u8; 20]);

            let peer = TorrentPeerBuilder::new()
                .with_peer_id(peer_id)
                .with_peer_address(*remote_addr)
                .with_number_of_bytes_left(0)
                .into();

            tracker.upsert_peer_and_get_stats(&info_hash.0.into(), &peer);
        }

        fn build_scrape_request(remote_addr: &SocketAddr, info_hash: &InfoHash) -> ScrapeRequest {
            let info_hashes = vec![*info_hash];

            ScrapeRequest {
                connection_id: into_connection_id(&make(remote_addr)),
                transaction_id: TransactionId::new(0i32),
                info_hashes,
            }
        }

        async fn add_a_sample_seeder_and_scrape(tracker: Arc<core::Tracker>) -> Response {
            let remote_addr = sample_ipv4_remote_addr();
            let info_hash = InfoHash([0u8; 20]);

            add_a_seeder(tracker.clone(), &remote_addr, &info_hash).await;

            let request = build_scrape_request(&remote_addr, &info_hash);

            handle_scrape(remote_addr, &request, &tracker).await.unwrap()
        }

        fn match_scrape_response(response: Response) -> Option<ScrapeResponse> {
            match response {
                Response::Scrape(scrape_response) => Some(scrape_response),
                _ => None,
            }
        }

        mod with_a_public_tracker {
            use aquatic_udp_protocol::{NumberOfDownloads, NumberOfPeers, TorrentScrapeStatistics};

            use crate::servers::udp::handlers::tests::public_tracker;
            use crate::servers::udp::handlers::tests::scrape_request::{add_a_sample_seeder_and_scrape, match_scrape_response};

            #[tokio::test]
            async fn should_return_torrent_statistics_when_the_tracker_has_the_requested_torrent() {
                let tracker = public_tracker();

                let torrent_stats = match_scrape_response(add_a_sample_seeder_and_scrape(tracker.clone()).await);

                let expected_torrent_stats = vec![TorrentScrapeStatistics {
                    seeders: NumberOfPeers(1.into()),
                    completed: NumberOfDownloads(0.into()),
                    leechers: NumberOfPeers(0.into()),
                }];

                assert_eq!(torrent_stats.unwrap().torrent_stats, expected_torrent_stats);
            }
        }

        mod with_a_private_tracker {

            use aquatic_udp_protocol::InfoHash;

            use crate::servers::udp::handlers::handle_scrape;
            use crate::servers::udp::handlers::tests::scrape_request::{
                add_a_sample_seeder_and_scrape, build_scrape_request, match_scrape_response, zeroed_torrent_statistics,
            };
            use crate::servers::udp::handlers::tests::{private_tracker, sample_ipv4_remote_addr};

            #[tokio::test]
            async fn should_return_zeroed_statistics_when_the_tracker_does_not_have_the_requested_torrent() {
                let tracker = private_tracker();

                let remote_addr = sample_ipv4_remote_addr();
                let non_existing_info_hash = InfoHash([0u8; 20]);

                let request = build_scrape_request(&remote_addr, &non_existing_info_hash);

                let torrent_stats = match_scrape_response(handle_scrape(remote_addr, &request, &tracker).await.unwrap()).unwrap();

                let expected_torrent_stats = vec![zeroed_torrent_statistics()];

                assert_eq!(torrent_stats.torrent_stats, expected_torrent_stats);
            }

            #[tokio::test]
            async fn should_return_zeroed_statistics_when_the_tracker_has_the_requested_torrent_because_authenticated_requests_are_not_supported_in_udp_tracker(
            ) {
                let tracker = private_tracker();

                let torrent_stats = match_scrape_response(add_a_sample_seeder_and_scrape(tracker.clone()).await).unwrap();

                let expected_torrent_stats = vec![zeroed_torrent_statistics()];

                assert_eq!(torrent_stats.torrent_stats, expected_torrent_stats);
            }
        }

        mod with_a_whitelisted_tracker {
            use aquatic_udp_protocol::{InfoHash, NumberOfDownloads, NumberOfPeers, TorrentScrapeStatistics};

            use crate::servers::udp::handlers::handle_scrape;
            use crate::servers::udp::handlers::tests::scrape_request::{
                add_a_seeder, build_scrape_request, match_scrape_response, zeroed_torrent_statistics,
            };
            use crate::servers::udp::handlers::tests::{sample_ipv4_remote_addr, whitelisted_tracker};

            #[tokio::test]
            async fn should_return_the_torrent_statistics_when_the_requested_torrent_is_whitelisted() {
                let tracker = whitelisted_tracker();

                let remote_addr = sample_ipv4_remote_addr();
                let info_hash = InfoHash([0u8; 20]);

                add_a_seeder(tracker.clone(), &remote_addr, &info_hash).await;

                tracker.add_torrent_to_memory_whitelist(&info_hash.0.into()).await;

                let request = build_scrape_request(&remote_addr, &info_hash);

                let torrent_stats = match_scrape_response(handle_scrape(remote_addr, &request, &tracker).await.unwrap()).unwrap();

                let expected_torrent_stats = vec![TorrentScrapeStatistics {
                    seeders: NumberOfPeers(1.into()),
                    completed: NumberOfDownloads(0.into()),
                    leechers: NumberOfPeers(0.into()),
                }];

                assert_eq!(torrent_stats.torrent_stats, expected_torrent_stats);
            }

            #[tokio::test]
            async fn should_return_zeroed_statistics_when_the_requested_torrent_is_not_whitelisted() {
                let tracker = whitelisted_tracker();

                let remote_addr = sample_ipv4_remote_addr();
                let info_hash = InfoHash([0u8; 20]);

                add_a_seeder(tracker.clone(), &remote_addr, &info_hash).await;

                let request = build_scrape_request(&remote_addr, &info_hash);

                let torrent_stats = match_scrape_response(handle_scrape(remote_addr, &request, &tracker).await.unwrap()).unwrap();

                let expected_torrent_stats = vec![zeroed_torrent_statistics()];

                assert_eq!(torrent_stats.torrent_stats, expected_torrent_stats);
            }
        }

        fn sample_scrape_request(remote_addr: &SocketAddr) -> ScrapeRequest {
            let info_hash = InfoHash([0u8; 20]);
            let info_hashes = vec![info_hash];

            ScrapeRequest {
                connection_id: into_connection_id(&make(remote_addr)),
                transaction_id: TransactionId(0i32.into()),
                info_hashes,
            }
        }

        mod using_ipv4 {
            use std::future;
            use std::sync::Arc;

            use mockall::predicate::eq;

            use super::sample_scrape_request;
            use crate::core::{self, statistics};
            use crate::servers::udp::handlers::handle_scrape;
            use crate::servers::udp::handlers::tests::{sample_ipv4_remote_addr, tracker_configuration};

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
                    core::Tracker::new(
                        &tracker_configuration().core,
                        Some(stats_event_sender),
                        statistics::Repo::new(),
                    )
                    .unwrap(),
                );

                handle_scrape(remote_addr, &sample_scrape_request(&remote_addr), &tracker)
                    .await
                    .unwrap();
            }
        }

        mod using_ipv6 {
            use std::future;
            use std::sync::Arc;

            use mockall::predicate::eq;

            use super::sample_scrape_request;
            use crate::core::{self, statistics};
            use crate::servers::udp::handlers::handle_scrape;
            use crate::servers::udp::handlers::tests::{sample_ipv6_remote_addr, tracker_configuration};

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
                    core::Tracker::new(
                        &tracker_configuration().core,
                        Some(stats_event_sender),
                        statistics::Repo::new(),
                    )
                    .unwrap(),
                );

                handle_scrape(remote_addr, &sample_scrape_request(&remote_addr), &tracker)
                    .await
                    .unwrap();
            }
        }
    }
}
