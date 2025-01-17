//! Handlers for the UDP server.
use std::hash::{DefaultHasher, Hash, Hasher as _};
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::sync::Arc;
use std::time::Instant;

use aquatic_udp_protocol::{
    AnnounceInterval, AnnounceRequest, AnnounceResponse, AnnounceResponseFixedData, ConnectRequest, ConnectResponse,
    ErrorResponse, Ipv4AddrBytes, Ipv6AddrBytes, NumberOfDownloads, NumberOfPeers, Port, Request, RequestParseError, Response,
    ResponsePeer, ScrapeRequest, ScrapeResponse, TorrentScrapeStatistics, TransactionId,
};
use bittorrent_primitives::info_hash::InfoHash;
use tokio::sync::RwLock;
use torrust_tracker_clock::clock::Time as _;
use tracing::{instrument, Level};
use uuid::Uuid;
use zerocopy::network_endian::I32;

use super::connection_cookie::{check, make};
use super::server::banning::BanService;
use super::RawRequest;
use crate::core::statistics::event::sender::Sender;
use crate::core::{statistics, PeersWanted, Tracker};
use crate::servers::udp::error::Error;
use crate::servers::udp::{peer_builder, UDP_TRACKER_LOG_TARGET};
use crate::shared::bit_torrent::common::MAX_SCRAPE_TORRENTS;
use crate::CurrentClock;

#[derive(Debug, Clone, PartialEq)]
pub(super) struct CookieTimeValues {
    pub(super) issue_time: f64,
    pub(super) valid_range: Range<f64>,
}

impl CookieTimeValues {
    pub(super) fn new(cookie_lifetime: f64) -> Self {
        let issue_time = CurrentClock::now().as_secs_f64();
        let expiry_time = issue_time - cookie_lifetime - 1.0;
        let tolerance_max_time = issue_time + 1.0;

        Self {
            issue_time,
            valid_range: expiry_time..tolerance_max_time,
        }
    }
}

/// It handles the incoming UDP packets.
///
/// It's responsible for:
///
/// - Parsing the incoming packet.
/// - Delegating the request to the correct handler depending on the request type.
///
/// It will return an `Error` response if the request is invalid.
#[instrument(fields(request_id), skip(udp_request, tracker, opt_stats_event_sender, cookie_time_values, ban_service), ret(level = Level::TRACE))]
pub(crate) async fn handle_packet(
    udp_request: RawRequest,
    tracker: &Tracker,
    opt_stats_event_sender: &Arc<Option<Box<dyn Sender>>>,
    local_addr: SocketAddr,
    cookie_time_values: CookieTimeValues,
    ban_service: Arc<RwLock<BanService>>,
) -> Response {
    let request_id = Uuid::new_v4();

    tracing::Span::current().record("request_id", request_id.to_string());
    tracing::debug!("Handling Packets: {udp_request:?}");

    let start_time = Instant::now();

    let response =
        match Request::parse_bytes(&udp_request.payload[..udp_request.payload.len()], MAX_SCRAPE_TORRENTS).map_err(Error::from) {
            Ok(request) => match handle_request(
                request,
                udp_request.from,
                tracker,
                opt_stats_event_sender,
                cookie_time_values.clone(),
            )
            .await
            {
                Ok(response) => return response,
                Err((e, transaction_id)) => {
                    match &e {
                        Error::CookieValueNotNormal { .. }
                        | Error::CookieValueExpired { .. }
                        | Error::CookieValueFromFuture { .. } => {
                            // code-review: should we include `RequestParseError` and `BadRequest`?
                            let mut ban_service = ban_service.write().await;
                            ban_service.increase_counter(&udp_request.from.ip());
                        }
                        _ => {}
                    }

                    handle_error(
                        udp_request.from,
                        local_addr,
                        request_id,
                        opt_stats_event_sender,
                        cookie_time_values.valid_range.clone(),
                        &e,
                        Some(transaction_id),
                    )
                    .await
                }
            },
            Err(e) => {
                handle_error(
                    udp_request.from,
                    local_addr,
                    request_id,
                    opt_stats_event_sender,
                    cookie_time_values.valid_range.clone(),
                    &e,
                    None,
                )
                .await
            }
        };

    let latency = start_time.elapsed();
    tracing::trace!(?latency, "responded");

    response
}

/// It dispatches the request to the correct handler.
///
/// # Errors
///
/// If a error happens in the `handle_request` function, it will just return the  `ServerError`.
#[instrument(skip(request, remote_addr, tracker, opt_stats_event_sender, cookie_time_values))]
pub async fn handle_request(
    request: Request,
    remote_addr: SocketAddr,
    tracker: &Tracker,
    opt_stats_event_sender: &Arc<Option<Box<dyn Sender>>>,
    cookie_time_values: CookieTimeValues,
) -> Result<Response, (Error, TransactionId)> {
    tracing::trace!("handle request");

    match request {
        Request::Connect(connect_request) => Ok(handle_connect(
            remote_addr,
            &connect_request,
            opt_stats_event_sender,
            cookie_time_values.issue_time,
        )
        .await),
        Request::Announce(announce_request) => {
            handle_announce(
                remote_addr,
                &announce_request,
                tracker,
                opt_stats_event_sender,
                cookie_time_values.valid_range,
            )
            .await
        }
        Request::Scrape(scrape_request) => {
            handle_scrape(
                remote_addr,
                &scrape_request,
                tracker,
                opt_stats_event_sender,
                cookie_time_values.valid_range,
            )
            .await
        }
    }
}

/// It handles the `Connect` request. Refer to [`Connect`](crate::servers::udp#connect)
/// request for more information.
///
/// # Errors
///
/// This function does not ever return an error.
#[instrument(fields(transaction_id), skip(opt_stats_event_sender), ret(level = Level::TRACE))]
pub async fn handle_connect(
    remote_addr: SocketAddr,
    request: &ConnectRequest,
    opt_stats_event_sender: &Arc<Option<Box<dyn Sender>>>,
    cookie_issue_time: f64,
) -> Response {
    tracing::Span::current().record("transaction_id", request.transaction_id.0.to_string());

    tracing::trace!("handle connect");

    let connection_id = make(gen_remote_fingerprint(&remote_addr), cookie_issue_time).expect("it should be a normal value");

    let response = ConnectResponse {
        transaction_id: request.transaction_id,
        connection_id,
    };

    if let Some(stats_event_sender) = opt_stats_event_sender.as_deref() {
        match remote_addr {
            SocketAddr::V4(_) => {
                stats_event_sender.send_event(statistics::event::Event::Udp4Connect).await;
            }
            SocketAddr::V6(_) => {
                stats_event_sender.send_event(statistics::event::Event::Udp6Connect).await;
            }
        }
    }

    Response::from(response)
}

/// It handles the `Announce` request. Refer to [`Announce`](crate::servers::udp#announce)
/// request for more information.
///
/// # Errors
///
/// If a error happens in the `handle_announce` function, it will just return the  `ServerError`.
#[instrument(fields(transaction_id, connection_id, info_hash), skip(tracker, opt_stats_event_sender), ret(level = Level::TRACE))]
pub async fn handle_announce(
    remote_addr: SocketAddr,
    request: &AnnounceRequest,
    tracker: &Tracker,
    opt_stats_event_sender: &Arc<Option<Box<dyn Sender>>>,
    cookie_valid_range: Range<f64>,
) -> Result<Response, (Error, TransactionId)> {
    tracing::Span::current()
        .record("transaction_id", request.transaction_id.0.to_string())
        .record("connection_id", request.connection_id.0.to_string())
        .record("info_hash", InfoHash::from_bytes(&request.info_hash.0).to_hex_string());

    tracing::trace!("handle announce");

    check(
        &request.connection_id,
        gen_remote_fingerprint(&remote_addr),
        cookie_valid_range,
    )
    .map_err(|e| (e, request.transaction_id))?;

    let info_hash = request.info_hash.into();
    let remote_client_ip = remote_addr.ip();

    // Authorization
    tracker
        .authorize(&info_hash)
        .await
        .map_err(|e| Error::TrackerError {
            source: (Arc::new(e) as Arc<dyn std::error::Error + Send + Sync>).into(),
        })
        .map_err(|e| (e, request.transaction_id))?;

    let mut peer = peer_builder::from_request(request, &remote_client_ip);
    let peers_wanted: PeersWanted = i32::from(request.peers_wanted.0).into();

    let response = tracker.announce(&info_hash, &mut peer, &remote_client_ip, &peers_wanted);

    if let Some(stats_event_sender) = opt_stats_event_sender.as_deref() {
        match remote_client_ip {
            IpAddr::V4(_) => {
                stats_event_sender.send_event(statistics::event::Event::Udp4Announce).await;
            }
            IpAddr::V6(_) => {
                stats_event_sender.send_event(statistics::event::Event::Udp6Announce).await;
            }
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    if remote_addr.is_ipv4() {
        let announce_response = AnnounceResponse {
            fixed: AnnounceResponseFixedData {
                transaction_id: request.transaction_id,
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
                transaction_id: request.transaction_id,
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
#[instrument(fields(transaction_id, connection_id), skip(tracker, opt_stats_event_sender),  ret(level = Level::TRACE))]
pub async fn handle_scrape(
    remote_addr: SocketAddr,
    request: &ScrapeRequest,
    tracker: &Tracker,
    opt_stats_event_sender: &Arc<Option<Box<dyn Sender>>>,
    cookie_valid_range: Range<f64>,
) -> Result<Response, (Error, TransactionId)> {
    tracing::Span::current()
        .record("transaction_id", request.transaction_id.0.to_string())
        .record("connection_id", request.connection_id.0.to_string());

    tracing::trace!("handle scrape");

    check(
        &request.connection_id,
        gen_remote_fingerprint(&remote_addr),
        cookie_valid_range,
    )
    .map_err(|e| (e, request.transaction_id))?;

    // Convert from aquatic infohashes
    let mut info_hashes: Vec<InfoHash> = vec![];
    for info_hash in &request.info_hashes {
        info_hashes.push((*info_hash).into());
    }

    let scrape_data = tracker.scrape(&info_hashes).await;

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

    if let Some(stats_event_sender) = opt_stats_event_sender.as_deref() {
        match remote_addr {
            SocketAddr::V4(_) => {
                stats_event_sender.send_event(statistics::event::Event::Udp4Scrape).await;
            }
            SocketAddr::V6(_) => {
                stats_event_sender.send_event(statistics::event::Event::Udp6Scrape).await;
            }
        }
    }

    let response = ScrapeResponse {
        transaction_id: request.transaction_id,
        torrent_stats,
    };

    Ok(Response::from(response))
}

#[instrument(fields(transaction_id), skip(opt_stats_event_sender), ret(level = Level::TRACE))]
async fn handle_error(
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    request_id: Uuid,
    opt_stats_event_sender: &Arc<Option<Box<dyn Sender>>>,
    cookie_valid_range: Range<f64>,
    e: &Error,
    transaction_id: Option<TransactionId>,
) -> Response {
    tracing::trace!("handle error");

    match transaction_id {
        Some(transaction_id) => {
            let transaction_id = transaction_id.0.to_string();
            tracing::error!(target: UDP_TRACKER_LOG_TARGET, error = %e, %remote_addr, %local_addr, %request_id, %transaction_id, "response error");
        }
        None => {
            tracing::error!(target: UDP_TRACKER_LOG_TARGET, error = %e, %remote_addr, %local_addr, %request_id, "response error");
        }
    }

    let e = if let Error::RequestParseError { request_parse_error } = e {
        match request_parse_error {
            RequestParseError::Sendable {
                connection_id,
                transaction_id,
                err,
            } => {
                if let Err(e) = check(connection_id, gen_remote_fingerprint(&remote_addr), cookie_valid_range) {
                    (e.to_string(), Some(*transaction_id))
                } else {
                    ((*err).to_string(), Some(*transaction_id))
                }
            }
            RequestParseError::Unsendable { err } => (err.to_string(), transaction_id),
        }
    } else {
        (e.to_string(), transaction_id)
    };

    if e.1.is_some() {
        if let Some(stats_event_sender) = opt_stats_event_sender.as_deref() {
            match remote_addr {
                SocketAddr::V4(_) => {
                    stats_event_sender.send_event(statistics::event::Event::Udp4Error).await;
                }
                SocketAddr::V6(_) => {
                    stats_event_sender.send_event(statistics::event::Event::Udp6Error).await;
                }
            }
        }
    }

    Response::from(ErrorResponse {
        transaction_id: e.1.unwrap_or(TransactionId(I32::new(0))),
        message: e.0.into(),
    })
}

fn gen_remote_fingerprint(remote_addr: &SocketAddr) -> u64 {
    let mut state = DefaultHasher::new();
    remote_addr.hash(&mut state);
    state.finish()
}

#[cfg(test)]
mod tests {

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::ops::Range;

    use aquatic_udp_protocol::{NumberOfBytes, PeerId};
    use torrust_tracker_clock::clock::Time;
    use torrust_tracker_configuration::Configuration;
    use torrust_tracker_primitives::peer;
    use torrust_tracker_test_helpers::configuration;

    use super::gen_remote_fingerprint;
    use crate::bootstrap::app::initialize_tracker_dependencies;
    use crate::core::services::{statistics, tracker_factory};
    use crate::core::statistics::event::sender::Sender;
    use crate::core::Tracker;
    use crate::CurrentClock;

    fn tracker_configuration() -> Configuration {
        default_testing_tracker_configuration()
    }

    fn default_testing_tracker_configuration() -> Configuration {
        configuration::ephemeral()
    }

    fn public_tracker() -> (Tracker, Option<Box<dyn Sender>>) {
        initialized_tracker(&configuration::ephemeral_public())
    }

    fn whitelisted_tracker() -> (Tracker, Option<Box<dyn Sender>>) {
        initialized_tracker(&configuration::ephemeral_listed())
    }

    fn initialized_tracker(config: &Configuration) -> (Tracker, Option<Box<dyn Sender>>) {
        let (database, whitelist_manager) = initialize_tracker_dependencies(config);
        let (stats_event_sender, _stats_repository) = statistics::setup::factory(config.core.tracker_usage_statistics);

        (tracker_factory(config, &database, &whitelist_manager), stats_event_sender)
    }

    fn sample_ipv4_remote_addr() -> SocketAddr {
        sample_ipv4_socket_address()
    }

    fn sample_ipv4_remote_addr_fingerprint() -> u64 {
        gen_remote_fingerprint(&sample_ipv4_socket_address())
    }

    fn sample_ipv6_remote_addr() -> SocketAddr {
        sample_ipv6_socket_address()
    }

    fn sample_ipv6_remote_addr_fingerprint() -> u64 {
        gen_remote_fingerprint(&sample_ipv6_socket_address())
    }

    fn sample_ipv4_socket_address() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    fn sample_ipv6_socket_address() -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080)
    }

    fn sample_issue_time() -> f64 {
        1_000_000_000_f64
    }

    fn sample_cookie_valid_range() -> Range<f64> {
        sample_issue_time() - 10.0..sample_issue_time() + 10.0
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

    fn test_tracker_factory() -> Tracker {
        let config = tracker_configuration();

        let (database, whitelist_manager) = initialize_tracker_dependencies(&config);

        Tracker::new(&config.core, &database, &whitelist_manager).unwrap()
    }

    mod connect_request {

        use std::future;
        use std::sync::Arc;

        use aquatic_udp_protocol::{ConnectRequest, ConnectResponse, Response, TransactionId};
        use mockall::predicate::eq;

        use super::{sample_ipv4_socket_address, sample_ipv6_remote_addr};
        use crate::core::statistics;
        use crate::servers::udp::connection_cookie::make;
        use crate::servers::udp::handlers::handle_connect;
        use crate::servers::udp::handlers::tests::{
            sample_ipv4_remote_addr, sample_ipv4_remote_addr_fingerprint, sample_ipv6_remote_addr_fingerprint, sample_issue_time,
        };

        fn sample_connect_request() -> ConnectRequest {
            ConnectRequest {
                transaction_id: TransactionId(0i32.into()),
            }
        }

        #[tokio::test]
        async fn a_connect_response_should_contain_the_same_transaction_id_as_the_connect_request() {
            let (stats_event_sender, _stats_repository) = crate::core::services::statistics::setup::factory(false);
            let stats_event_sender = Arc::new(stats_event_sender);

            let request = ConnectRequest {
                transaction_id: TransactionId(0i32.into()),
            };

            let response = handle_connect(sample_ipv4_remote_addr(), &request, &stats_event_sender, sample_issue_time()).await;

            assert_eq!(
                response,
                Response::Connect(ConnectResponse {
                    connection_id: make(sample_ipv4_remote_addr_fingerprint(), sample_issue_time()).unwrap(),
                    transaction_id: request.transaction_id
                })
            );
        }

        #[tokio::test]
        async fn a_connect_response_should_contain_a_new_connection_id() {
            let (stats_event_sender, _stats_repository) = crate::core::services::statistics::setup::factory(false);
            let stats_event_sender = Arc::new(stats_event_sender);

            let request = ConnectRequest {
                transaction_id: TransactionId(0i32.into()),
            };

            let response = handle_connect(sample_ipv4_remote_addr(), &request, &stats_event_sender, sample_issue_time()).await;

            assert_eq!(
                response,
                Response::Connect(ConnectResponse {
                    connection_id: make(sample_ipv4_remote_addr_fingerprint(), sample_issue_time()).unwrap(),
                    transaction_id: request.transaction_id
                })
            );
        }

        #[tokio::test]
        async fn a_connect_response_should_contain_a_new_connection_id_ipv6() {
            let (stats_event_sender, _stats_repository) = crate::core::services::statistics::setup::factory(false);
            let stats_event_sender = Arc::new(stats_event_sender);

            let request = ConnectRequest {
                transaction_id: TransactionId(0i32.into()),
            };

            let response = handle_connect(sample_ipv6_remote_addr(), &request, &stats_event_sender, sample_issue_time()).await;

            assert_eq!(
                response,
                Response::Connect(ConnectResponse {
                    connection_id: make(sample_ipv6_remote_addr_fingerprint(), sample_issue_time()).unwrap(),
                    transaction_id: request.transaction_id
                })
            );
        }

        #[tokio::test]
        async fn it_should_send_the_upd4_connect_event_when_a_client_tries_to_connect_using_a_ip4_socket_address() {
            let mut stats_event_sender_mock = statistics::event::sender::MockSender::new();
            stats_event_sender_mock
                .expect_send_event()
                .with(eq(statistics::event::Event::Udp4Connect))
                .times(1)
                .returning(|_| Box::pin(future::ready(Some(Ok(())))));
            let stats_event_sender: Arc<Option<Box<dyn statistics::event::sender::Sender>>> =
                Arc::new(Some(Box::new(stats_event_sender_mock)));

            let client_socket_address = sample_ipv4_socket_address();

            handle_connect(
                client_socket_address,
                &sample_connect_request(),
                &stats_event_sender,
                sample_issue_time(),
            )
            .await;
        }

        #[tokio::test]
        async fn it_should_send_the_upd6_connect_event_when_a_client_tries_to_connect_using_a_ip6_socket_address() {
            let mut stats_event_sender_mock = statistics::event::sender::MockSender::new();
            stats_event_sender_mock
                .expect_send_event()
                .with(eq(statistics::event::Event::Udp6Connect))
                .times(1)
                .returning(|_| Box::pin(future::ready(Some(Ok(())))));
            let stats_event_sender: Arc<Option<Box<dyn statistics::event::sender::Sender>>> =
                Arc::new(Some(Box::new(stats_event_sender_mock)));

            handle_connect(
                sample_ipv6_remote_addr(),
                &sample_connect_request(),
                &stats_event_sender,
                sample_issue_time(),
            )
            .await;
        }
    }

    mod announce_request {

        use std::net::Ipv4Addr;
        use std::num::NonZeroU16;

        use aquatic_udp_protocol::{
            AnnounceActionPlaceholder, AnnounceEvent, AnnounceRequest, ConnectionId, NumberOfBytes, NumberOfPeers,
            PeerId as AquaticPeerId, PeerKey, Port, TransactionId,
        };

        use super::{sample_ipv4_remote_addr_fingerprint, sample_issue_time};
        use crate::servers::udp::connection_cookie::make;

        struct AnnounceRequestBuilder {
            request: AnnounceRequest,
        }

        impl AnnounceRequestBuilder {
            pub fn default() -> AnnounceRequestBuilder {
                let client_ip = Ipv4Addr::new(126, 0, 0, 1);
                let client_port = 8080;
                let info_hash_aquatic = aquatic_udp_protocol::InfoHash([0u8; 20]);

                let default_request = AnnounceRequest {
                    connection_id: make(sample_ipv4_remote_addr_fingerprint(), sample_issue_time()).unwrap(),
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
            use crate::servers::udp::connection_cookie::make;
            use crate::servers::udp::handlers::tests::announce_request::AnnounceRequestBuilder;
            use crate::servers::udp::handlers::tests::{
                gen_remote_fingerprint, public_tracker, sample_cookie_valid_range, sample_ipv4_socket_address, sample_issue_time,
                test_tracker_factory, TorrentPeerBuilder,
            };
            use crate::servers::udp::handlers::{handle_announce, AnnounceResponseFixedData};

            #[tokio::test]
            async fn an_announced_peer_should_be_added_to_the_tracker() {
                let (tracker, stats_event_sender) = public_tracker();
                let tracker = Arc::new(tracker);
                let stats_event_sender = Arc::new(stats_event_sender);

                let client_ip = Ipv4Addr::new(126, 0, 0, 1);
                let client_port = 8080;
                let info_hash = AquaticInfoHash([0u8; 20]);
                let peer_id = AquaticPeerId([255u8; 20]);

                let remote_addr = SocketAddr::new(IpAddr::V4(client_ip), client_port);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(make(gen_remote_fingerprint(&remote_addr), sample_issue_time()).unwrap())
                    .with_info_hash(info_hash)
                    .with_peer_id(peer_id)
                    .with_ip_address(client_ip)
                    .with_port(client_port)
                    .into();

                handle_announce(
                    remote_addr,
                    &request,
                    &tracker,
                    &stats_event_sender,
                    sample_cookie_valid_range(),
                )
                .await
                .unwrap();

                let peers = tracker.get_torrent_peers(&info_hash.0.into());

                let expected_peer = TorrentPeerBuilder::new()
                    .with_peer_id(peer_id)
                    .with_peer_address(SocketAddr::new(IpAddr::V4(client_ip), client_port))
                    .into();

                assert_eq!(peers[0], Arc::new(expected_peer));
            }

            #[tokio::test]
            async fn the_announced_peer_should_not_be_included_in_the_response() {
                let (tracker, stats_event_sender) = public_tracker();
                let tracker = Arc::new(tracker);
                let stats_event_sender = Arc::new(stats_event_sender);

                let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(make(gen_remote_fingerprint(&remote_addr), sample_issue_time()).unwrap())
                    .into();

                let response = handle_announce(
                    remote_addr,
                    &request,
                    &tracker,
                    &stats_event_sender,
                    sample_cookie_valid_range(),
                )
                .await
                .unwrap();

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

                let (tracker, stats_event_sender) = public_tracker();
                let tracker = Arc::new(tracker);
                let stats_event_sender = Arc::new(stats_event_sender);

                let info_hash = AquaticInfoHash([0u8; 20]);
                let peer_id = AquaticPeerId([255u8; 20]);
                let client_port = 8080;

                let remote_client_ip = Ipv4Addr::new(126, 0, 0, 1);
                let remote_client_port = 8081;
                let peer_address = Ipv4Addr::new(126, 0, 0, 2);

                let remote_addr = SocketAddr::new(IpAddr::V4(remote_client_ip), remote_client_port);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(make(gen_remote_fingerprint(&remote_addr), sample_issue_time()).unwrap())
                    .with_info_hash(info_hash)
                    .with_peer_id(peer_id)
                    .with_ip_address(peer_address)
                    .with_port(client_port)
                    .into();

                handle_announce(
                    remote_addr,
                    &request,
                    &tracker,
                    &stats_event_sender,
                    sample_cookie_valid_range(),
                )
                .await
                .unwrap();

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
                let (stats_event_sender, _stats_repository) = crate::core::services::statistics::setup::factory(false);
                let stats_event_sender = Arc::new(stats_event_sender);

                let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080);
                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(make(gen_remote_fingerprint(&remote_addr), sample_issue_time()).unwrap())
                    .into();

                handle_announce(
                    remote_addr,
                    &request,
                    &tracker,
                    &stats_event_sender,
                    sample_cookie_valid_range(),
                )
                .await
                .unwrap()
            }

            #[tokio::test]
            async fn when_the_announce_request_comes_from_a_client_using_ipv4_the_response_should_not_include_peers_using_ipv6() {
                let (tracker, _stats_event_sender) = public_tracker();
                let tracker = Arc::new(tracker);

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
                let mut stats_event_sender_mock = statistics::event::sender::MockSender::new();
                stats_event_sender_mock
                    .expect_send_event()
                    .with(eq(statistics::event::Event::Udp4Announce))
                    .times(1)
                    .returning(|_| Box::pin(future::ready(Some(Ok(())))));
                let stats_event_sender: Arc<Option<Box<dyn statistics::event::sender::Sender>>> =
                    Arc::new(Some(Box::new(stats_event_sender_mock)));

                let tracker = Arc::new(test_tracker_factory());

                handle_announce(
                    sample_ipv4_socket_address(),
                    &AnnounceRequestBuilder::default().into(),
                    &tracker,
                    &stats_event_sender,
                    sample_cookie_valid_range(),
                )
                .await
                .unwrap();
            }

            mod from_a_loopback_ip {
                use std::net::{IpAddr, Ipv4Addr, SocketAddr};
                use std::sync::Arc;

                use aquatic_udp_protocol::{InfoHash as AquaticInfoHash, PeerId as AquaticPeerId};

                use crate::servers::udp::connection_cookie::make;
                use crate::servers::udp::handlers::handle_announce;
                use crate::servers::udp::handlers::tests::announce_request::AnnounceRequestBuilder;
                use crate::servers::udp::handlers::tests::{
                    gen_remote_fingerprint, public_tracker, sample_cookie_valid_range, sample_issue_time, TorrentPeerBuilder,
                };

                #[tokio::test]
                async fn the_peer_ip_should_be_changed_to_the_external_ip_in_the_tracker_configuration_if_defined() {
                    let (tracker, stats_event_sender) = public_tracker();
                    let tracker = Arc::new(tracker);
                    let stats_event_sender = Arc::new(stats_event_sender);

                    let client_ip = Ipv4Addr::new(127, 0, 0, 1);
                    let client_port = 8080;
                    let info_hash = AquaticInfoHash([0u8; 20]);
                    let peer_id = AquaticPeerId([255u8; 20]);

                    let remote_addr = SocketAddr::new(IpAddr::V4(client_ip), client_port);

                    let request = AnnounceRequestBuilder::default()
                        .with_connection_id(make(gen_remote_fingerprint(&remote_addr), sample_issue_time()).unwrap())
                        .with_info_hash(info_hash)
                        .with_peer_id(peer_id)
                        .with_ip_address(client_ip)
                        .with_port(client_port)
                        .into();

                    handle_announce(
                        remote_addr,
                        &request,
                        &tracker,
                        &stats_event_sender,
                        sample_cookie_valid_range(),
                    )
                    .await
                    .unwrap();

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
            use crate::servers::udp::connection_cookie::make;
            use crate::servers::udp::handlers::tests::announce_request::AnnounceRequestBuilder;
            use crate::servers::udp::handlers::tests::{
                gen_remote_fingerprint, public_tracker, sample_cookie_valid_range, sample_ipv6_remote_addr, sample_issue_time,
                test_tracker_factory, TorrentPeerBuilder,
            };
            use crate::servers::udp::handlers::{handle_announce, AnnounceResponseFixedData};

            #[tokio::test]
            async fn an_announced_peer_should_be_added_to_the_tracker() {
                let (tracker, stats_event_sender) = public_tracker();
                let tracker = Arc::new(tracker);
                let stats_event_sender = Arc::new(stats_event_sender);

                let client_ip_v4 = Ipv4Addr::new(126, 0, 0, 1);
                let client_ip_v6 = client_ip_v4.to_ipv6_compatible();
                let client_port = 8080;
                let info_hash = AquaticInfoHash([0u8; 20]);
                let peer_id = AquaticPeerId([255u8; 20]);

                let remote_addr = SocketAddr::new(IpAddr::V6(client_ip_v6), client_port);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(make(gen_remote_fingerprint(&remote_addr), sample_issue_time()).unwrap())
                    .with_info_hash(info_hash)
                    .with_peer_id(peer_id)
                    .with_ip_address(client_ip_v4)
                    .with_port(client_port)
                    .into();

                handle_announce(
                    remote_addr,
                    &request,
                    &tracker,
                    &stats_event_sender,
                    sample_cookie_valid_range(),
                )
                .await
                .unwrap();

                let peers = tracker.get_torrent_peers(&info_hash.0.into());

                let expected_peer = TorrentPeerBuilder::new()
                    .with_peer_id(peer_id)
                    .with_peer_address(SocketAddr::new(IpAddr::V6(client_ip_v6), client_port))
                    .into();

                assert_eq!(peers[0], Arc::new(expected_peer));
            }

            #[tokio::test]
            async fn the_announced_peer_should_not_be_included_in_the_response() {
                let (tracker, stats_event_sender) = public_tracker();
                let tracker = Arc::new(tracker);
                let stats_event_sender = Arc::new(stats_event_sender);

                let client_ip_v4 = Ipv4Addr::new(126, 0, 0, 1);
                let client_ip_v6 = client_ip_v4.to_ipv6_compatible();

                let remote_addr = SocketAddr::new(IpAddr::V6(client_ip_v6), 8080);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(make(gen_remote_fingerprint(&remote_addr), sample_issue_time()).unwrap())
                    .into();

                let response = handle_announce(
                    remote_addr,
                    &request,
                    &tracker,
                    &stats_event_sender,
                    sample_cookie_valid_range(),
                )
                .await
                .unwrap();

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

                let (tracker, stats_event_sender) = public_tracker();
                let tracker = Arc::new(tracker);
                let stats_event_sender = Arc::new(stats_event_sender);

                let info_hash = AquaticInfoHash([0u8; 20]);
                let peer_id = AquaticPeerId([255u8; 20]);
                let client_port = 8080;

                let remote_client_ip = "::100".parse().unwrap(); // IPV4 ::0.0.1.0 -> IPV6 = ::100 = ::ffff:0:100 = 0:0:0:0:0:ffff:0:0100
                let remote_client_port = 8081;
                let peer_address = "126.0.0.1".parse().unwrap();

                let remote_addr = SocketAddr::new(IpAddr::V6(remote_client_ip), remote_client_port);

                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(make(gen_remote_fingerprint(&remote_addr), sample_issue_time()).unwrap())
                    .with_info_hash(info_hash)
                    .with_peer_id(peer_id)
                    .with_ip_address(peer_address)
                    .with_port(client_port)
                    .into();

                handle_announce(
                    remote_addr,
                    &request,
                    &tracker,
                    &stats_event_sender,
                    sample_cookie_valid_range(),
                )
                .await
                .unwrap();

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
                let (stats_event_sender, _stats_repository) = crate::core::services::statistics::setup::factory(false);
                let stats_event_sender = Arc::new(stats_event_sender);

                let client_ip_v4 = Ipv4Addr::new(126, 0, 0, 1);
                let client_ip_v6 = client_ip_v4.to_ipv6_compatible();
                let client_port = 8080;
                let remote_addr = SocketAddr::new(IpAddr::V6(client_ip_v6), client_port);
                let request = AnnounceRequestBuilder::default()
                    .with_connection_id(make(gen_remote_fingerprint(&remote_addr), sample_issue_time()).unwrap())
                    .into();

                handle_announce(
                    remote_addr,
                    &request,
                    &tracker,
                    &stats_event_sender,
                    sample_cookie_valid_range(),
                )
                .await
                .unwrap()
            }

            #[tokio::test]
            async fn when_the_announce_request_comes_from_a_client_using_ipv6_the_response_should_not_include_peers_using_ipv4() {
                let (tracker, _stats_event_sender) = public_tracker();
                let tracker = Arc::new(tracker);

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
                let mut stats_event_sender_mock = statistics::event::sender::MockSender::new();
                stats_event_sender_mock
                    .expect_send_event()
                    .with(eq(statistics::event::Event::Udp6Announce))
                    .times(1)
                    .returning(|_| Box::pin(future::ready(Some(Ok(())))));
                let stats_event_sender: Arc<Option<Box<dyn statistics::event::sender::Sender>>> =
                    Arc::new(Some(Box::new(stats_event_sender_mock)));

                let tracker = Arc::new(test_tracker_factory());

                let remote_addr = sample_ipv6_remote_addr();

                let announce_request = AnnounceRequestBuilder::default()
                    .with_connection_id(make(gen_remote_fingerprint(&remote_addr), sample_issue_time()).unwrap())
                    .into();

                handle_announce(
                    remote_addr,
                    &announce_request,
                    &tracker,
                    &stats_event_sender,
                    sample_cookie_valid_range(),
                )
                .await
                .unwrap();
            }

            mod from_a_loopback_ip {
                use std::future;
                use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
                use std::sync::Arc;

                use aquatic_udp_protocol::{InfoHash as AquaticInfoHash, PeerId as AquaticPeerId};
                use mockall::predicate::eq;

                use crate::bootstrap::app::initialize_tracker_dependencies;
                use crate::core::{self, statistics};
                use crate::servers::udp::connection_cookie::make;
                use crate::servers::udp::handlers::handle_announce;
                use crate::servers::udp::handlers::tests::announce_request::AnnounceRequestBuilder;
                use crate::servers::udp::handlers::tests::{
                    gen_remote_fingerprint, sample_cookie_valid_range, sample_issue_time, TrackerConfigurationBuilder,
                };

                #[tokio::test]
                async fn the_peer_ip_should_be_changed_to_the_external_ip_in_the_tracker_configuration() {
                    let config = Arc::new(TrackerConfigurationBuilder::default().with_external_ip("::126.0.0.1").into());

                    let (database, whitelist_manager) = initialize_tracker_dependencies(&config);

                    let mut stats_event_sender_mock = statistics::event::sender::MockSender::new();
                    stats_event_sender_mock
                        .expect_send_event()
                        .with(eq(statistics::event::Event::Udp6Announce))
                        .times(1)
                        .returning(|_| Box::pin(future::ready(Some(Ok(())))));
                    let stats_event_sender: Arc<Option<Box<dyn statistics::event::sender::Sender>>> =
                        Arc::new(Some(Box::new(stats_event_sender_mock)));

                    let tracker = Arc::new(core::Tracker::new(&config.core, &database, &whitelist_manager).unwrap());

                    let loopback_ipv4 = Ipv4Addr::new(127, 0, 0, 1);
                    let loopback_ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

                    let client_ip_v4 = loopback_ipv4;
                    let client_ip_v6 = loopback_ipv6;
                    let client_port = 8080;

                    let info_hash = AquaticInfoHash([0u8; 20]);
                    let peer_id = AquaticPeerId([255u8; 20]);

                    let remote_addr = SocketAddr::new(IpAddr::V6(client_ip_v6), client_port);

                    let request = AnnounceRequestBuilder::default()
                        .with_connection_id(make(gen_remote_fingerprint(&remote_addr), sample_issue_time()).unwrap())
                        .with_info_hash(info_hash)
                        .with_peer_id(peer_id)
                        .with_ip_address(client_ip_v4)
                        .with_port(client_port)
                        .into();

                    handle_announce(
                        remote_addr,
                        &request,
                        &tracker,
                        &stats_event_sender,
                        sample_cookie_valid_range(),
                    )
                    .await
                    .unwrap();

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

        use super::{gen_remote_fingerprint, TorrentPeerBuilder};
        use crate::core::services::statistics;
        use crate::core::{self};
        use crate::servers::udp::connection_cookie::make;
        use crate::servers::udp::handlers::handle_scrape;
        use crate::servers::udp::handlers::tests::{
            public_tracker, sample_cookie_valid_range, sample_ipv4_remote_addr, sample_issue_time,
        };

        fn zeroed_torrent_statistics() -> TorrentScrapeStatistics {
            TorrentScrapeStatistics {
                seeders: NumberOfPeers(0.into()),
                completed: NumberOfDownloads(0.into()),
                leechers: NumberOfPeers(0.into()),
            }
        }

        #[tokio::test]
        async fn should_return_no_stats_when_the_tracker_does_not_have_any_torrent() {
            let (tracker, stats_event_sender) = public_tracker();
            let tracker = Arc::new(tracker);
            let stats_event_sender = Arc::new(stats_event_sender);

            let remote_addr = sample_ipv4_remote_addr();

            let info_hash = InfoHash([0u8; 20]);
            let info_hashes = vec![info_hash];

            let request = ScrapeRequest {
                connection_id: make(gen_remote_fingerprint(&remote_addr), sample_issue_time()).unwrap(),
                transaction_id: TransactionId(0i32.into()),
                info_hashes,
            };

            let response = handle_scrape(
                remote_addr,
                &request,
                &tracker,
                &stats_event_sender,
                sample_cookie_valid_range(),
            )
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
                connection_id: make(gen_remote_fingerprint(remote_addr), sample_issue_time()).unwrap(),
                transaction_id: TransactionId::new(0i32),
                info_hashes,
            }
        }

        async fn add_a_sample_seeder_and_scrape(tracker: Arc<core::Tracker>) -> Response {
            let (stats_event_sender, _stats_repository) = statistics::setup::factory(false);
            let stats_event_sender = Arc::new(stats_event_sender);

            let remote_addr = sample_ipv4_remote_addr();
            let info_hash = InfoHash([0u8; 20]);

            add_a_seeder(tracker.clone(), &remote_addr, &info_hash).await;

            let request = build_scrape_request(&remote_addr, &info_hash);

            handle_scrape(
                remote_addr,
                &request,
                &tracker,
                &stats_event_sender,
                sample_cookie_valid_range(),
            )
            .await
            .unwrap()
        }

        fn match_scrape_response(response: Response) -> Option<ScrapeResponse> {
            match response {
                Response::Scrape(scrape_response) => Some(scrape_response),
                _ => None,
            }
        }

        mod with_a_public_tracker {
            use std::sync::Arc;

            use aquatic_udp_protocol::{NumberOfDownloads, NumberOfPeers, TorrentScrapeStatistics};

            use crate::servers::udp::handlers::tests::public_tracker;
            use crate::servers::udp::handlers::tests::scrape_request::{add_a_sample_seeder_and_scrape, match_scrape_response};

            #[tokio::test]
            async fn should_return_torrent_statistics_when_the_tracker_has_the_requested_torrent() {
                let (tracker, _stats_event_sender) = public_tracker();
                let tracker = Arc::new(tracker);

                let torrent_stats = match_scrape_response(add_a_sample_seeder_and_scrape(tracker.clone()).await);

                let expected_torrent_stats = vec![TorrentScrapeStatistics {
                    seeders: NumberOfPeers(1.into()),
                    completed: NumberOfDownloads(0.into()),
                    leechers: NumberOfPeers(0.into()),
                }];

                assert_eq!(torrent_stats.unwrap().torrent_stats, expected_torrent_stats);
            }
        }

        mod with_a_whitelisted_tracker {
            use std::sync::Arc;

            use aquatic_udp_protocol::{InfoHash, NumberOfDownloads, NumberOfPeers, TorrentScrapeStatistics};

            use crate::servers::udp::handlers::handle_scrape;
            use crate::servers::udp::handlers::tests::scrape_request::{
                add_a_seeder, build_scrape_request, match_scrape_response, zeroed_torrent_statistics,
            };
            use crate::servers::udp::handlers::tests::{sample_cookie_valid_range, sample_ipv4_remote_addr, whitelisted_tracker};

            #[tokio::test]
            async fn should_return_the_torrent_statistics_when_the_requested_torrent_is_whitelisted() {
                let (tracker, stats_event_sender) = whitelisted_tracker();
                let tracker = Arc::new(tracker);
                let stats_event_sender = Arc::new(stats_event_sender);

                let remote_addr = sample_ipv4_remote_addr();
                let info_hash = InfoHash([0u8; 20]);

                add_a_seeder(tracker.clone(), &remote_addr, &info_hash).await;

                tracker
                    .whitelist_manager
                    .add_torrent_to_memory_whitelist(&info_hash.0.into())
                    .await;

                let request = build_scrape_request(&remote_addr, &info_hash);

                let torrent_stats = match_scrape_response(
                    handle_scrape(
                        remote_addr,
                        &request,
                        &tracker,
                        &stats_event_sender,
                        sample_cookie_valid_range(),
                    )
                    .await
                    .unwrap(),
                )
                .unwrap();

                let expected_torrent_stats = vec![TorrentScrapeStatistics {
                    seeders: NumberOfPeers(1.into()),
                    completed: NumberOfDownloads(0.into()),
                    leechers: NumberOfPeers(0.into()),
                }];

                assert_eq!(torrent_stats.torrent_stats, expected_torrent_stats);
            }

            #[tokio::test]
            async fn should_return_zeroed_statistics_when_the_requested_torrent_is_not_whitelisted() {
                let (tracker, stats_event_sender) = whitelisted_tracker();
                let tracker = Arc::new(tracker);
                let stats_event_sender = Arc::new(stats_event_sender);

                let remote_addr = sample_ipv4_remote_addr();
                let info_hash = InfoHash([0u8; 20]);

                add_a_seeder(tracker.clone(), &remote_addr, &info_hash).await;

                let request = build_scrape_request(&remote_addr, &info_hash);

                let torrent_stats = match_scrape_response(
                    handle_scrape(
                        remote_addr,
                        &request,
                        &tracker,
                        &stats_event_sender,
                        sample_cookie_valid_range(),
                    )
                    .await
                    .unwrap(),
                )
                .unwrap();

                let expected_torrent_stats = vec![zeroed_torrent_statistics()];

                assert_eq!(torrent_stats.torrent_stats, expected_torrent_stats);
            }
        }

        fn sample_scrape_request(remote_addr: &SocketAddr) -> ScrapeRequest {
            let info_hash = InfoHash([0u8; 20]);
            let info_hashes = vec![info_hash];

            ScrapeRequest {
                connection_id: make(gen_remote_fingerprint(remote_addr), sample_issue_time()).unwrap(),
                transaction_id: TransactionId(0i32.into()),
                info_hashes,
            }
        }

        mod using_ipv4 {
            use std::future;
            use std::sync::Arc;

            use mockall::predicate::eq;

            use super::sample_scrape_request;
            use crate::core::statistics;
            use crate::servers::udp::handlers::handle_scrape;
            use crate::servers::udp::handlers::tests::{
                sample_cookie_valid_range, sample_ipv4_remote_addr, test_tracker_factory,
            };

            #[tokio::test]
            async fn should_send_the_upd4_scrape_event() {
                let mut stats_event_sender_mock = statistics::event::sender::MockSender::new();
                stats_event_sender_mock
                    .expect_send_event()
                    .with(eq(statistics::event::Event::Udp4Scrape))
                    .times(1)
                    .returning(|_| Box::pin(future::ready(Some(Ok(())))));
                let stats_event_sender: Arc<Option<Box<dyn statistics::event::sender::Sender>>> =
                    Arc::new(Some(Box::new(stats_event_sender_mock)));

                let remote_addr = sample_ipv4_remote_addr();
                let tracker = Arc::new(test_tracker_factory());

                handle_scrape(
                    remote_addr,
                    &sample_scrape_request(&remote_addr),
                    &tracker,
                    &stats_event_sender,
                    sample_cookie_valid_range(),
                )
                .await
                .unwrap();
            }
        }

        mod using_ipv6 {
            use std::future;
            use std::sync::Arc;

            use mockall::predicate::eq;

            use super::sample_scrape_request;
            use crate::core::statistics;
            use crate::servers::udp::handlers::handle_scrape;
            use crate::servers::udp::handlers::tests::{
                sample_cookie_valid_range, sample_ipv6_remote_addr, test_tracker_factory,
            };

            #[tokio::test]
            async fn should_send_the_upd6_scrape_event() {
                let mut stats_event_sender_mock = statistics::event::sender::MockSender::new();
                stats_event_sender_mock
                    .expect_send_event()
                    .with(eq(statistics::event::Event::Udp6Scrape))
                    .times(1)
                    .returning(|_| Box::pin(future::ready(Some(Ok(())))));
                let stats_event_sender: Arc<Option<Box<dyn statistics::event::sender::Sender>>> =
                    Arc::new(Some(Box::new(stats_event_sender_mock)));

                let remote_addr = sample_ipv6_remote_addr();
                let tracker = Arc::new(test_tracker_factory());

                handle_scrape(
                    remote_addr,
                    &sample_scrape_request(&remote_addr),
                    &tracker,
                    &stats_event_sender,
                    sample_cookie_valid_range(),
                )
                .await
                .unwrap();
            }
        }
    }
}
