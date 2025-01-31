//! The `announce` service.
//!
//! The service is responsible for handling the `announce` requests.
//!
//! It delegates the `announce` logic to the [`AnnounceHandler`] and it returns
//! the [`AnnounceData`].
//!
//! It also sends an [`http_tracker_core::statistics::event::Event`]
//! because events are specific for the HTTP tracker.
use std::net::IpAddr;
use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use bittorrent_tracker_core::announce_handler::{AnnounceHandler, PeersWanted};
use torrust_tracker_primitives::core::AnnounceData;
use torrust_tracker_primitives::peer;

use crate::packages::http_tracker_core;

/// The HTTP tracker `announce` service.
///
/// The service sends an statistics event that increments:
///
/// - The number of TCP connections handled by the HTTP tracker.
/// - The number of TCP `announce` requests handled by the HTTP tracker.
///
/// > **NOTICE**: as the HTTP tracker does not requires a connection request
/// > like the UDP tracker, the number of TCP connections is incremented for
/// > each `announce` request.
pub async fn invoke(
    announce_handler: Arc<AnnounceHandler>,
    opt_http_stats_event_sender: Arc<Option<Box<dyn http_tracker_core::statistics::event::sender::Sender>>>,
    info_hash: InfoHash,
    peer: &mut peer::Peer,
    peers_wanted: &PeersWanted,
) -> AnnounceData {
    let original_peer_ip = peer.peer_addr.ip();

    // The tracker could change the original peer ip
    let announce_data = announce_handler.announce(&info_hash, peer, &original_peer_ip, peers_wanted);

    if let Some(http_stats_event_sender) = opt_http_stats_event_sender.as_deref() {
        match original_peer_ip {
            IpAddr::V4(_) => {
                http_stats_event_sender
                    .send_event(http_tracker_core::statistics::event::Event::Tcp4Announce)
                    .await;
            }
            IpAddr::V6(_) => {
                http_stats_event_sender
                    .send_event(http_tracker_core::statistics::event::Event::Tcp6Announce)
                    .await;
            }
        }
    }

    announce_data
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;

    use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes, PeerId};
    use bittorrent_tracker_core::announce_handler::AnnounceHandler;
    use bittorrent_tracker_core::databases::setup::initialize_database;
    use bittorrent_tracker_core::torrent::repository::in_memory::InMemoryTorrentRepository;
    use bittorrent_tracker_core::torrent::repository::persisted::DatabasePersistentTorrentRepository;
    use torrust_tracker_configuration::Core;
    use torrust_tracker_primitives::{peer, DurationSinceUnixEpoch};
    use torrust_tracker_test_helpers::configuration;

    struct CoreTrackerServices {
        pub core_config: Arc<Core>,
        pub announce_handler: Arc<AnnounceHandler>,
    }

    struct CoreHttpTrackerServices {
        pub http_stats_event_sender: Arc<Option<Box<dyn http_tracker_core::statistics::event::sender::Sender>>>,
    }

    fn initialize_core_tracker_services() -> (CoreTrackerServices, CoreHttpTrackerServices) {
        let config = configuration::ephemeral_public();

        let core_config = Arc::new(config.core.clone());
        let database = initialize_database(&config);
        let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());
        let db_torrent_repository = Arc::new(DatabasePersistentTorrentRepository::new(&database));

        let announce_handler = Arc::new(AnnounceHandler::new(
            &config.core,
            &in_memory_torrent_repository,
            &db_torrent_repository,
        ));

        // HTTP stats
        let (http_stats_event_sender, http_stats_repository) =
            http_tracker_core::statistics::setup::factory(config.core.tracker_usage_statistics);
        let http_stats_event_sender = Arc::new(http_stats_event_sender);
        let _http_stats_repository = Arc::new(http_stats_repository);

        (
            CoreTrackerServices {
                core_config,
                announce_handler,
            },
            CoreHttpTrackerServices { http_stats_event_sender },
        )
    }

    fn sample_peer_using_ipv4() -> peer::Peer {
        sample_peer()
    }

    fn sample_peer_using_ipv6() -> peer::Peer {
        let mut peer = sample_peer();
        peer.peer_addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969)),
            8080,
        );
        peer
    }

    fn sample_peer() -> peer::Peer {
        peer::Peer {
            peer_id: PeerId(*b"-qB00000000000000000"),
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080),
            updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
            uploaded: NumberOfBytes::new(0),
            downloaded: NumberOfBytes::new(0),
            left: NumberOfBytes::new(0),
            event: AnnounceEvent::Started,
        }
    }

    use futures::future::BoxFuture;
    use mockall::mock;
    use tokio::sync::mpsc::error::SendError;

    use crate::packages::http_tracker_core;

    mock! {
        HttpStatsEventSender {}
        impl http_tracker_core::statistics::event::sender::Sender for HttpStatsEventSender {
             fn send_event(&self, event: http_tracker_core::statistics::event::Event) -> BoxFuture<'static,Option<Result<(),SendError<http_tracker_core::statistics::event::Event> > > > ;
        }
    }

    mod with_tracker_in_any_mode {
        use std::future;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
        use std::sync::Arc;

        use bittorrent_tracker_core::announce_handler::{AnnounceHandler, PeersWanted};
        use bittorrent_tracker_core::core_tests::sample_info_hash;
        use bittorrent_tracker_core::databases::setup::initialize_database;
        use bittorrent_tracker_core::torrent::repository::in_memory::InMemoryTorrentRepository;
        use bittorrent_tracker_core::torrent::repository::persisted::DatabasePersistentTorrentRepository;
        use mockall::predicate::eq;
        use torrust_tracker_primitives::core::AnnounceData;
        use torrust_tracker_primitives::peer;
        use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;
        use torrust_tracker_test_helpers::configuration;

        use super::{sample_peer_using_ipv4, sample_peer_using_ipv6};
        use crate::packages::http_tracker_core;
        use crate::servers::http::v1::services::announce::invoke;
        use crate::servers::http::v1::services::announce::tests::{
            initialize_core_tracker_services, sample_peer, MockHttpStatsEventSender,
        };

        fn initialize_announce_handler() -> Arc<AnnounceHandler> {
            let config = configuration::ephemeral();

            let database = initialize_database(&config);
            let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());
            let db_torrent_repository = Arc::new(DatabasePersistentTorrentRepository::new(&database));

            Arc::new(AnnounceHandler::new(
                &config.core,
                &in_memory_torrent_repository,
                &db_torrent_repository,
            ))
        }

        #[tokio::test]
        async fn it_should_return_the_announce_data() {
            let (core_tracker_services, core_http_tracker_services) = initialize_core_tracker_services();

            let mut peer = sample_peer();

            let announce_data = invoke(
                core_tracker_services.announce_handler.clone(),
                core_http_tracker_services.http_stats_event_sender.clone(),
                sample_info_hash(),
                &mut peer,
                &PeersWanted::All,
            )
            .await;

            let expected_announce_data = AnnounceData {
                peers: vec![],
                stats: SwarmMetadata {
                    downloaded: 0,
                    complete: 1,
                    incomplete: 0,
                },
                policy: core_tracker_services.core_config.announce_policy,
            };

            assert_eq!(announce_data, expected_announce_data);
        }

        #[tokio::test]
        async fn it_should_send_the_tcp_4_announce_event_when_the_peer_uses_ipv4() {
            let mut http_stats_event_sender_mock = MockHttpStatsEventSender::new();
            http_stats_event_sender_mock
                .expect_send_event()
                .with(eq(http_tracker_core::statistics::event::Event::Tcp4Announce))
                .times(1)
                .returning(|_| Box::pin(future::ready(Some(Ok(())))));
            let http_stats_event_sender: Arc<Option<Box<dyn http_tracker_core::statistics::event::sender::Sender>>> =
                Arc::new(Some(Box::new(http_stats_event_sender_mock)));

            let announce_handler = initialize_announce_handler();

            let mut peer = sample_peer_using_ipv4();

            let _announce_data = invoke(
                announce_handler,
                http_stats_event_sender,
                sample_info_hash(),
                &mut peer,
                &PeersWanted::All,
            )
            .await;
        }

        fn tracker_with_an_ipv6_external_ip() -> Arc<AnnounceHandler> {
            let mut configuration = configuration::ephemeral();
            configuration.core.net.external_ip = Some(IpAddr::V6(Ipv6Addr::new(
                0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969,
            )));

            initialize_announce_handler()
        }

        fn peer_with_the_ipv4_loopback_ip() -> peer::Peer {
            let loopback_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
            let mut peer = sample_peer();
            peer.peer_addr = SocketAddr::new(loopback_ip, 8080);
            peer
        }

        #[tokio::test]
        async fn it_should_send_the_tcp_4_announce_event_when_the_peer_uses_ipv4_even_if_the_tracker_changes_the_peer_ip_to_ipv6()
        {
            // Tracker changes the peer IP to the tracker external IP when the peer is using the loopback IP.

            // Assert that the event sent is a TCP4 event
            let mut http_stats_event_sender_mock = MockHttpStatsEventSender::new();
            http_stats_event_sender_mock
                .expect_send_event()
                .with(eq(http_tracker_core::statistics::event::Event::Tcp4Announce))
                .times(1)
                .returning(|_| Box::pin(future::ready(Some(Ok(())))));
            let http_stats_event_sender: Arc<Option<Box<dyn http_tracker_core::statistics::event::sender::Sender>>> =
                Arc::new(Some(Box::new(http_stats_event_sender_mock)));

            let mut peer = peer_with_the_ipv4_loopback_ip();

            let announce_handler = tracker_with_an_ipv6_external_ip();

            let _announce_data = invoke(
                announce_handler,
                http_stats_event_sender,
                sample_info_hash(),
                &mut peer,
                &PeersWanted::All,
            )
            .await;
        }

        #[tokio::test]
        async fn it_should_send_the_tcp_6_announce_event_when_the_peer_uses_ipv6_even_if_the_tracker_changes_the_peer_ip_to_ipv4()
        {
            let mut http_stats_event_sender_mock = MockHttpStatsEventSender::new();
            http_stats_event_sender_mock
                .expect_send_event()
                .with(eq(http_tracker_core::statistics::event::Event::Tcp6Announce))
                .times(1)
                .returning(|_| Box::pin(future::ready(Some(Ok(())))));
            let http_stats_event_sender: Arc<Option<Box<dyn http_tracker_core::statistics::event::sender::Sender>>> =
                Arc::new(Some(Box::new(http_stats_event_sender_mock)));

            let announce_handler = initialize_announce_handler();

            let mut peer = sample_peer_using_ipv6();

            let _announce_data = invoke(
                announce_handler,
                http_stats_event_sender,
                sample_info_hash(),
                &mut peer,
                &PeersWanted::All,
            )
            .await;
        }
    }
}
