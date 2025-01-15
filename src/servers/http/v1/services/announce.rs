//! The `announce` service.
//!
//! The service is responsible for handling the `announce` requests.
//!
//! It delegates the `announce` logic to the [`Tracker`](crate::core::Tracker::announce)
//! and it returns the [`AnnounceData`] returned
//! by the [`Tracker`].
//!
//! It also sends an [`statistics::event::Event`]
//! because events are specific for the HTTP tracker.
use std::net::IpAddr;
use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_primitives::core::AnnounceData;
use torrust_tracker_primitives::peer;

use crate::core::{statistics, PeersWanted, Tracker};

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
    tracker: Arc<Tracker>,
    info_hash: InfoHash,
    peer: &mut peer::Peer,
    peers_wanted: &PeersWanted,
) -> AnnounceData {
    let original_peer_ip = peer.peer_addr.ip();

    // The tracker could change the original peer ip
    let announce_data = tracker.announce(&info_hash, peer, &original_peer_ip, peers_wanted);

    match original_peer_ip {
        IpAddr::V4(_) => {
            tracker.send_stats_event(statistics::event::Event::Tcp4Announce).await;
        }
        IpAddr::V6(_) => {
            tracker.send_stats_event(statistics::event::Event::Tcp6Announce).await;
        }
    }

    announce_data
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes, PeerId};
    use bittorrent_primitives::info_hash::InfoHash;
    use torrust_tracker_primitives::{peer, DurationSinceUnixEpoch};
    use torrust_tracker_test_helpers::configuration;

    use crate::bootstrap::app::initialize_tracker_dependencies;
    use crate::core::services::tracker_factory;
    use crate::core::Tracker;

    fn public_tracker() -> Tracker {
        let config = configuration::ephemeral_public();
        let (database, whitelist_manager) = initialize_tracker_dependencies(&config);
        tracker_factory(&config, &database, &whitelist_manager)
    }

    fn sample_info_hash() -> InfoHash {
        "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap()
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

    mod with_tracker_in_any_mode {
        use std::future;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
        use std::sync::Arc;

        use mockall::predicate::eq;
        use torrust_tracker_primitives::core::AnnounceData;
        use torrust_tracker_primitives::peer;
        use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;
        use torrust_tracker_test_helpers::configuration;

        use super::{sample_peer_using_ipv4, sample_peer_using_ipv6};
        use crate::bootstrap::app::initialize_tracker_dependencies;
        use crate::core::{statistics, PeersWanted, Tracker};
        use crate::servers::http::v1::services::announce::invoke;
        use crate::servers::http::v1::services::announce::tests::{public_tracker, sample_info_hash, sample_peer};

        fn test_tracker_factory(stats_event_sender: Option<Box<dyn statistics::event::sender::Sender>>) -> Tracker {
            let config = configuration::ephemeral();

            let (database, whitelist_manager) = initialize_tracker_dependencies(&config);

            Tracker::new(
                &config.core,
                &database,
                &whitelist_manager,
                stats_event_sender,
                statistics::repository::Repository::new(),
            )
            .unwrap()
        }

        #[tokio::test]
        async fn it_should_return_the_announce_data() {
            let tracker = Arc::new(public_tracker());

            let mut peer = sample_peer();

            let announce_data = invoke(tracker.clone(), sample_info_hash(), &mut peer, &PeersWanted::All).await;

            let expected_announce_data = AnnounceData {
                peers: vec![],
                stats: SwarmMetadata {
                    downloaded: 0,
                    complete: 1,
                    incomplete: 0,
                },
                policy: tracker.get_announce_policy(),
            };

            assert_eq!(announce_data, expected_announce_data);
        }

        #[tokio::test]
        async fn it_should_send_the_tcp_4_announce_event_when_the_peer_uses_ipv4() {
            let mut stats_event_sender_mock = statistics::event::sender::MockSender::new();
            stats_event_sender_mock
                .expect_send_event()
                .with(eq(statistics::event::Event::Tcp4Announce))
                .times(1)
                .returning(|_| Box::pin(future::ready(Some(Ok(())))));
            let stats_event_sender = Box::new(stats_event_sender_mock);

            let tracker = Arc::new(test_tracker_factory(Some(stats_event_sender)));

            let mut peer = sample_peer_using_ipv4();

            let _announce_data = invoke(tracker, sample_info_hash(), &mut peer, &PeersWanted::All).await;
        }

        fn tracker_with_an_ipv6_external_ip(stats_event_sender: Box<dyn statistics::event::sender::Sender>) -> Tracker {
            let mut configuration = configuration::ephemeral();
            configuration.core.net.external_ip = Some(IpAddr::V6(Ipv6Addr::new(
                0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969,
            )));

            test_tracker_factory(Some(stats_event_sender))
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
            let mut stats_event_sender_mock = statistics::event::sender::MockSender::new();
            stats_event_sender_mock
                .expect_send_event()
                .with(eq(statistics::event::Event::Tcp4Announce))
                .times(1)
                .returning(|_| Box::pin(future::ready(Some(Ok(())))));
            let stats_event_sender = Box::new(stats_event_sender_mock);

            let mut peer = peer_with_the_ipv4_loopback_ip();

            let _announce_data = invoke(
                tracker_with_an_ipv6_external_ip(stats_event_sender).into(),
                sample_info_hash(),
                &mut peer,
                &PeersWanted::All,
            )
            .await;
        }

        #[tokio::test]
        async fn it_should_send_the_tcp_6_announce_event_when_the_peer_uses_ipv6_even_if_the_tracker_changes_the_peer_ip_to_ipv4()
        {
            let mut stats_event_sender_mock = statistics::event::sender::MockSender::new();
            stats_event_sender_mock
                .expect_send_event()
                .with(eq(statistics::event::Event::Tcp6Announce))
                .times(1)
                .returning(|_| Box::pin(future::ready(Some(Ok(())))));
            let stats_event_sender = Box::new(stats_event_sender_mock);

            let tracker = Arc::new(test_tracker_factory(Some(stats_event_sender)));

            let mut peer = sample_peer_using_ipv6();

            let _announce_data = invoke(tracker, sample_info_hash(), &mut peer, &PeersWanted::All).await;
        }
    }
}
