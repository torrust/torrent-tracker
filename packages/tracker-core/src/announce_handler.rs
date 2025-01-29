use std::net::IpAddr;
use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_configuration::{Core, TORRENT_PEERS_LIMIT};
use torrust_tracker_primitives::core::AnnounceData;
use torrust_tracker_primitives::peer;
use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;

use super::torrent::repository::in_memory::InMemoryTorrentRepository;
use super::torrent::repository::persisted::DatabasePersistentTorrentRepository;

pub struct AnnounceHandler {
    /// The tracker configuration.
    config: Core,

    /// The in-memory torrents repository.
    in_memory_torrent_repository: Arc<InMemoryTorrentRepository>,

    /// The persistent torrents repository.
    db_torrent_repository: Arc<DatabasePersistentTorrentRepository>,
}

impl AnnounceHandler {
    #[must_use]
    pub fn new(
        config: &Core,
        in_memory_torrent_repository: &Arc<InMemoryTorrentRepository>,
        db_torrent_repository: &Arc<DatabasePersistentTorrentRepository>,
    ) -> Self {
        Self {
            config: config.clone(),
            in_memory_torrent_repository: in_memory_torrent_repository.clone(),
            db_torrent_repository: db_torrent_repository.clone(),
        }
    }

    /// It handles an announce request.
    ///
    /// BEP 03: [The `BitTorrent` Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html).
    pub fn announce(
        &self,
        info_hash: &InfoHash,
        peer: &mut peer::Peer,
        remote_client_ip: &IpAddr,
        peers_wanted: &PeersWanted,
    ) -> AnnounceData {
        // code-review: maybe instead of mutating the peer we could just return
        // a tuple with the new peer and the announce data: (Peer, AnnounceData).
        // It could even be a different struct: `StoredPeer` or `PublicPeer`.

        // code-review: in the `scrape` function we perform an authorization check.
        // We check if the torrent is whitelisted. Should we also check authorization here?
        // I think so because the `Tracker` has the responsibility for checking authentication and authorization.
        // The `Tracker` has delegated that responsibility to the handlers
        // (because we want to return a friendly error response) but that does not mean we should
        // double-check authorization at this domain level too.
        // I would propose to return a `Result<AnnounceData, Error>` here.
        // Besides, regarding authentication the `Tracker` is also responsible for authentication but
        // we are actually handling authentication at the handlers level. So I would extract that
        // responsibility into another authentication service.

        tracing::debug!("Before: {peer:?}");
        peer.change_ip(&assign_ip_address_to_peer(remote_client_ip, self.config.net.external_ip));
        tracing::debug!("After: {peer:?}");

        let stats = self.upsert_peer_and_get_stats(info_hash, peer);

        let peers = self
            .in_memory_torrent_repository
            .get_peers_for(info_hash, peer, peers_wanted.limit());

        AnnounceData {
            peers,
            stats,
            policy: self.config.announce_policy,
        }
    }

    /// It updates the torrent entry in memory, it also stores in the database
    /// the torrent info data which is persistent, and finally return the data
    /// needed for a `announce` request response.
    #[must_use]
    fn upsert_peer_and_get_stats(&self, info_hash: &InfoHash, peer: &peer::Peer) -> SwarmMetadata {
        let swarm_metadata_before = match self.in_memory_torrent_repository.get_opt_swarm_metadata(info_hash) {
            Some(swarm_metadata) => swarm_metadata,
            None => SwarmMetadata::zeroed(),
        };

        self.in_memory_torrent_repository.upsert_peer(info_hash, peer);

        let swarm_metadata_after = match self.in_memory_torrent_repository.get_opt_swarm_metadata(info_hash) {
            Some(swarm_metadata) => swarm_metadata,
            None => SwarmMetadata::zeroed(),
        };

        if swarm_metadata_before != swarm_metadata_after {
            self.persist_stats(info_hash, &swarm_metadata_after);
        }

        swarm_metadata_after
    }

    /// It stores the torrents stats into the database (if persistency is enabled).
    fn persist_stats(&self, info_hash: &InfoHash, swarm_metadata: &SwarmMetadata) {
        if self.config.tracker_policy.persistent_torrent_completed_stat {
            let completed = swarm_metadata.downloaded;
            let info_hash = *info_hash;

            drop(self.db_torrent_repository.save(&info_hash, completed));
        }
    }
}

/// How many peers the peer announcing wants in the announce response.
#[derive(Clone, Debug, PartialEq, Default)]
pub enum PeersWanted {
    /// The peer wants as many peers as possible in the announce response.
    #[default]
    All,
    /// The peer only wants a certain amount of peers in the announce response.
    Only { amount: usize },
}

impl PeersWanted {
    #[must_use]
    pub fn only(limit: u32) -> Self {
        let amount: usize = match limit.try_into() {
            Ok(amount) => amount,
            Err(_) => TORRENT_PEERS_LIMIT,
        };

        Self::Only { amount }
    }

    fn limit(&self) -> usize {
        match self {
            PeersWanted::All => TORRENT_PEERS_LIMIT,
            PeersWanted::Only { amount } => *amount,
        }
    }
}

impl From<i32> for PeersWanted {
    fn from(value: i32) -> Self {
        if value > 0 {
            match value.try_into() {
                Ok(peers_wanted) => Self::Only { amount: peers_wanted },
                Err(_) => Self::All,
            }
        } else {
            Self::All
        }
    }
}

#[must_use]
fn assign_ip_address_to_peer(remote_client_ip: &IpAddr, tracker_external_ip: Option<IpAddr>) -> IpAddr {
    if let Some(host_ip) = tracker_external_ip.filter(|_| remote_client_ip.is_loopback()) {
        host_ip
    } else {
        *remote_client_ip
    }
}

#[cfg(test)]
mod tests {
    mod the_announce_handler {

        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::str::FromStr;
        use std::sync::Arc;

        use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes, PeerId};
        use torrust_tracker_primitives::peer::Peer;
        use torrust_tracker_primitives::DurationSinceUnixEpoch;
        use torrust_tracker_test_helpers::configuration;

        use crate::announce_handler::AnnounceHandler;
        use crate::core_tests::initialize_handlers;
        use crate::scrape_handler::ScrapeHandler;

        fn public_tracker() -> (Arc<AnnounceHandler>, Arc<ScrapeHandler>) {
            let config = configuration::ephemeral_public();
            initialize_handlers(&config)
        }

        // The client peer IP
        fn peer_ip() -> IpAddr {
            IpAddr::V4(Ipv4Addr::from_str("126.0.0.1").unwrap())
        }

        /// Sample peer when for tests that need more than one peer
        fn sample_peer_1() -> Peer {
            Peer {
                peer_id: PeerId(*b"-qB00000000000000001"),
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8081),
                updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
                uploaded: NumberOfBytes::new(0),
                downloaded: NumberOfBytes::new(0),
                left: NumberOfBytes::new(0),
                event: AnnounceEvent::Completed,
            }
        }

        /// Sample peer when for tests that need more than one peer
        fn sample_peer_2() -> Peer {
            Peer {
                peer_id: PeerId(*b"-qB00000000000000002"),
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 2)), 8082),
                updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
                uploaded: NumberOfBytes::new(0),
                downloaded: NumberOfBytes::new(0),
                left: NumberOfBytes::new(0),
                event: AnnounceEvent::Completed,
            }
        }

        mod for_all_tracker_config_modes {

            mod handling_an_announce_request {

                use std::sync::Arc;

                use crate::announce_handler::tests::the_announce_handler::{
                    peer_ip, public_tracker, sample_peer_1, sample_peer_2,
                };
                use crate::announce_handler::PeersWanted;
                use crate::core_tests::{sample_info_hash, sample_peer};

                mod should_assign_the_ip_to_the_peer {

                    use std::net::{IpAddr, Ipv4Addr};

                    use crate::announce_handler::assign_ip_address_to_peer;

                    #[test]
                    fn using_the_source_ip_instead_of_the_ip_in_the_announce_request() {
                        let remote_ip = IpAddr::V4(Ipv4Addr::new(126, 0, 0, 2));

                        let peer_ip = assign_ip_address_to_peer(&remote_ip, None);

                        assert_eq!(peer_ip, remote_ip);
                    }

                    mod and_when_the_client_ip_is_a_ipv4_loopback_ip {

                        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
                        use std::str::FromStr;

                        use crate::announce_handler::assign_ip_address_to_peer;

                        #[test]
                        fn it_should_use_the_loopback_ip_if_the_tracker_does_not_have_the_external_ip_configuration() {
                            let remote_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

                            let peer_ip = assign_ip_address_to_peer(&remote_ip, None);

                            assert_eq!(peer_ip, remote_ip);
                        }

                        #[test]
                        fn it_should_use_the_external_tracker_ip_in_tracker_configuration_if_it_is_defined() {
                            let remote_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

                            let tracker_external_ip = IpAddr::V4(Ipv4Addr::from_str("126.0.0.1").unwrap());

                            let peer_ip = assign_ip_address_to_peer(&remote_ip, Some(tracker_external_ip));

                            assert_eq!(peer_ip, tracker_external_ip);
                        }

                        #[test]
                        fn it_should_use_the_external_ip_in_the_tracker_configuration_if_it_is_defined_even_if_the_external_ip_is_an_ipv6_ip(
                        ) {
                            let remote_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

                            let tracker_external_ip =
                                IpAddr::V6(Ipv6Addr::from_str("2345:0425:2CA1:0000:0000:0567:5673:23b5").unwrap());

                            let peer_ip = assign_ip_address_to_peer(&remote_ip, Some(tracker_external_ip));

                            assert_eq!(peer_ip, tracker_external_ip);
                        }
                    }

                    mod and_when_client_ip_is_a_ipv6_loopback_ip {

                        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
                        use std::str::FromStr;

                        use crate::announce_handler::assign_ip_address_to_peer;

                        #[test]
                        fn it_should_use_the_loopback_ip_if_the_tracker_does_not_have_the_external_ip_configuration() {
                            let remote_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);

                            let peer_ip = assign_ip_address_to_peer(&remote_ip, None);

                            assert_eq!(peer_ip, remote_ip);
                        }

                        #[test]
                        fn it_should_use_the_external_ip_in_tracker_configuration_if_it_is_defined() {
                            let remote_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);

                            let tracker_external_ip =
                                IpAddr::V6(Ipv6Addr::from_str("2345:0425:2CA1:0000:0000:0567:5673:23b5").unwrap());

                            let peer_ip = assign_ip_address_to_peer(&remote_ip, Some(tracker_external_ip));

                            assert_eq!(peer_ip, tracker_external_ip);
                        }

                        #[test]
                        fn it_should_use_the_external_ip_in_the_tracker_configuration_if_it_is_defined_even_if_the_external_ip_is_an_ipv4_ip(
                        ) {
                            let remote_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);

                            let tracker_external_ip = IpAddr::V4(Ipv4Addr::from_str("126.0.0.1").unwrap());

                            let peer_ip = assign_ip_address_to_peer(&remote_ip, Some(tracker_external_ip));

                            assert_eq!(peer_ip, tracker_external_ip);
                        }
                    }
                }

                #[tokio::test]
                async fn it_should_return_the_announce_data_with_an_empty_peer_list_when_it_is_the_first_announced_peer() {
                    let (announce_handler, _scrape_handler) = public_tracker();

                    let mut peer = sample_peer();

                    let announce_data = announce_handler.announce(&sample_info_hash(), &mut peer, &peer_ip(), &PeersWanted::All);

                    assert_eq!(announce_data.peers, vec![]);
                }

                #[tokio::test]
                async fn it_should_return_the_announce_data_with_the_previously_announced_peers() {
                    let (announce_handler, _scrape_handler) = public_tracker();

                    let mut previously_announced_peer = sample_peer_1();
                    announce_handler.announce(
                        &sample_info_hash(),
                        &mut previously_announced_peer,
                        &peer_ip(),
                        &PeersWanted::All,
                    );

                    let mut peer = sample_peer_2();
                    let announce_data = announce_handler.announce(&sample_info_hash(), &mut peer, &peer_ip(), &PeersWanted::All);

                    assert_eq!(announce_data.peers, vec![Arc::new(previously_announced_peer)]);
                }

                mod it_should_update_the_swarm_stats_for_the_torrent {

                    use crate::announce_handler::tests::the_announce_handler::{peer_ip, public_tracker};
                    use crate::announce_handler::PeersWanted;
                    use crate::core_tests::{completed_peer, leecher, sample_info_hash, seeder, started_peer};

                    #[tokio::test]
                    async fn when_the_peer_is_a_seeder() {
                        let (announce_handler, _scrape_handler) = public_tracker();

                        let mut peer = seeder();

                        let announce_data =
                            announce_handler.announce(&sample_info_hash(), &mut peer, &peer_ip(), &PeersWanted::All);

                        assert_eq!(announce_data.stats.complete, 1);
                    }

                    #[tokio::test]
                    async fn when_the_peer_is_a_leecher() {
                        let (announce_handler, _scrape_handler) = public_tracker();

                        let mut peer = leecher();

                        let announce_data =
                            announce_handler.announce(&sample_info_hash(), &mut peer, &peer_ip(), &PeersWanted::All);

                        assert_eq!(announce_data.stats.incomplete, 1);
                    }

                    #[tokio::test]
                    async fn when_a_previously_announced_started_peer_has_completed_downloading() {
                        let (announce_handler, _scrape_handler) = public_tracker();

                        // We have to announce with "started" event because peer does not count if peer was not previously known
                        let mut started_peer = started_peer();
                        announce_handler.announce(&sample_info_hash(), &mut started_peer, &peer_ip(), &PeersWanted::All);

                        let mut completed_peer = completed_peer();
                        let announce_data =
                            announce_handler.announce(&sample_info_hash(), &mut completed_peer, &peer_ip(), &PeersWanted::All);

                        assert_eq!(announce_data.stats.downloaded, 1);
                    }
                }
            }
        }

        mod handling_torrent_persistence {

            use std::sync::Arc;

            use aquatic_udp_protocol::AnnounceEvent;
            use torrust_tracker_test_helpers::configuration;
            use torrust_tracker_torrent_repository::entry::EntrySync;

            use crate::announce_handler::tests::the_announce_handler::peer_ip;
            use crate::announce_handler::{AnnounceHandler, PeersWanted};
            use crate::core_tests::{sample_info_hash, sample_peer};
            use crate::databases::setup::initialize_database;
            use crate::torrent::manager::TorrentsManager;
            use crate::torrent::repository::in_memory::InMemoryTorrentRepository;
            use crate::torrent::repository::persisted::DatabasePersistentTorrentRepository;

            #[tokio::test]
            async fn it_should_persist_the_number_of_completed_peers_for_all_torrents_into_the_database() {
                let mut config = configuration::ephemeral_listed();

                config.core.tracker_policy.persistent_torrent_completed_stat = true;

                let database = initialize_database(&config);
                let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());
                let db_torrent_repository = Arc::new(DatabasePersistentTorrentRepository::new(&database));
                let torrents_manager = Arc::new(TorrentsManager::new(
                    &config.core,
                    &in_memory_torrent_repository,
                    &db_torrent_repository,
                ));
                let announce_handler = Arc::new(AnnounceHandler::new(
                    &config.core,
                    &in_memory_torrent_repository,
                    &db_torrent_repository,
                ));

                let info_hash = sample_info_hash();

                let mut peer = sample_peer();

                peer.event = AnnounceEvent::Started;
                let announce_data = announce_handler.announce(&info_hash, &mut peer, &peer_ip(), &PeersWanted::All);
                assert_eq!(announce_data.stats.downloaded, 0);

                peer.event = AnnounceEvent::Completed;
                let announce_data = announce_handler.announce(&info_hash, &mut peer, &peer_ip(), &PeersWanted::All);
                assert_eq!(announce_data.stats.downloaded, 1);

                // Remove the newly updated torrent from memory
                let _unused = in_memory_torrent_repository.remove(&info_hash);

                torrents_manager.load_torrents_from_database().unwrap();

                let torrent_entry = in_memory_torrent_repository
                    .get(&info_hash)
                    .expect("it should be able to get entry");

                // It persists the number of completed peers.
                assert_eq!(torrent_entry.get_swarm_metadata().downloaded, 1);

                // It does not persist the peers
                assert!(torrent_entry.peers_is_empty());
            }
        }
    }
}
