use std::cmp::max;
use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_configuration::{TrackerPolicy, TORRENT_PEERS_LIMIT};
use torrust_tracker_primitives::pagination::Pagination;
use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;
use torrust_tracker_primitives::torrent_metrics::TorrentsMetrics;
use torrust_tracker_primitives::{peer, DurationSinceUnixEpoch, PersistentTorrents};
use torrust_tracker_torrent_repository::entry::EntrySync;
use torrust_tracker_torrent_repository::repository::Repository;
use torrust_tracker_torrent_repository::EntryMutexStd;

use crate::torrent::Torrents;

/// The in-memory torrents repository.
///
/// There are many implementations of the repository trait. We tried with
/// different types of data structures, but the best performance was with
/// the one we use for production. We kept the other implementations for
/// reference.
#[derive(Debug, Default)]
pub struct InMemoryTorrentRepository {
    /// The in-memory torrents repository implementation.
    torrents: Arc<Torrents>,
}

impl InMemoryTorrentRepository {
    /// It inserts (or updates if it's already in the list) the peer in the
    /// torrent entry.
    pub fn upsert_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        self.torrents.upsert_peer(info_hash, peer);
    }

    #[must_use]
    pub fn remove(&self, key: &InfoHash) -> Option<EntryMutexStd> {
        self.torrents.remove(key)
    }

    pub fn remove_inactive_peers(&self, current_cutoff: DurationSinceUnixEpoch) {
        self.torrents.remove_inactive_peers(current_cutoff);
    }

    pub fn remove_peerless_torrents(&self, policy: &TrackerPolicy) {
        self.torrents.remove_peerless_torrents(policy);
    }

    #[must_use]
    pub fn get(&self, key: &InfoHash) -> Option<EntryMutexStd> {
        self.torrents.get(key)
    }

    #[must_use]
    pub fn get_paginated(&self, pagination: Option<&Pagination>) -> Vec<(InfoHash, EntryMutexStd)> {
        self.torrents.get_paginated(pagination)
    }

    /// It returns the data for a `scrape` response or empty if the torrent is
    /// not found.
    #[must_use]
    pub fn get_swarm_metadata(&self, info_hash: &InfoHash) -> SwarmMetadata {
        match self.torrents.get(info_hash) {
            Some(torrent_entry) => torrent_entry.get_swarm_metadata(),
            None => SwarmMetadata::default(),
        }
    }

    /// It returns the data for a `scrape` response if the torrent is found.
    #[must_use]
    pub fn get_opt_swarm_metadata(&self, info_hash: &InfoHash) -> Option<SwarmMetadata> {
        self.torrents.get_swarm_metadata(info_hash)
    }

    /// Get torrent peers for a given torrent and client.
    ///
    /// It filters out the client making the request.
    #[must_use]
    pub fn get_peers_for(&self, info_hash: &InfoHash, peer: &peer::Peer, limit: usize) -> Vec<Arc<peer::Peer>> {
        match self.torrents.get(info_hash) {
            None => vec![],
            Some(entry) => entry.get_peers_for_client(&peer.peer_addr, Some(max(limit, TORRENT_PEERS_LIMIT))),
        }
    }

    /// Get torrent peers for a given torrent.
    #[must_use]
    pub fn get_torrent_peers(&self, info_hash: &InfoHash) -> Vec<Arc<peer::Peer>> {
        match self.torrents.get(info_hash) {
            None => vec![],
            Some(entry) => entry.get_peers(Some(TORRENT_PEERS_LIMIT)),
        }
    }

    /// It calculates and returns the general [`TorrentsMetrics`].
    #[must_use]
    pub fn get_torrents_metrics(&self) -> TorrentsMetrics {
        self.torrents.get_metrics()
    }

    pub fn import_persistent(&self, persistent_torrents: &PersistentTorrents) {
        self.torrents.import_persistent(persistent_torrents);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes, PeerId};
    use bittorrent_primitives::info_hash::fixture::gen_seeded_infohash;
    use torrust_tracker_configuration::TORRENT_PEERS_LIMIT;
    use torrust_tracker_primitives::peer::Peer;
    use torrust_tracker_primitives::torrent_metrics::TorrentsMetrics;
    use torrust_tracker_primitives::DurationSinceUnixEpoch;

    use crate::core_tests::{leecher, sample_info_hash, sample_peer};
    use crate::torrent::repository::in_memory::InMemoryTorrentRepository;

    /// It generates a peer id from a number where the number is the last
    /// part of the peer ID. For example, for `12` it returns
    /// `-qB00000000000000012`.
    fn numeric_peer_id(two_digits_value: i32) -> PeerId {
        // Format idx as a string with leading zeros, ensuring it has exactly 2 digits
        let idx_str = format!("{two_digits_value:02}");

        // Create the base part of the peer ID.
        let base = b"-qB00000000000000000";

        // Concatenate the base with idx bytes, ensuring the total length is 20 bytes.
        let mut peer_id_bytes = [0u8; 20];
        peer_id_bytes[..base.len()].copy_from_slice(base);
        peer_id_bytes[base.len() - idx_str.len()..].copy_from_slice(idx_str.as_bytes());

        PeerId(peer_id_bytes)
    }

    #[tokio::test]
    async fn it_should_collect_torrent_metrics() {
        let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());

        let torrents_metrics = in_memory_torrent_repository.get_torrents_metrics();

        assert_eq!(
            torrents_metrics,
            TorrentsMetrics {
                complete: 0,
                downloaded: 0,
                incomplete: 0,
                torrents: 0
            }
        );
    }

    #[tokio::test]
    async fn it_should_return_74_peers_at_the_most_for_a_given_torrent() {
        let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());

        let info_hash = sample_info_hash();

        for idx in 1..=75 {
            let peer = Peer {
                peer_id: numeric_peer_id(idx),
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, idx.try_into().unwrap())), 8080),
                updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
                uploaded: NumberOfBytes::new(0),
                downloaded: NumberOfBytes::new(0),
                left: NumberOfBytes::new(0), // No bytes left to download
                event: AnnounceEvent::Completed,
            };

            let () = in_memory_torrent_repository.upsert_peer(&info_hash, &peer);
        }

        let peers = in_memory_torrent_repository.get_torrent_peers(&info_hash);

        assert_eq!(peers.len(), 74);
    }

    #[tokio::test]
    async fn it_should_return_the_peers_for_a_given_torrent_excluding_a_given_peer() {
        let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());

        let info_hash = sample_info_hash();
        let peer = sample_peer();

        let () = in_memory_torrent_repository.upsert_peer(&info_hash, &peer);

        let peers = in_memory_torrent_repository.get_peers_for(&info_hash, &peer, TORRENT_PEERS_LIMIT);

        assert_eq!(peers, vec![]);
    }

    #[tokio::test]
    async fn it_should_return_74_peers_at_the_most_for_a_given_torrent_when_it_filters_out_a_given_peer() {
        let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());

        let info_hash = sample_info_hash();

        let excluded_peer = sample_peer();

        let () = in_memory_torrent_repository.upsert_peer(&info_hash, &excluded_peer);

        // Add 74 peers
        for idx in 2..=75 {
            let peer = Peer {
                peer_id: numeric_peer_id(idx),
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, idx.try_into().unwrap())), 8080),
                updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
                uploaded: NumberOfBytes::new(0),
                downloaded: NumberOfBytes::new(0),
                left: NumberOfBytes::new(0), // No bytes left to download
                event: AnnounceEvent::Completed,
            };

            let () = in_memory_torrent_repository.upsert_peer(&info_hash, &peer);
        }

        let peers = in_memory_torrent_repository.get_peers_for(&info_hash, &excluded_peer, TORRENT_PEERS_LIMIT);

        assert_eq!(peers.len(), 74);
    }

    #[tokio::test]
    async fn it_should_return_the_torrent_metrics() {
        let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());

        let () = in_memory_torrent_repository.upsert_peer(&sample_info_hash(), &leecher());

        let torrent_metrics = in_memory_torrent_repository.get_torrents_metrics();

        assert_eq!(
            torrent_metrics,
            TorrentsMetrics {
                complete: 0,
                downloaded: 0,
                incomplete: 1,
                torrents: 1,
            }
        );
    }

    #[tokio::test]
    async fn it_should_get_many_the_torrent_metrics() {
        let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());

        let start_time = std::time::Instant::now();
        for i in 0..1_000_000 {
            let () = in_memory_torrent_repository.upsert_peer(&gen_seeded_infohash(&i), &leecher());
        }
        let result_a = start_time.elapsed();

        let start_time = std::time::Instant::now();
        let torrent_metrics = in_memory_torrent_repository.get_torrents_metrics();
        let result_b = start_time.elapsed();

        assert_eq!(
            (torrent_metrics),
            (TorrentsMetrics {
                complete: 0,
                downloaded: 0,
                incomplete: 1_000_000,
                torrents: 1_000_000,
            }),
            "{result_a:?} {result_b:?}"
        );
    }

    #[tokio::test]
    async fn it_should_return_the_peers_for_a_given_torrent() {
        let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());

        let info_hash = sample_info_hash();
        let peer = sample_peer();

        let () = in_memory_torrent_repository.upsert_peer(&info_hash, &peer);

        let peers = in_memory_torrent_repository.get_torrent_peers(&info_hash);

        assert_eq!(peers, vec![Arc::new(peer)]);
    }
}
