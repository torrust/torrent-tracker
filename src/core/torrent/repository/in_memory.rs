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

use crate::core::torrent::Torrents;

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
