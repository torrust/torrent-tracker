use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_configuration::TrackerPolicy;
use torrust_tracker_primitives::pagination::Pagination;
use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;
use torrust_tracker_primitives::torrent_metrics::TorrentsMetrics;
use torrust_tracker_primitives::{peer, DurationSinceUnixEpoch, PersistentTorrents};

use super::Repository;
use crate::entry::peer_list::PeerList;
use crate::entry::Entry;
use crate::{EntrySingle, TorrentsRwLockStd};

#[derive(Default, Debug)]
pub struct RwLockStd<T> {
    pub(crate) torrents: std::sync::RwLock<std::collections::BTreeMap<InfoHash, T>>,
}

impl<T> RwLockStd<T> {
    /// # Panics
    ///
    /// Panics if unable to get a lock.
    pub fn write(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, std::collections::BTreeMap<bittorrent_primitives::info_hash::InfoHash, T>> {
        self.torrents.write().expect("it should get lock")
    }
}

impl TorrentsRwLockStd {
    fn get_torrents<'a>(&'a self) -> std::sync::RwLockReadGuard<'a, std::collections::BTreeMap<InfoHash, EntrySingle>>
    where
        std::collections::BTreeMap<InfoHash, EntrySingle>: 'a,
    {
        self.torrents.read().expect("it should get the read lock")
    }

    fn get_torrents_mut<'a>(&'a self) -> std::sync::RwLockWriteGuard<'a, std::collections::BTreeMap<InfoHash, EntrySingle>>
    where
        std::collections::BTreeMap<InfoHash, EntrySingle>: 'a,
    {
        self.torrents.write().expect("it should get the write lock")
    }
}

impl Repository<EntrySingle> for TorrentsRwLockStd
where
    EntrySingle: Entry,
{
    fn upsert_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        let mut db = self.get_torrents_mut();

        let entry = db.entry(*info_hash).or_insert(EntrySingle::default());

        entry.upsert_peer(peer);
    }

    fn get_swarm_metadata(&self, info_hash: &InfoHash) -> Option<SwarmMetadata> {
        self.get(info_hash).map(|entry| entry.get_swarm_metadata())
    }

    fn get(&self, key: &InfoHash) -> Option<EntrySingle> {
        let db = self.get_torrents();
        db.get(key).cloned()
    }

    fn get_metrics(&self) -> TorrentsMetrics {
        let mut metrics = TorrentsMetrics::default();

        for entry in self.get_torrents().values() {
            let stats = entry.get_swarm_metadata();
            metrics.complete += u64::from(stats.complete);
            metrics.downloaded += u64::from(stats.downloaded);
            metrics.incomplete += u64::from(stats.incomplete);
            metrics.torrents += 1;
        }

        metrics
    }

    fn get_paginated(&self, pagination: Option<&Pagination>) -> Vec<(InfoHash, EntrySingle)> {
        let db = self.get_torrents();

        match pagination {
            Some(pagination) => db
                .iter()
                .skip(pagination.offset as usize)
                .take(pagination.limit as usize)
                .map(|(a, b)| (*a, b.clone()))
                .collect(),
            None => db.iter().map(|(a, b)| (*a, b.clone())).collect(),
        }
    }

    fn import_persistent(&self, persistent_torrents: &PersistentTorrents) {
        let mut torrents = self.get_torrents_mut();

        for (info_hash, downloaded) in persistent_torrents {
            // Skip if torrent entry already exists
            if torrents.contains_key(info_hash) {
                continue;
            }

            let entry = EntrySingle {
                swarm: PeerList::default(),
                downloaded: *downloaded,
            };

            torrents.insert(*info_hash, entry);
        }
    }

    fn remove(&self, key: &InfoHash) -> Option<EntrySingle> {
        let mut db = self.get_torrents_mut();
        db.remove(key)
    }

    fn remove_inactive_peers(&self, current_cutoff: DurationSinceUnixEpoch) {
        let mut db = self.get_torrents_mut();
        let entries = db.values_mut();

        for entry in entries {
            entry.remove_inactive_peers(current_cutoff);
        }
    }

    fn remove_peerless_torrents(&self, policy: &TrackerPolicy) {
        let mut db = self.get_torrents_mut();

        db.retain(|_, e| e.meets_retaining_policy(policy));
    }
}
