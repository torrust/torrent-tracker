use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_configuration::TrackerPolicy;
use torrust_tracker_primitives::pagination::Pagination;
use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;
use torrust_tracker_primitives::torrent_metrics::TorrentsMetrics;
use torrust_tracker_primitives::{peer, DurationSinceUnixEpoch, PersistentTorrents};

use super::Repository;
use crate::entry::peer_list::PeerList;
use crate::entry::{Entry, EntrySync};
use crate::{EntryMutexStd, EntrySingle, TorrentsRwLockStdMutexStd};

impl TorrentsRwLockStdMutexStd {
    fn get_torrents<'a>(&'a self) -> std::sync::RwLockReadGuard<'a, std::collections::BTreeMap<InfoHash, EntryMutexStd>>
    where
        std::collections::BTreeMap<InfoHash, crate::EntryMutexStd>: 'a,
    {
        self.torrents.read().expect("unable to get torrent list")
    }

    fn get_torrents_mut<'a>(&'a self) -> std::sync::RwLockWriteGuard<'a, std::collections::BTreeMap<InfoHash, EntryMutexStd>>
    where
        std::collections::BTreeMap<InfoHash, EntryMutexStd>: 'a,
    {
        self.torrents.write().expect("unable to get writable torrent list")
    }
}

impl Repository<EntryMutexStd> for TorrentsRwLockStdMutexStd
where
    EntryMutexStd: EntrySync,
    EntrySingle: Entry,
{
    fn upsert_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        let maybe_entry = self.get_torrents().get(info_hash).cloned();

        let entry = if let Some(entry) = maybe_entry {
            entry
        } else {
            let mut db = self.get_torrents_mut();
            let entry = db.entry(*info_hash).or_insert(Arc::default());
            entry.clone()
        };

        entry.upsert_peer(peer);
    }

    fn get_swarm_metadata(&self, info_hash: &InfoHash) -> Option<SwarmMetadata> {
        self.get_torrents()
            .get(info_hash)
            .map(super::super::entry::EntrySync::get_swarm_metadata)
    }

    fn get(&self, key: &InfoHash) -> Option<EntryMutexStd> {
        let db = self.get_torrents();
        db.get(key).cloned()
    }

    fn get_metrics(&self) -> TorrentsMetrics {
        let mut metrics = TorrentsMetrics::default();

        for entry in self.get_torrents().values() {
            let stats = entry.lock().expect("it should get a lock").get_swarm_metadata();
            metrics.complete += u64::from(stats.complete);
            metrics.downloaded += u64::from(stats.downloaded);
            metrics.incomplete += u64::from(stats.incomplete);
            metrics.torrents += 1;
        }

        metrics
    }

    fn get_paginated(&self, pagination: Option<&Pagination>) -> Vec<(InfoHash, EntryMutexStd)> {
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

        for (info_hash, completed) in persistent_torrents {
            // Skip if torrent entry already exists
            if torrents.contains_key(info_hash) {
                continue;
            }

            let entry = EntryMutexStd::new(
                EntrySingle {
                    swarm: PeerList::default(),
                    downloaded: *completed,
                }
                .into(),
            );

            torrents.insert(*info_hash, entry);
        }
    }

    fn remove(&self, key: &InfoHash) -> Option<EntryMutexStd> {
        let mut db = self.get_torrents_mut();
        db.remove(key)
    }

    fn remove_inactive_peers(&self, current_cutoff: DurationSinceUnixEpoch) {
        let db = self.get_torrents();
        let entries = db.values().cloned();

        for entry in entries {
            entry.remove_inactive_peers(current_cutoff);
        }
    }

    fn remove_peerless_torrents(&self, policy: &TrackerPolicy) {
        let mut db = self.get_torrents_mut();

        db.retain(|_, e| e.lock().expect("it should lock entry").meets_retaining_policy(policy));
    }
}
