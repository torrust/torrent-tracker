use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use crossbeam_skiplist::SkipMap;
use torrust_tracker_configuration::TrackerPolicy;
use torrust_tracker_primitives::pagination::Pagination;
use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;
use torrust_tracker_primitives::torrent_metrics::TorrentsMetrics;
use torrust_tracker_primitives::{peer, DurationSinceUnixEpoch, PersistentTorrents};

use super::Repository;
use crate::entry::peer_list::PeerList;
use crate::entry::{Entry, EntrySync};
use crate::{EntryMutexParkingLot, EntryMutexStd, EntryRwLockParkingLot, EntrySingle};

#[derive(Default, Debug)]
pub struct CrossbeamSkipList<T> {
    pub torrents: SkipMap<InfoHash, T>,
}

impl Repository<EntryMutexStd> for CrossbeamSkipList<EntryMutexStd>
where
    EntryMutexStd: EntrySync,
    EntrySingle: Entry,
{
    fn upsert_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        let entry = self.torrents.get_or_insert(*info_hash, Arc::default());
        entry.value().upsert_peer(peer);
    }

    fn get_swarm_metadata(&self, info_hash: &InfoHash) -> Option<SwarmMetadata> {
        self.torrents.get(info_hash).map(|entry| entry.value().get_swarm_metadata())
    }

    fn get(&self, key: &InfoHash) -> Option<EntryMutexStd> {
        let maybe_entry = self.torrents.get(key);
        maybe_entry.map(|entry| entry.value().clone())
    }

    fn get_metrics(&self) -> TorrentsMetrics {
        let mut metrics = TorrentsMetrics::default();

        for entry in &self.torrents {
            let stats = entry.value().lock().expect("it should get a lock").get_swarm_metadata();
            metrics.complete += u64::from(stats.complete);
            metrics.downloaded += u64::from(stats.downloaded);
            metrics.incomplete += u64::from(stats.incomplete);
            metrics.torrents += 1;
        }

        metrics
    }

    fn get_paginated(&self, pagination: Option<&Pagination>) -> Vec<(InfoHash, EntryMutexStd)> {
        match pagination {
            Some(pagination) => self
                .torrents
                .iter()
                .skip(pagination.offset as usize)
                .take(pagination.limit as usize)
                .map(|entry| (*entry.key(), entry.value().clone()))
                .collect(),
            None => self
                .torrents
                .iter()
                .map(|entry| (*entry.key(), entry.value().clone()))
                .collect(),
        }
    }

    fn import_persistent(&self, persistent_torrents: &PersistentTorrents) {
        for (info_hash, completed) in persistent_torrents {
            if self.torrents.contains_key(info_hash) {
                continue;
            }

            let entry = EntryMutexStd::new(
                EntrySingle {
                    swarm: PeerList::default(),
                    downloaded: *completed,
                }
                .into(),
            );

            // Since SkipMap is lock-free the torrent could have been inserted
            // after checking if it exists.
            self.torrents.get_or_insert(*info_hash, entry);
        }
    }

    fn remove(&self, key: &InfoHash) -> Option<EntryMutexStd> {
        self.torrents.remove(key).map(|entry| entry.value().clone())
    }

    fn remove_inactive_peers(&self, current_cutoff: DurationSinceUnixEpoch) {
        for entry in &self.torrents {
            entry.value().remove_inactive_peers(current_cutoff);
        }
    }

    fn remove_peerless_torrents(&self, policy: &TrackerPolicy) {
        for entry in &self.torrents {
            if entry.value().meets_retaining_policy(policy) {
                continue;
            }

            entry.remove();
        }
    }
}

impl Repository<EntryRwLockParkingLot> for CrossbeamSkipList<EntryRwLockParkingLot>
where
    EntryRwLockParkingLot: EntrySync,
    EntrySingle: Entry,
{
    fn upsert_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        let entry = self.torrents.get_or_insert(*info_hash, Arc::default());
        entry.value().upsert_peer(peer);
    }

    fn get_swarm_metadata(&self, info_hash: &InfoHash) -> Option<SwarmMetadata> {
        self.torrents.get(info_hash).map(|entry| entry.value().get_swarm_metadata())
    }

    fn get(&self, key: &InfoHash) -> Option<EntryRwLockParkingLot> {
        let maybe_entry = self.torrents.get(key);
        maybe_entry.map(|entry| entry.value().clone())
    }

    fn get_metrics(&self) -> TorrentsMetrics {
        let mut metrics = TorrentsMetrics::default();

        for entry in &self.torrents {
            let stats = entry.value().read().get_swarm_metadata();
            metrics.complete += u64::from(stats.complete);
            metrics.downloaded += u64::from(stats.downloaded);
            metrics.incomplete += u64::from(stats.incomplete);
            metrics.torrents += 1;
        }

        metrics
    }

    fn get_paginated(&self, pagination: Option<&Pagination>) -> Vec<(InfoHash, EntryRwLockParkingLot)> {
        match pagination {
            Some(pagination) => self
                .torrents
                .iter()
                .skip(pagination.offset as usize)
                .take(pagination.limit as usize)
                .map(|entry| (*entry.key(), entry.value().clone()))
                .collect(),
            None => self
                .torrents
                .iter()
                .map(|entry| (*entry.key(), entry.value().clone()))
                .collect(),
        }
    }

    fn import_persistent(&self, persistent_torrents: &PersistentTorrents) {
        for (info_hash, completed) in persistent_torrents {
            if self.torrents.contains_key(info_hash) {
                continue;
            }

            let entry = EntryRwLockParkingLot::new(
                EntrySingle {
                    swarm: PeerList::default(),
                    downloaded: *completed,
                }
                .into(),
            );

            // Since SkipMap is lock-free the torrent could have been inserted
            // after checking if it exists.
            self.torrents.get_or_insert(*info_hash, entry);
        }
    }

    fn remove(&self, key: &InfoHash) -> Option<EntryRwLockParkingLot> {
        self.torrents.remove(key).map(|entry| entry.value().clone())
    }

    fn remove_inactive_peers(&self, current_cutoff: DurationSinceUnixEpoch) {
        for entry in &self.torrents {
            entry.value().remove_inactive_peers(current_cutoff);
        }
    }

    fn remove_peerless_torrents(&self, policy: &TrackerPolicy) {
        for entry in &self.torrents {
            if entry.value().meets_retaining_policy(policy) {
                continue;
            }

            entry.remove();
        }
    }
}

impl Repository<EntryMutexParkingLot> for CrossbeamSkipList<EntryMutexParkingLot>
where
    EntryMutexParkingLot: EntrySync,
    EntrySingle: Entry,
{
    fn upsert_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        let entry = self.torrents.get_or_insert(*info_hash, Arc::default());
        entry.value().upsert_peer(peer);
    }

    fn get_swarm_metadata(&self, info_hash: &InfoHash) -> Option<SwarmMetadata> {
        self.torrents.get(info_hash).map(|entry| entry.value().get_swarm_metadata())
    }

    fn get(&self, key: &InfoHash) -> Option<EntryMutexParkingLot> {
        let maybe_entry = self.torrents.get(key);
        maybe_entry.map(|entry| entry.value().clone())
    }

    fn get_metrics(&self) -> TorrentsMetrics {
        let mut metrics = TorrentsMetrics::default();

        for entry in &self.torrents {
            let stats = entry.value().lock().get_swarm_metadata();
            metrics.complete += u64::from(stats.complete);
            metrics.downloaded += u64::from(stats.downloaded);
            metrics.incomplete += u64::from(stats.incomplete);
            metrics.torrents += 1;
        }

        metrics
    }

    fn get_paginated(&self, pagination: Option<&Pagination>) -> Vec<(InfoHash, EntryMutexParkingLot)> {
        match pagination {
            Some(pagination) => self
                .torrents
                .iter()
                .skip(pagination.offset as usize)
                .take(pagination.limit as usize)
                .map(|entry| (*entry.key(), entry.value().clone()))
                .collect(),
            None => self
                .torrents
                .iter()
                .map(|entry| (*entry.key(), entry.value().clone()))
                .collect(),
        }
    }

    fn import_persistent(&self, persistent_torrents: &PersistentTorrents) {
        for (info_hash, completed) in persistent_torrents {
            if self.torrents.contains_key(info_hash) {
                continue;
            }

            let entry = EntryMutexParkingLot::new(
                EntrySingle {
                    swarm: PeerList::default(),
                    downloaded: *completed,
                }
                .into(),
            );

            // Since SkipMap is lock-free the torrent could have been inserted
            // after checking if it exists.
            self.torrents.get_or_insert(*info_hash, entry);
        }
    }

    fn remove(&self, key: &InfoHash) -> Option<EntryMutexParkingLot> {
        self.torrents.remove(key).map(|entry| entry.value().clone())
    }

    fn remove_inactive_peers(&self, current_cutoff: DurationSinceUnixEpoch) {
        for entry in &self.torrents {
            entry.value().remove_inactive_peers(current_cutoff);
        }
    }

    fn remove_peerless_torrents(&self, policy: &TrackerPolicy) {
        for entry in &self.torrents {
            if entry.value().meets_retaining_policy(policy) {
                continue;
            }

            entry.remove();
        }
    }
}
