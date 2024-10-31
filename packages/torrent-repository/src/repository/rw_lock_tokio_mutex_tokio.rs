use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_configuration::TrackerPolicy;
use torrust_tracker_primitives::pagination::Pagination;
use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;
use torrust_tracker_primitives::torrent_metrics::TorrentsMetrics;
use torrust_tracker_primitives::{peer, DurationSinceUnixEpoch, PersistentTorrents};

use super::RepositoryAsync;
use crate::entry::peer_list::PeerList;
use crate::entry::{Entry, EntryAsync};
use crate::{EntryMutexTokio, EntrySingle, TorrentsRwLockTokioMutexTokio};

impl TorrentsRwLockTokioMutexTokio {
    async fn get_torrents<'a>(&'a self) -> tokio::sync::RwLockReadGuard<'a, std::collections::BTreeMap<InfoHash, EntryMutexTokio>>
    where
        std::collections::BTreeMap<InfoHash, EntryMutexTokio>: 'a,
    {
        self.torrents.read().await
    }

    async fn get_torrents_mut<'a>(
        &'a self,
    ) -> tokio::sync::RwLockWriteGuard<'a, std::collections::BTreeMap<InfoHash, EntryMutexTokio>>
    where
        std::collections::BTreeMap<InfoHash, EntryMutexTokio>: 'a,
    {
        self.torrents.write().await
    }
}

impl RepositoryAsync<EntryMutexTokio> for TorrentsRwLockTokioMutexTokio
where
    EntryMutexTokio: EntryAsync,
    EntrySingle: Entry,
{
    async fn upsert_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        let maybe_entry = self.get_torrents().await.get(info_hash).cloned();

        let entry = if let Some(entry) = maybe_entry {
            entry
        } else {
            let mut db = self.get_torrents_mut().await;
            let entry = db.entry(*info_hash).or_insert(Arc::default());
            entry.clone()
        };

        entry.upsert_peer(peer).await;
    }

    async fn get_swarm_metadata(&self, info_hash: &InfoHash) -> Option<SwarmMetadata> {
        match self.get(info_hash).await {
            Some(entry) => Some(entry.get_swarm_metadata().await),
            None => None,
        }
    }

    async fn get(&self, key: &InfoHash) -> Option<EntryMutexTokio> {
        let db = self.get_torrents().await;
        db.get(key).cloned()
    }

    async fn get_paginated(&self, pagination: Option<&Pagination>) -> Vec<(InfoHash, EntryMutexTokio)> {
        let db = self.get_torrents().await;

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

    async fn get_metrics(&self) -> TorrentsMetrics {
        let mut metrics = TorrentsMetrics::default();

        for entry in self.get_torrents().await.values() {
            let stats = entry.get_swarm_metadata().await;
            metrics.complete += u64::from(stats.complete);
            metrics.downloaded += u64::from(stats.downloaded);
            metrics.incomplete += u64::from(stats.incomplete);
            metrics.torrents += 1;
        }

        metrics
    }

    async fn import_persistent(&self, persistent_torrents: &PersistentTorrents) {
        let mut db = self.get_torrents_mut().await;

        for (info_hash, completed) in persistent_torrents {
            // Skip if torrent entry already exists
            if db.contains_key(info_hash) {
                continue;
            }

            let entry = EntryMutexTokio::new(
                EntrySingle {
                    swarm: PeerList::default(),
                    downloaded: *completed,
                }
                .into(),
            );

            db.insert(*info_hash, entry);
        }
    }

    async fn remove(&self, key: &InfoHash) -> Option<EntryMutexTokio> {
        let mut db = self.get_torrents_mut().await;
        db.remove(key)
    }

    async fn remove_inactive_peers(&self, current_cutoff: DurationSinceUnixEpoch) {
        let db = self.get_torrents().await;
        let entries = db.values().cloned();

        for entry in entries {
            entry.remove_inactive_peers(current_cutoff).await;
        }
    }

    async fn remove_peerless_torrents(&self, policy: &TrackerPolicy) {
        let mut db = self.get_torrents_mut().await;

        let mut not_good = Vec::<InfoHash>::default();

        for (&infohash, torrent) in db.iter() {
            if !torrent.clone().meets_retaining_policy(policy).await {
                not_good.push(infohash);
            }
        }

        for remove in not_good {
            drop(db.remove(&remove));
        }
    }
}
