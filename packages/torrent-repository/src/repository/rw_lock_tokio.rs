use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_configuration::TrackerPolicy;
use torrust_tracker_primitives::pagination::Pagination;
use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;
use torrust_tracker_primitives::torrent_metrics::TorrentsMetrics;
use torrust_tracker_primitives::{peer, DurationSinceUnixEpoch, PersistentTorrents};

use super::RepositoryAsync;
use crate::entry::peer_list::PeerList;
use crate::entry::Entry;
use crate::{EntrySingle, TorrentsRwLockTokio};

#[derive(Default, Debug)]
pub struct RwLockTokio<T> {
    pub(crate) torrents: tokio::sync::RwLock<std::collections::BTreeMap<InfoHash, T>>,
}

impl<T> RwLockTokio<T> {
    pub fn write(
        &self,
    ) -> impl std::future::Future<
        Output = tokio::sync::RwLockWriteGuard<'_, std::collections::BTreeMap<bittorrent_primitives::info_hash::InfoHash, T>>,
    > {
        self.torrents.write()
    }
}

impl TorrentsRwLockTokio {
    async fn get_torrents<'a>(&'a self) -> tokio::sync::RwLockReadGuard<'a, std::collections::BTreeMap<InfoHash, EntrySingle>>
    where
        std::collections::BTreeMap<InfoHash, EntrySingle>: 'a,
    {
        self.torrents.read().await
    }

    async fn get_torrents_mut<'a>(
        &'a self,
    ) -> tokio::sync::RwLockWriteGuard<'a, std::collections::BTreeMap<InfoHash, EntrySingle>>
    where
        std::collections::BTreeMap<InfoHash, EntrySingle>: 'a,
    {
        self.torrents.write().await
    }
}

impl RepositoryAsync<EntrySingle> for TorrentsRwLockTokio
where
    EntrySingle: Entry,
{
    async fn upsert_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        let mut db = self.get_torrents_mut().await;

        let entry = db.entry(*info_hash).or_insert(EntrySingle::default());

        entry.upsert_peer(peer);
    }

    async fn get_swarm_metadata(&self, info_hash: &InfoHash) -> Option<SwarmMetadata> {
        self.get(info_hash).await.map(|entry| entry.get_swarm_metadata())
    }

    async fn get(&self, key: &InfoHash) -> Option<EntrySingle> {
        let db = self.get_torrents().await;
        db.get(key).cloned()
    }

    async fn get_paginated(&self, pagination: Option<&Pagination>) -> Vec<(InfoHash, EntrySingle)> {
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
            let stats = entry.get_swarm_metadata();
            metrics.complete += u64::from(stats.complete);
            metrics.downloaded += u64::from(stats.downloaded);
            metrics.incomplete += u64::from(stats.incomplete);
            metrics.torrents += 1;
        }

        metrics
    }

    async fn import_persistent(&self, persistent_torrents: &PersistentTorrents) {
        let mut torrents = self.get_torrents_mut().await;

        for (info_hash, completed) in persistent_torrents {
            // Skip if torrent entry already exists
            if torrents.contains_key(info_hash) {
                continue;
            }

            let entry = EntrySingle {
                swarm: PeerList::default(),
                downloaded: *completed,
            };

            torrents.insert(*info_hash, entry);
        }
    }

    async fn remove(&self, key: &InfoHash) -> Option<EntrySingle> {
        let mut db = self.get_torrents_mut().await;
        db.remove(key)
    }

    async fn remove_inactive_peers(&self, current_cutoff: DurationSinceUnixEpoch) {
        let mut db = self.get_torrents_mut().await;
        let entries = db.values_mut();

        for entry in entries {
            entry.remove_inactive_peers(current_cutoff);
        }
    }

    async fn remove_peerless_torrents(&self, policy: &TrackerPolicy) {
        let mut db = self.get_torrents_mut().await;

        db.retain(|_, e| e.meets_retaining_policy(policy));
    }
}
