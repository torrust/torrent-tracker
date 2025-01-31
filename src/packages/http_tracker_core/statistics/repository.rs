use std::sync::Arc;

use tokio::sync::{RwLock, RwLockReadGuard};

use super::metrics::Metrics;

/// A repository for the tracker metrics.
#[derive(Clone)]
pub struct Repository {
    pub stats: Arc<RwLock<Metrics>>,
}

impl Default for Repository {
    fn default() -> Self {
        Self::new()
    }
}

impl Repository {
    #[must_use]
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(Metrics::default())),
        }
    }

    pub async fn get_stats(&self) -> RwLockReadGuard<'_, Metrics> {
        self.stats.read().await
    }

    pub async fn increase_tcp4_announces(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.tcp4_announces_handled += 1;
        drop(stats_lock);
    }

    pub async fn increase_tcp4_connections(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.tcp4_connections_handled += 1;
        drop(stats_lock);
    }

    pub async fn increase_tcp4_scrapes(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.tcp4_scrapes_handled += 1;
        drop(stats_lock);
    }

    pub async fn increase_tcp6_announces(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.tcp6_announces_handled += 1;
        drop(stats_lock);
    }

    pub async fn increase_tcp6_connections(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.tcp6_connections_handled += 1;
        drop(stats_lock);
    }

    pub async fn increase_tcp6_scrapes(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.tcp6_scrapes_handled += 1;
        drop(stats_lock);
    }
}
