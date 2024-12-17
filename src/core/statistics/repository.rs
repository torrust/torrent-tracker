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

    pub async fn increase_udp_requests_aborted(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp_requests_aborted += 1;
        drop(stats_lock);
    }

    pub async fn increase_udp4_requests(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp4_requests += 1;
        drop(stats_lock);
    }

    pub async fn increase_udp4_connections(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp4_connections_handled += 1;
        drop(stats_lock);
    }

    pub async fn increase_udp4_announces(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp4_announces_handled += 1;
        drop(stats_lock);
    }

    pub async fn increase_udp4_scrapes(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp4_scrapes_handled += 1;
        drop(stats_lock);
    }

    pub async fn increase_udp4_responses(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp4_responses += 1;
        drop(stats_lock);
    }

    pub async fn increase_udp4_errors(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp4_errors_handled += 1;
        drop(stats_lock);
    }

    pub async fn increase_udp6_requests(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp6_requests += 1;
        drop(stats_lock);
    }

    pub async fn increase_udp6_connections(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp6_connections_handled += 1;
        drop(stats_lock);
    }

    pub async fn increase_udp6_announces(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp6_announces_handled += 1;
        drop(stats_lock);
    }

    pub async fn increase_udp6_scrapes(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp6_scrapes_handled += 1;
        drop(stats_lock);
    }

    pub async fn increase_udp6_responses(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp6_responses += 1;
        drop(stats_lock);
    }

    pub async fn increase_udp6_errors(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp6_errors_handled += 1;
        drop(stats_lock);
    }
}
