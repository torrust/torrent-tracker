use std::sync::Arc;
use std::time::Duration;

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

    pub async fn increase_udp_requests_aborted(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp_requests_aborted += 1;
        drop(stats_lock);
    }

    pub async fn increase_udp_requests_banned(&self) {
        let mut stats_lock = self.stats.write().await;
        stats_lock.udp_requests_banned += 1;
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

    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    pub async fn recalculate_udp_avg_connect_processing_time_ns(&self, req_processing_time: Duration) {
        let mut stats_lock = self.stats.write().await;

        let req_processing_time = req_processing_time.as_nanos() as f64;
        let udp_connections_handled = (stats_lock.udp4_connections_handled + stats_lock.udp6_connections_handled) as f64;

        let previous_avg = stats_lock.udp_avg_connect_processing_time_ns;

        // Moving average: https://en.wikipedia.org/wiki/Moving_average
        let new_avg = previous_avg as f64 + (req_processing_time - previous_avg as f64) / udp_connections_handled;

        stats_lock.udp_avg_connect_processing_time_ns = new_avg.ceil() as u64;

        drop(stats_lock);
    }

    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    pub async fn recalculate_udp_avg_announce_processing_time_ns(&self, req_processing_time: Duration) {
        let mut stats_lock = self.stats.write().await;

        let req_processing_time = req_processing_time.as_nanos() as f64;

        let udp_announces_handled = (stats_lock.udp4_announces_handled + stats_lock.udp6_announces_handled) as f64;

        let previous_avg = stats_lock.udp_avg_announce_processing_time_ns;

        // Moving average: https://en.wikipedia.org/wiki/Moving_average
        let new_avg = previous_avg as f64 + (req_processing_time - previous_avg as f64) / udp_announces_handled;

        stats_lock.udp_avg_announce_processing_time_ns = new_avg.ceil() as u64;

        drop(stats_lock);
    }

    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    pub async fn recalculate_udp_avg_scrape_processing_time_ns(&self, req_processing_time: Duration) {
        let mut stats_lock = self.stats.write().await;

        let req_processing_time = req_processing_time.as_nanos() as f64;
        let udp_scrapes_handled = (stats_lock.udp4_scrapes_handled + stats_lock.udp6_scrapes_handled) as f64;

        let previous_avg = stats_lock.udp_avg_scrape_processing_time_ns;

        // Moving average: https://en.wikipedia.org/wiki/Moving_average
        let new_avg = previous_avg as f64 + (req_processing_time - previous_avg as f64) / udp_scrapes_handled;

        stats_lock.udp_avg_scrape_processing_time_ns = new_avg.ceil() as u64;

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
