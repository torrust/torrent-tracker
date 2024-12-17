use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::metrics::Metrics;

/// A repository for the tracker metrics.
#[derive(Clone)]
pub struct Repository {
    atomic_stats: Arc<AtomicMetrics>,
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
            atomic_stats: Arc::new(AtomicMetrics::default()),
        }
    }

    #[must_use]
    pub fn get_stats(&self) -> Metrics {
        Metrics {
            tcp4_connections_handled: self.atomic_stats.tcp4_connections_handled.load(Ordering::SeqCst),
            tcp4_announces_handled: self.atomic_stats.tcp4_announces_handled.load(Ordering::SeqCst),
            tcp4_scrapes_handled: self.atomic_stats.tcp4_scrapes_handled.load(Ordering::SeqCst),
            tcp6_connections_handled: self.atomic_stats.tcp6_connections_handled.load(Ordering::SeqCst),
            tcp6_announces_handled: self.atomic_stats.tcp6_announces_handled.load(Ordering::SeqCst),
            tcp6_scrapes_handled: self.atomic_stats.tcp6_scrapes_handled.load(Ordering::SeqCst),
            udp_requests_aborted: self.atomic_stats.udp_requests_aborted.load(Ordering::SeqCst),
            udp4_requests: self.atomic_stats.udp4_requests.load(Ordering::SeqCst),
            udp4_connections_handled: self.atomic_stats.udp4_connections_handled.load(Ordering::SeqCst),
            udp4_announces_handled: self.atomic_stats.udp4_announces_handled.load(Ordering::SeqCst),
            udp4_scrapes_handled: self.atomic_stats.udp4_scrapes_handled.load(Ordering::SeqCst),
            udp4_responses: self.atomic_stats.udp4_responses.load(Ordering::SeqCst),
            udp4_errors_handled: self.atomic_stats.udp4_errors_handled.load(Ordering::SeqCst),
            udp6_requests: self.atomic_stats.udp6_requests.load(Ordering::SeqCst),
            udp6_connections_handled: self.atomic_stats.udp6_connections_handled.load(Ordering::SeqCst),
            udp6_announces_handled: self.atomic_stats.udp6_announces_handled.load(Ordering::SeqCst),
            udp6_scrapes_handled: self.atomic_stats.udp6_scrapes_handled.load(Ordering::SeqCst),
            udp6_responses: self.atomic_stats.udp6_responses.load(Ordering::SeqCst),
            udp6_errors_handled: self.atomic_stats.udp6_errors_handled.load(Ordering::SeqCst),
        }
    }

    pub fn increase_tcp4_announces(&self) {
        self.atomic_stats.tcp4_announces_handled.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_tcp4_connections(&self) {
        self.atomic_stats.tcp4_connections_handled.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_tcp4_scrapes(&self) {
        self.atomic_stats.tcp4_scrapes_handled.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_tcp6_announces(&self) {
        self.atomic_stats.tcp6_announces_handled.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_tcp6_connections(&self) {
        self.atomic_stats.tcp6_connections_handled.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_tcp6_scrapes(&self) {
        self.atomic_stats.tcp6_scrapes_handled.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_udp_requests_aborted(&self) {
        self.atomic_stats.udp_requests_aborted.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_udp4_requests(&self) {
        self.atomic_stats.udp4_requests.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_udp4_connections(&self) {
        self.atomic_stats.udp4_connections_handled.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_udp4_announces(&self) {
        self.atomic_stats.udp4_announces_handled.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_udp4_scrapes(&self) {
        self.atomic_stats.udp4_scrapes_handled.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_udp4_responses(&self) {
        self.atomic_stats.udp4_responses.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_udp4_errors(&self) {
        self.atomic_stats.udp4_errors_handled.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_udp6_requests(&self) {
        self.atomic_stats.udp6_requests.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_udp6_connections(&self) {
        self.atomic_stats.udp6_connections_handled.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_udp6_announces(&self) {
        self.atomic_stats.udp6_announces_handled.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_udp6_scrapes(&self) {
        self.atomic_stats.udp6_scrapes_handled.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_udp6_responses(&self) {
        self.atomic_stats.udp6_responses.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increase_udp6_errors(&self) {
        self.atomic_stats.udp6_errors_handled.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Default)]
struct AtomicMetrics {
    pub tcp4_connections_handled: AtomicU64,
    pub tcp4_announces_handled: AtomicU64,
    pub tcp4_scrapes_handled: AtomicU64,
    pub tcp6_connections_handled: AtomicU64,
    pub tcp6_announces_handled: AtomicU64,
    pub tcp6_scrapes_handled: AtomicU64,
    pub udp_requests_aborted: AtomicU64,
    pub udp4_requests: AtomicU64,
    pub udp4_connections_handled: AtomicU64,
    pub udp4_announces_handled: AtomicU64,
    pub udp4_scrapes_handled: AtomicU64,
    pub udp4_responses: AtomicU64,
    pub udp4_errors_handled: AtomicU64,
    pub udp6_requests: AtomicU64,
    pub udp6_connections_handled: AtomicU64,
    pub udp6_announces_handled: AtomicU64,
    pub udp6_scrapes_handled: AtomicU64,
    pub udp6_responses: AtomicU64,
    pub udp6_errors_handled: AtomicU64,
}
