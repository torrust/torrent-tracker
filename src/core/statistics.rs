//! Structs to collect and keep tracker metrics.
//!
//! The tracker collects metrics such as:
//!
//! - Number of connections handled
//! - Number of `announce` requests handled
//! - Number of `scrape` request handled
//!
//! These metrics are collected for each connection type: UDP and HTTP and
//! also for each IP version used by the peers: IPv4 and IPv6.
//!
//! > Notice: that UDP tracker have an specific `connection` request. For the HTTP metrics the counter counts one connection for each `announce` or `scrape` request.
//!
//! The data is collected by using an `event-sender -> event listener` model.
//!
//! The tracker uses an [`statistics::EventSender`](crate::core::statistics::EventSender) instance to send an event.
//! The [`statistics::Keeper`](crate::core::statistics::Keeper) listens to new events and uses the [`statistics::Repo`](crate::core::statistics::Repo) to upgrade and store metrics.
//!
//! See the [`statistics::Event`](crate::core::statistics::Event) enum to check which events are available.
use std::sync::Arc;

use futures::future::BoxFuture;
use futures::FutureExt;
#[cfg(test)]
use mockall::{automock, predicate::str};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::{mpsc, RwLock, RwLockReadGuard};

const CHANNEL_BUFFER_SIZE: usize = 65_535;

/// An statistics event. It is used to collect tracker metrics.
///
/// - `Tcp` prefix means the event was triggered by the HTTP tracker
/// - `Udp` prefix means the event was triggered by the UDP tracker
/// - `4` or `6` prefixes means the IP version used by the peer
/// - Finally the event suffix is the type of request: `announce`, `scrape` or `connection`
///
/// > NOTE: HTTP trackers do not use `connection` requests.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    // code-review: consider one single event for request type with data: Event::Announce { scheme: HTTPorUDP, ip_version: V4orV6 }
    // Attributes are enums too.
    Tcp4Announce,
    Tcp4Scrape,
    Tcp6Announce,
    Tcp6Scrape,
    Udp4RequestAborted,
    Udp4Request,
    Udp4Connect,
    Udp4Announce,
    Udp4Scrape,
    Udp4Response,
    Udp4Error,
    Udp6Request,
    Udp6Connect,
    Udp6Announce,
    Udp6Scrape,
    Udp6Response,
    Udp6Error,
}

/// Metrics collected by the tracker.
///
/// - Number of connections handled
/// - Number of `announce` requests handled
/// - Number of `scrape` request handled
///
/// These metrics are collected for each connection type: UDP and HTTP
/// and also for each IP version used by the peers: IPv4 and IPv6.
#[derive(Debug, PartialEq, Default)]
pub struct Metrics {
    /// Total number of TCP (HTTP tracker) connections from IPv4 peers.
    /// Since the HTTP tracker spec does not require a handshake, this metric
    /// increases for every HTTP request.
    pub tcp4_connections_handled: u64,
    /// Total number of TCP (HTTP tracker) `announce` requests from IPv4 peers.
    pub tcp4_announces_handled: u64,
    /// Total number of TCP (HTTP tracker) `scrape` requests from IPv4 peers.
    pub tcp4_scrapes_handled: u64,

    /// Total number of TCP (HTTP tracker) connections from IPv6 peers.
    pub tcp6_connections_handled: u64,
    /// Total number of TCP (HTTP tracker) `announce` requests from IPv6 peers.
    pub tcp6_announces_handled: u64,
    /// Total number of TCP (HTTP tracker) `scrape` requests from IPv6 peers.
    pub tcp6_scrapes_handled: u64,

    /// Total number of UDP (UDP tracker) requests aborted.
    pub udp_requests_aborted: u64,

    /// Total number of UDP (UDP tracker) requests from IPv4 peers.
    pub udp4_requests: u64,
    /// Total number of UDP (UDP tracker) connections from IPv4 peers.
    pub udp4_connections_handled: u64,
    /// Total number of UDP (UDP tracker) `announce` requests from IPv4 peers.
    pub udp4_announces_handled: u64,
    /// Total number of UDP (UDP tracker) `scrape` requests from IPv4 peers.
    pub udp4_scrapes_handled: u64,
    /// Total number of UDP (UDP tracker) responses from IPv4 peers.
    pub udp4_responses: u64,
    /// Total number of UDP (UDP tracker) `error` requests from IPv4 peers.
    pub udp4_errors_handled: u64,

    /// Total number of UDP (UDP tracker) requests from IPv6 peers.
    pub udp6_requests: u64,
    /// Total number of UDP (UDP tracker) `connection` requests from IPv6 peers.
    pub udp6_connections_handled: u64,
    /// Total number of UDP (UDP tracker) `announce` requests from IPv6 peers.
    pub udp6_announces_handled: u64,
    /// Total number of UDP (UDP tracker) `scrape` requests from IPv6 peers.
    pub udp6_scrapes_handled: u64,
    /// Total number of UDP (UDP tracker) responses from IPv6 peers.
    pub udp6_responses: u64,
    /// Total number of UDP (UDP tracker) `error` requests from IPv6 peers.
    pub udp6_errors_handled: u64,
}

/// The service responsible for keeping tracker metrics (listening to statistics events and handle them).
///
/// It actively listen to new statistics events. When it receives a new event
/// it accordingly increases the counters.
pub struct Keeper {
    pub repository: Repo,
}

impl Default for Keeper {
    fn default() -> Self {
        Self::new()
    }
}

impl Keeper {
    #[must_use]
    pub fn new() -> Self {
        Self { repository: Repo::new() }
    }

    #[must_use]
    pub fn new_active_instance() -> (Box<dyn EventSender>, Repo) {
        let mut stats_tracker = Self::new();

        let stats_event_sender = stats_tracker.run_event_listener();

        (stats_event_sender, stats_tracker.repository)
    }

    pub fn run_event_listener(&mut self) -> Box<dyn EventSender> {
        let (sender, receiver) = mpsc::channel::<Event>(CHANNEL_BUFFER_SIZE);

        let stats_repository = self.repository.clone();

        tokio::spawn(async move { event_listener(receiver, stats_repository).await });

        Box::new(Sender { sender })
    }
}

async fn event_listener(mut receiver: mpsc::Receiver<Event>, stats_repository: Repo) {
    while let Some(event) = receiver.recv().await {
        event_handler(event, &stats_repository).await;
    }
}

async fn event_handler(event: Event, stats_repository: &Repo) {
    match event {
        // TCP4
        Event::Tcp4Announce => {
            stats_repository.increase_tcp4_announces().await;
            stats_repository.increase_tcp4_connections().await;
        }
        Event::Tcp4Scrape => {
            stats_repository.increase_tcp4_scrapes().await;
            stats_repository.increase_tcp4_connections().await;
        }

        // TCP6
        Event::Tcp6Announce => {
            stats_repository.increase_tcp6_announces().await;
            stats_repository.increase_tcp6_connections().await;
        }
        Event::Tcp6Scrape => {
            stats_repository.increase_tcp6_scrapes().await;
            stats_repository.increase_tcp6_connections().await;
        }

        // UDP
        Event::Udp4RequestAborted => {
            stats_repository.increase_udp_requests_aborted().await;
        }

        // UDP4
        Event::Udp4Request => {
            stats_repository.increase_udp4_requests().await;
        }
        Event::Udp4Connect => {
            stats_repository.increase_udp4_connections().await;
        }
        Event::Udp4Announce => {
            stats_repository.increase_udp4_announces().await;
        }
        Event::Udp4Scrape => {
            stats_repository.increase_udp4_scrapes().await;
        }
        Event::Udp4Response => {
            stats_repository.increase_udp4_responses().await;
        }
        Event::Udp4Error => {
            stats_repository.increase_udp4_errors().await;
        }

        // UDP6
        Event::Udp6Request => {
            stats_repository.increase_udp6_requests().await;
        }
        Event::Udp6Connect => {
            stats_repository.increase_udp6_connections().await;
        }
        Event::Udp6Announce => {
            stats_repository.increase_udp6_announces().await;
        }
        Event::Udp6Scrape => {
            stats_repository.increase_udp6_scrapes().await;
        }
        Event::Udp6Response => {
            stats_repository.increase_udp6_responses().await;
        }
        Event::Udp6Error => {
            stats_repository.increase_udp6_errors().await;
        }
    }

    tracing::debug!("stats: {:?}", stats_repository.get_stats().await);
}

/// A trait to allow sending statistics events
#[cfg_attr(test, automock)]
pub trait EventSender: Sync + Send {
    fn send_event(&self, event: Event) -> BoxFuture<'_, Option<Result<(), SendError<Event>>>>;
}

/// An [`statistics::EventSender`](crate::core::statistics::EventSender) implementation.
///
/// It uses a channel sender to send the statistic events. The channel is created by a
/// [`statistics::Keeper`](crate::core::statistics::Keeper)
pub struct Sender {
    sender: mpsc::Sender<Event>,
}

impl EventSender for Sender {
    fn send_event(&self, event: Event) -> BoxFuture<'_, Option<Result<(), SendError<Event>>>> {
        async move { Some(self.sender.send(event).await) }.boxed()
    }
}

/// A repository for the tracker metrics.
#[derive(Clone)]
pub struct Repo {
    pub stats: Arc<RwLock<Metrics>>,
}

impl Default for Repo {
    fn default() -> Self {
        Self::new()
    }
}

impl Repo {
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

#[cfg(test)]
mod tests {

    mod stats_tracker {
        use crate::core::statistics::{Event, Keeper, Metrics};

        #[tokio::test]
        async fn should_contain_the_tracker_statistics() {
            let stats_tracker = Keeper::new();

            let stats = stats_tracker.repository.get_stats().await;

            assert_eq!(stats.tcp4_announces_handled, Metrics::default().tcp4_announces_handled);
        }

        #[tokio::test]
        async fn should_create_an_event_sender_to_send_statistical_events() {
            let mut stats_tracker = Keeper::new();

            let event_sender = stats_tracker.run_event_listener();

            let result = event_sender.send_event(Event::Udp4Connect).await;

            assert!(result.is_some());
        }
    }

    mod event_handler {
        use crate::core::statistics::{event_handler, Event, Repo};

        #[tokio::test]
        async fn should_increase_the_tcp4_announces_counter_when_it_receives_a_tcp4_announce_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Tcp4Announce, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.tcp4_announces_handled, 1);
        }

        #[tokio::test]
        async fn should_increase_the_tcp4_connections_counter_when_it_receives_a_tcp4_announce_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Tcp4Announce, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.tcp4_connections_handled, 1);
        }

        #[tokio::test]
        async fn should_increase_the_tcp4_scrapes_counter_when_it_receives_a_tcp4_scrape_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Tcp4Scrape, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.tcp4_scrapes_handled, 1);
        }

        #[tokio::test]
        async fn should_increase_the_tcp4_connections_counter_when_it_receives_a_tcp4_scrape_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Tcp4Scrape, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.tcp4_connections_handled, 1);
        }

        #[tokio::test]
        async fn should_increase_the_tcp6_announces_counter_when_it_receives_a_tcp6_announce_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Tcp6Announce, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.tcp6_announces_handled, 1);
        }

        #[tokio::test]
        async fn should_increase_the_tcp6_connections_counter_when_it_receives_a_tcp6_announce_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Tcp6Announce, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.tcp6_connections_handled, 1);
        }

        #[tokio::test]
        async fn should_increase_the_tcp6_scrapes_counter_when_it_receives_a_tcp6_scrape_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Tcp6Scrape, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.tcp6_scrapes_handled, 1);
        }

        #[tokio::test]
        async fn should_increase_the_tcp6_connections_counter_when_it_receives_a_tcp6_scrape_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Tcp6Scrape, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.tcp6_connections_handled, 1);
        }

        #[tokio::test]
        async fn should_increase_the_udp4_connections_counter_when_it_receives_a_udp4_connect_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Udp4Connect, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.udp4_connections_handled, 1);
        }

        #[tokio::test]
        async fn should_increase_the_udp4_announces_counter_when_it_receives_a_udp4_announce_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Udp4Announce, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.udp4_announces_handled, 1);
        }

        #[tokio::test]
        async fn should_increase_the_udp4_scrapes_counter_when_it_receives_a_udp4_scrape_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Udp4Scrape, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.udp4_scrapes_handled, 1);
        }

        #[tokio::test]
        async fn should_increase_the_udp6_connections_counter_when_it_receives_a_udp6_connect_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Udp6Connect, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.udp6_connections_handled, 1);
        }

        #[tokio::test]
        async fn should_increase_the_udp6_announces_counter_when_it_receives_a_udp6_announce_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Udp6Announce, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.udp6_announces_handled, 1);
        }

        #[tokio::test]
        async fn should_increase_the_udp6_scrapes_counter_when_it_receives_a_udp6_scrape_event() {
            let stats_repository = Repo::new();

            event_handler(Event::Udp6Scrape, &stats_repository).await;

            let stats = stats_repository.get_stats().await;

            assert_eq!(stats.udp6_scrapes_handled, 1);
        }
    }
}
