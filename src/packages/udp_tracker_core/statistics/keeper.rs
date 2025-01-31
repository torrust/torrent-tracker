use tokio::sync::mpsc;

use super::event::listener::dispatch_events;
use super::event::sender::{ChannelSender, Sender};
use super::event::Event;
use super::repository::Repository;

const CHANNEL_BUFFER_SIZE: usize = 65_535;

/// The service responsible for keeping tracker metrics (listening to statistics events and handle them).
///
/// It actively listen to new statistics events. When it receives a new event
/// it accordingly increases the counters.
pub struct Keeper {
    pub repository: Repository,
}

impl Default for Keeper {
    fn default() -> Self {
        Self::new()
    }
}

impl Keeper {
    #[must_use]
    pub fn new() -> Self {
        Self {
            repository: Repository::new(),
        }
    }

    #[must_use]
    pub fn new_active_instance() -> (Box<dyn Sender>, Repository) {
        let mut stats_tracker = Self::new();

        let stats_event_sender = stats_tracker.run_event_listener();

        (stats_event_sender, stats_tracker.repository)
    }

    pub fn run_event_listener(&mut self) -> Box<dyn Sender> {
        let (sender, receiver) = mpsc::channel::<Event>(CHANNEL_BUFFER_SIZE);

        let stats_repository = self.repository.clone();

        tokio::spawn(async move { dispatch_events(receiver, stats_repository).await });

        Box::new(ChannelSender { sender })
    }
}

#[cfg(test)]
mod tests {
    use crate::packages::udp_tracker_core::statistics::event::Event;
    use crate::packages::udp_tracker_core::statistics::keeper::Keeper;
    use crate::packages::udp_tracker_core::statistics::metrics::Metrics;

    #[tokio::test]
    async fn should_contain_the_tracker_statistics() {
        let stats_tracker = Keeper::new();

        let stats = stats_tracker.repository.get_stats().await;

        assert_eq!(stats.udp4_announces_handled, Metrics::default().udp4_announces_handled);
    }

    #[tokio::test]
    async fn should_create_an_event_sender_to_send_statistical_events() {
        let mut stats_tracker = Keeper::new();

        let event_sender = stats_tracker.run_event_listener();

        let result = event_sender.send_event(Event::Udp4Connect).await;

        assert!(result.is_some());
    }
}
