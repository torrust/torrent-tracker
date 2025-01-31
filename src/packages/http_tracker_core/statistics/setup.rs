//! Setup for the tracker statistics.
//!
//! The [`factory`] function builds the structs needed for handling the tracker metrics.
use crate::packages::http_tracker_core::statistics;

/// It builds the structs needed for handling the tracker metrics.
///
/// It returns:
///
/// - An statistics event [`Sender`](crate::packages::http_tracker_core::statistics::event::sender::Sender) that allows you to send events related to statistics.
/// - An statistics [`Repository`](crate::packages::http_tracker_core::statistics::repository::Repository) which is an in-memory repository for the tracker metrics.
///
/// When the input argument `tracker_usage_statistics`is false the setup does not run the event listeners, consequently the statistics
/// events are sent are received but not dispatched to the handler.
#[must_use]
pub fn factory(
    tracker_usage_statistics: bool,
) -> (
    Option<Box<dyn statistics::event::sender::Sender>>,
    statistics::repository::Repository,
) {
    let mut stats_event_sender = None;

    let mut stats_tracker = statistics::keeper::Keeper::new();

    if tracker_usage_statistics {
        stats_event_sender = Some(stats_tracker.run_event_listener());
    }

    (stats_event_sender, stats_tracker.repository)
}

#[cfg(test)]
mod test {
    use super::factory;

    #[tokio::test]
    async fn should_not_send_any_event_when_statistics_are_disabled() {
        let tracker_usage_statistics = false;

        let (stats_event_sender, _stats_repository) = factory(tracker_usage_statistics);

        assert!(stats_event_sender.is_none());
    }

    #[tokio::test]
    async fn should_send_events_when_statistics_are_enabled() {
        let tracker_usage_statistics = true;

        let (stats_event_sender, _stats_repository) = factory(tracker_usage_statistics);

        assert!(stats_event_sender.is_some());
    }
}
