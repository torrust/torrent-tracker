use tokio::sync::mpsc;

use super::handler::handle_event;
use super::Event;
use crate::statistics::repository::Repository;

pub async fn dispatch_events(mut receiver: mpsc::Receiver<Event>, stats_repository: Repository) {
    while let Some(event) = receiver.recv().await {
        handle_event(event, &stats_repository).await;
    }
}
