use futures::future::BoxFuture;
use futures::FutureExt;
#[cfg(test)]
use mockall::{automock, predicate::str};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::SendError;

use super::Event;

/// A trait to allow sending statistics events
#[cfg_attr(test, automock)]
pub trait Sender: Sync + Send {
    fn send_event(&self, event: Event) -> BoxFuture<'_, Option<Result<(), SendError<Event>>>>;
}

/// An [`statistics::EventSender`](crate::packages::statistics::event::sender::Sender) implementation.
///
/// It uses a channel sender to send the statistic events. The channel is created by a
/// [`statistics::Keeper`](crate::packages::statistics::keeper::Keeper)
#[allow(clippy::module_name_repetitions)]
pub struct ChannelSender {
    pub(crate) sender: mpsc::Sender<Event>,
}

impl Sender for ChannelSender {
    fn send_event(&self, event: Event) -> BoxFuture<'_, Option<Result<(), SendError<Event>>>> {
        async move { Some(self.sender.send(event).await) }.boxed()
    }
}
