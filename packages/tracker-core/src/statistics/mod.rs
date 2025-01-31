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
//! > Notice: that UDP tracker have an specific `connection` request. For the
//! > `HTTP` metrics the counter counts one connection for each `announce` or
//! > `scrape` request.
//!
//! The data is collected by using an `event-sender -> event listener` model.
//!
//! The tracker uses a [`Sender`](crate::core::statistics::event::sender::Sender)
//! instance to send an event.
//!
//! The [`statistics::keeper::Keeper`](crate::core::statistics::keeper::Keeper) listens to new
//! events and uses the [`statistics::repository::Repository`](crate::core::statistics::repository::Repository) to
//! upgrade and store metrics.
//!
//! See the [`statistics::event::Event`](crate::core::statistics::event::Event) enum to check
//! which events are available.
pub mod event;
pub mod keeper;
pub mod metrics;
pub mod repository;
pub mod setup;
