//! Primitive types for [Torrust Tracker](https://docs.rs/torrust-tracker).
//!
//! This module contains the basic data structures for the [Torrust Tracker](https://docs.rs/torrust-tracker),
//! which is a `BitTorrent` tracker server. These structures are used not only
//! by the tracker server crate, but also by other crates in the Torrust
//! ecosystem.
pub mod core;
pub mod pagination;
pub mod peer;
pub mod swarm_metadata;
pub mod torrent_metrics;

use std::collections::BTreeMap;
use std::time::Duration;

use bittorrent_primitives::info_hash::InfoHash;

/// Duration since the Unix Epoch.
pub type DurationSinceUnixEpoch = Duration;

pub type PersistentTorrents = BTreeMap<InfoHash, u32>;
