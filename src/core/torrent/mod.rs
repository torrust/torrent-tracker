//! Structs to store the swarm data.
//!
//! There are to main data structures:
//!
//! - A torrent [`Entry`](torrust_tracker_torrent_repository::entry::Entry): it contains all the information stored by the tracker for one torrent.
//! - The [`SwarmMetadata`](torrust_tracker_primitives::swarm_metadata::SwarmMetadata): it contains aggregate information that can me derived from the torrent entries.
//!
//! A "swarm" is a network of peers that are trying to download the same torrent.
//!
//! The torrent entry contains the "swarm" data, which is basically the list of peers in the swarm.
//! That's the most valuable information the peer want to get from the tracker, because it allows them to
//! start downloading torrent from those peers.
//!
//! The "swarm metadata" contains aggregate data derived from the torrent entries. There two types of data:
//!
//! - For **active peers**: metrics related to the current active peers in the swarm.
//! - **Historical data**: since the tracker started running.
//!
//! The tracker collects metrics for:
//!
//! - The number of peers that have completed downloading the torrent since the tracker started collecting metrics.
//! - The number of peers that have completed downloading the torrent and are still active, that means they are actively participating in the network,
//!   by announcing themselves periodically to the tracker. Since they have completed downloading they have a full copy of the torrent data. Peers with a
//!   full copy of the data are called "seeders".
//! - The number of peers that have NOT completed downloading the torrent and are still active, that means they are actively participating in the network.
//!   Peer that don not have a full copy of the torrent data are called "leechers".
//!
pub mod repository;

use torrust_tracker_torrent_repository::TorrentsSkipMapMutexStd;

pub type Torrents = TorrentsSkipMapMutexStd; // Currently Used
