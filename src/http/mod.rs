//! Tracker HTTP/HTTPS Protocol:
//!
//! Original specification in BEP 3 (section "Trackers"):
//!
//! <https://www.bittorrent.org/beps/bep_0003.html>
//!
//! Other resources:
//!
//! - <https://wiki.theory.org/BitTorrentSpecification#Tracker_HTTP.2FHTTPS_Protocol>
//! - <https://wiki.theory.org/BitTorrent_Tracker_Protocol>
//!

use serde::{Deserialize, Serialize};

pub mod axum_implementation;
pub mod percent_encoding;
pub mod server;
pub mod warp_implementation;

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub enum Version {
    Warp,
    Axum,
}
