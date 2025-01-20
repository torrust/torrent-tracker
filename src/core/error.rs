//! Error returned by the core `Tracker`.
//!
//! Error | Context | Description
//! ---|---|---
//! `PeerKeyNotValid` | Authentication | The supplied key is not valid. It may not be registered or expired.
//! `PeerNotAuthenticated` | Authentication | The peer did not provide the authentication key.
//! `TorrentNotWhitelisted` | Authorization | The action cannot be perform on a not-whitelisted torrent (it only applies for trackers running in `listed` or `private_listed` modes).
//!
use std::panic::Location;

use bittorrent_http_protocol::v1::responses;
use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_located_error::LocatedError;

use super::{auth::key::ParseKeyError, databases};

/// Authentication or authorization error returned by the core `Tracker`
#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    // Authentication errors
    #[error("The supplied key: {key:?}, is not valid: {source}")]
    PeerKeyNotValid {
        key: super::auth::Key,
        source: LocatedError<'static, dyn std::error::Error + Send + Sync>,
    },

    #[error("The peer is not authenticated, {location}")]
    PeerNotAuthenticated { location: &'static Location<'static> },

    // Authorization errors
    #[error("The torrent: {info_hash}, is not whitelisted, {location}")]
    TorrentNotWhitelisted {
        info_hash: InfoHash,
        location: &'static Location<'static>,
    },
}

/// Errors related to peers keys.
#[allow(clippy::module_name_repetitions)]
#[derive(thiserror::Error, Debug, Clone)]
pub enum PeerKeyError {
    #[error("Invalid peer key duration: {seconds_valid:?}, is not valid")]
    DurationOverflow { seconds_valid: u64 },

    #[error("Invalid key: {key}")]
    InvalidKey {
        key: String,
        source: LocatedError<'static, ParseKeyError>,
    },

    #[error("Can't persist key: {source}")]
    DatabaseError {
        source: LocatedError<'static, databases::error::Error>,
    },
}

impl From<Error> for responses::error::Error {
    fn from(err: Error) -> Self {
        responses::error::Error {
            failure_reason: format!("Tracker error: {err}"),
        }
    }
}
