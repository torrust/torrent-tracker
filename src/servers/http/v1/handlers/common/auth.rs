//! HTTP server authentication error and conversion to
//! [`responses::error::Error`]
//! response.
use std::panic::Location;

use bittorrent_http_protocol::v1::responses;
use thiserror::Error;

use crate::core::auth;

/// Authentication error.
///
/// When the tracker is private, the authentication key is required in the URL
/// path. These are the possible errors that can occur when extracting the key
/// from the URL path.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Missing authentication key param for private tracker. Error in {location}")]
    MissingAuthKey { location: &'static Location<'static> },
    #[error("Invalid format for authentication key param. Error in {location}")]
    InvalidKeyFormat { location: &'static Location<'static> },
    #[error("Cannot extract authentication key param from URL path. Error in {location}")]
    CannotExtractKeyParam { location: &'static Location<'static> },
}

impl From<Error> for responses::error::Error {
    fn from(err: Error) -> Self {
        responses::error::Error {
            failure_reason: format!("Authentication error: {err}"),
        }
    }
}

impl From<auth::Error> for responses::error::Error {
    fn from(err: auth::Error) -> Self {
        responses::error::Error {
            failure_reason: format!("Authentication error: {err}"),
        }
    }
}
