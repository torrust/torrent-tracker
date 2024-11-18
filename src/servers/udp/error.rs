//! Error types for the UDP server.
use std::panic::Location;

use aquatic_udp_protocol::ConnectionId;
use derive_more::derive::Display;
use thiserror::Error;
use torrust_tracker_located_error::LocatedError;

#[derive(Display, Debug)]
#[display(":?")]
pub struct ConnectionCookie(pub ConnectionId);

/// Error returned by the UDP server.
#[derive(Error, Debug)]
pub enum Error {
    #[error("the issue time should be a normal floating point number")]
    InvalidCookieIssueTime { invalid_value: f64 },

    #[error("connection id was decoded, but could not be understood")]
    InvalidConnectionId { bad_id: ConnectionCookie },

    #[error("connection id was decoded, but was expired (too old)")]
    ConnectionIdExpired { bad_age: f64, min_age: f64 },

    #[error("connection id was decoded, but was invalid (from future)")]
    ConnectionIdFromFuture { future_age: f64, max_age: f64 },

    /// Error returned when the domain tracker returns an error.
    #[error("tracker server error: {source}")]
    TrackerError {
        source: LocatedError<'static, dyn std::error::Error + Send + Sync>,
    },

    /// Error returned from a third-party library (`aquatic_udp_protocol`).
    #[error("internal server error: {message}, {location}")]
    InternalServer {
        location: &'static Location<'static>,
        message: String,
    },

    /// Error returned when the request is invalid.
    #[error("bad request: {source}")]
    BadRequest {
        source: LocatedError<'static, dyn std::error::Error + Send + Sync>,
    },

    /// Error returned when tracker requires authentication.
    #[error("domain tracker requires authentication but is not supported in current UDP implementation. Location: {location}")]
    TrackerAuthenticationRequired { location: &'static Location<'static> },
}
