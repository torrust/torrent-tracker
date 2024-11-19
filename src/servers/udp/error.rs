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

    #[error("connection id did not produce a normal value")]
    ConnectionIdNotNormal { not_normal_value: f64 },

    #[error("connection id produced an expired value")]
    ConnectionIdExpired { expired_value: f64, min_value: f64 },

    #[error("connection id produces a future value")]
    ConnectionIdFromFuture { future_value: f64, max_value: f64 },

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
