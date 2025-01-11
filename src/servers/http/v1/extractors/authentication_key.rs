//! Axum [`extractor`](axum::extract) to extract the authentication [`Key`]
//! from the URL path.
//!
//! It's only used when the tracker is running in private mode.
//!
//! Given the following URL route with a path param: `/announce/:key`,
//! it extracts the `key` param from the URL path.
//!
//! It's a wrapper for Axum `Path` extractor in order to return custom
//! authentication errors.
//!
//! It returns a bencoded [`Error`](bittorrent_http_protocol::v1::responses::error)
//! response (`500`) if the `key` parameter are missing or invalid.
//!
//! **Sample authentication error responses**
//!
//! When the key param is **missing**:
//!
//! ```text
//! d14:failure reason131:Authentication error: Missing authentication key param for private tracker. Error in src/servers/http/v1/handlers/announce.rs:79:31e
//! ```
//!
//! When the key param has an **invalid format**:
//!
//! ```text
//! d14:failure reason134:Authentication error: Invalid format for authentication key param. Error in src/servers/http/v1/extractors/authentication_key.rs:73:23e
//! ```
//!
//! When the key is **not found** in the database:
//!
//! ```text
//! d14:failure reason101:Authentication error: Failed to read key: YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ, src/tracker/mod.rs:848:27e
//! ```
//!
//! When the key is found in the database but it's **expired**:
//!
//! ```text
//! d14:failure reason64:Authentication error: Key has expired, src/tracker/auth.rs:88:23e
//! ```
//!
//! > **NOTICE**: the returned HTTP status code is always `200` for authentication errors.
//! > Neither [The `BitTorrent` Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)
//! > nor [The Private Torrents](https://www.bittorrent.org/beps/bep_0027.html)
//! > specifications specify any HTTP status code for authentication errors.
use std::future::Future;
use std::panic::Location;

use axum::extract::rejection::PathRejection;
use axum::extract::{FromRequestParts, Path};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use bittorrent_http_protocol::v1::responses;
use hyper::StatusCode;
use serde::Deserialize;

use crate::core::auth::Key;
use crate::servers::http::v1::handlers::common::auth;

/// Extractor for the [`Key`] struct.
pub struct Extract(pub Key);

#[derive(Deserialize)]
pub struct KeyParam(String);

impl KeyParam {
    #[must_use]
    pub fn value(&self) -> String {
        self.0.clone()
    }
}

impl<S> FromRequestParts<S> for Extract
where
    S: Send + Sync + 'static,
{
    type Rejection = Response;

    #[allow(clippy::manual_async_fn)]
    fn from_request_parts(parts: &mut Parts, state: &S) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            // Extract `key` from URL path with Axum `Path` extractor
            let maybe_path_with_key = Path::<KeyParam>::from_request_parts(parts, state).await;

            match extract_key(maybe_path_with_key) {
                Ok(key) => Ok(Extract(key)),
                Err(error) => Err((StatusCode::OK, error.write()).into_response()),
            }
        }
    }
}

fn extract_key(path_extractor_result: Result<Path<KeyParam>, PathRejection>) -> Result<Key, responses::error::Error> {
    match path_extractor_result {
        Ok(key_param) => match parse_key(&key_param.0.value()) {
            Ok(key) => Ok(key),
            Err(error) => Err(error),
        },
        Err(path_rejection) => Err(custom_error(&path_rejection)),
    }
}

fn parse_key(key: &str) -> Result<Key, responses::error::Error> {
    let key = key.parse::<Key>();

    match key {
        Ok(key) => Ok(key),
        Err(_parse_key_error) => Err(responses::error::Error::from(auth::Error::InvalidKeyFormat {
            location: Location::caller(),
        })),
    }
}

fn custom_error(rejection: &PathRejection) -> responses::error::Error {
    match rejection {
        axum::extract::rejection::PathRejection::FailedToDeserializePathParams(_) => {
            responses::error::Error::from(auth::Error::InvalidKeyFormat {
                location: Location::caller(),
            })
        }
        axum::extract::rejection::PathRejection::MissingPathParams(_) => {
            responses::error::Error::from(auth::Error::MissingAuthKey {
                location: Location::caller(),
            })
        }
        _ => responses::error::Error::from(auth::Error::CannotExtractKeyParam {
            location: Location::caller(),
        }),
    }
}

#[cfg(test)]
mod tests {

    use bittorrent_http_protocol::v1::responses::error::Error;

    use super::parse_key;

    fn assert_error_response(error: &Error, error_message: &str) {
        assert!(
            error.failure_reason.contains(error_message),
            "Error response does not contain message: '{error_message}'. Error: {error:?}"
        );
    }

    #[test]
    fn it_should_return_an_authentication_error_if_the_key_cannot_be_parsed() {
        let invalid_key = "invalid_key";

        let response = parse_key(invalid_key).unwrap_err();

        assert_error_response(&response, "Authentication error: Invalid format for authentication key param");
    }
}
