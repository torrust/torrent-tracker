//! Axum [`extractor`](axum::extract) for the [`Announce`]
//! request.
//!
//! It parses the query parameters returning an [`Announce`]
//! request.
//!
//! Refer to [`Announce`](crate::servers::http::v1::requests::announce) for more
//! information about the returned structure.
//!
//! It returns a bencoded [`Error`](crate::servers::http::v1::responses::error)
//! response (`500`) if the query parameters are missing or invalid.
//!
//! **Sample announce request**
//!
//! <http://0.0.0.0:7070/announce?info_hash=%81%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00&peer_addr=2.137.87.41&downloaded=0&uploaded=0&peer_id=-qB00000000000000001&port=17548&left=0&event=completed&compact=0>
//!
//! **Sample error response**
//!
//! Missing query params for `announce` request: <http://0.0.0.0:7070/announce>
//!
//! ```text
//! d14:failure reason149:Bad request. Cannot parse query params for announce request: missing query params for announce request in src/servers/http/v1/extractors/announce_request.rs:54:23e
//! ```
//!
//! Invalid query param (`info_hash`): <http://0.0.0.0:7070/announce?info_hash=invalid&peer_addr=2.137.87.41&downloaded=0&uploaded=0&peer_id=-qB00000000000000001&port=17548&left=0&event=completed&compact=0>
//!
//! ```text
//! d14:failure reason240:Bad request. Cannot parse query params for announce request: invalid param value invalid for info_hash in not enough bytes for infohash: got 7 bytes, expected 20 src/shared/bit_torrent/info_hash.rs:240:27, src/servers/http/v1/requests/announce.rs:182:42e
//! ```
use std::panic::Location;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use futures::future::BoxFuture;
use futures::FutureExt;

use crate::servers::http::v1::query::Query;
use crate::servers::http::v1::requests::announce::{Announce, ParseAnnounceQueryError};
use crate::servers::http::v1::responses;

/// Extractor for the [`Announce`]
/// request.
pub struct ExtractRequest(pub Announce);

impl<S> FromRequestParts<S> for ExtractRequest
where
    S: Send + Sync,
{
    type Rejection = Response;

    #[must_use]
    fn from_request_parts<'life0, 'life1, 'async_trait>(
        parts: &'life0 mut Parts,
        _state: &'life1 S,
    ) -> BoxFuture<'async_trait, Result<Self, Self::Rejection>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        async {
            match extract_announce_from(parts.uri.query()) {
                Ok(announce_request) => Ok(ExtractRequest(announce_request)),
                Err(error) => Err(error.into_response()),
            }
        }
        .boxed()
    }
}

fn extract_announce_from(maybe_raw_query: Option<&str>) -> Result<Announce, responses::error::Error> {
    if maybe_raw_query.is_none() {
        return Err(responses::error::Error::from(ParseAnnounceQueryError::MissingParams {
            location: Location::caller(),
        }));
    }

    let query = maybe_raw_query.unwrap().parse::<Query>();

    if let Err(error) = query {
        return Err(responses::error::Error::from(error));
    }

    let announce_request = Announce::try_from(query.unwrap());

    if let Err(error) = announce_request {
        return Err(responses::error::Error::from(error));
    }

    Ok(announce_request.unwrap())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use aquatic_udp_protocol::{NumberOfBytes, PeerId};
    use bittorrent_primitives::info_hash::InfoHash;

    use super::extract_announce_from;
    use crate::servers::http::v1::requests::announce::{Announce, Compact, Event};
    use crate::servers::http::v1::responses::error::Error;

    fn assert_error_response(error: &Error, error_message: &str) {
        assert!(
            error.failure_reason.contains(error_message),
            "Error response does not contain message: '{error_message}'. Error: {error:?}"
        );
    }

    #[test]
    fn it_should_extract_the_announce_request_from_the_url_query_params() {
        let raw_query = "info_hash=%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0&peer_addr=2.137.87.41&downloaded=0&uploaded=0&peer_id=-qB00000000000000001&port=17548&left=0&event=completed&compact=0&numwant=50";

        let announce = extract_announce_from(Some(raw_query)).unwrap();

        assert_eq!(
            announce,
            Announce {
                info_hash: InfoHash::from_str("3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0").unwrap(),
                peer_id: PeerId(*b"-qB00000000000000001"),
                port: 17548,
                downloaded: Some(NumberOfBytes::new(0)),
                uploaded: Some(NumberOfBytes::new(0)),
                left: Some(NumberOfBytes::new(0)),
                event: Some(Event::Completed),
                compact: Some(Compact::NotAccepted),
                numwant: Some(50),
            }
        );
    }

    #[test]
    fn it_should_reject_a_request_without_query_params() {
        let response = extract_announce_from(None).unwrap_err();

        assert_error_response(
            &response,
            "Bad request. Cannot parse query params for announce request: missing query params for announce request",
        );
    }

    #[test]
    fn it_should_reject_a_request_with_a_query_that_cannot_be_parsed() {
        let invalid_query = "param1=value1=value2";
        let response = extract_announce_from(Some(invalid_query)).unwrap_err();

        assert_error_response(&response, "Bad request. Cannot parse query params");
    }

    #[test]
    fn it_should_reject_a_request_with_a_query_that_cannot_be_parsed_into_an_announce_request() {
        let response = extract_announce_from(Some("param1=value1")).unwrap_err();

        assert_error_response(&response, "Bad request. Cannot parse query params for announce request");
    }
}
