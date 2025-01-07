//! Axum [`extractor`](axum::extract) for the [`Scrape`]
//! request.
//!
//! It parses the query parameters returning an [`Scrape`]
//! request.
//!
//! Refer to [`Scrape`](crate::servers::http::v1::requests::scrape)  for more
//! information about the returned structure.
//!
//! It returns a bencoded [`Error`](crate::servers::http::v1::responses::error)
//! response (`500`) if the query parameters are missing or invalid.
//!
//! **Sample scrape request**
//!
//! <http://0.0.0.0:7070/scrape?info_hash=%81%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00>
//!
//! **Sample error response**
//!
//! Missing query params for scrape request: <http://0.0.0.0:7070/scrape>
//!
//! ```text
//! d14:failure reason143:Bad request. Cannot parse query params for scrape request: missing query params for scrape request in src/servers/http/v1/extractors/scrape_request.rs:52:23e
//! ```
//!
//! Invalid query params for scrape request: <http://0.0.0.0:7070/scrape?info_hash=invalid>
//!
//! ```text
//! d14:failure reason235:Bad request. Cannot parse query params for scrape request: invalid param value invalid for info_hash in not enough bytes for infohash: got 7 bytes, expected 20 src/shared/bit_torrent/info_hash.rs:240:27, src/servers/http/v1/requests/scrape.rs:66:46e
//! ```
use std::future::Future;
use std::panic::Location;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use futures::FutureExt;

use crate::servers::http::v1::query::Query;
use crate::servers::http::v1::requests::scrape::{ParseScrapeQueryError, Scrape};
use crate::servers::http::v1::responses;

/// Extractor for the [`Scrape`]
/// request.
pub struct ExtractRequest(pub Scrape);

impl<S> FromRequestParts<S> for ExtractRequest
where
    S: Send + Sync,
{
    type Rejection = Response;

    fn from_request_parts(parts: &mut Parts, _state: &S) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async {
            match extract_scrape_from(parts.uri.query()) {
                Ok(scrape_request) => Ok(ExtractRequest(scrape_request)),
                Err(error) => Err(error.into_response()),
            }
        }
        .boxed()
    }
}

fn extract_scrape_from(maybe_raw_query: Option<&str>) -> Result<Scrape, responses::error::Error> {
    if maybe_raw_query.is_none() {
        return Err(responses::error::Error::from(ParseScrapeQueryError::MissingParams {
            location: Location::caller(),
        }));
    }

    let query = maybe_raw_query.unwrap().parse::<Query>();

    if let Err(error) = query {
        return Err(responses::error::Error::from(error));
    }

    let scrape_request = Scrape::try_from(query.unwrap());

    if let Err(error) = scrape_request {
        return Err(responses::error::Error::from(error));
    }

    Ok(scrape_request.unwrap())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bittorrent_primitives::info_hash::InfoHash;

    use super::extract_scrape_from;
    use crate::servers::http::v1::requests::scrape::Scrape;
    use crate::servers::http::v1::responses::error::Error;

    struct TestInfoHash {
        pub bencoded: String,
        pub value: InfoHash,
    }

    fn test_info_hash() -> TestInfoHash {
        TestInfoHash {
            bencoded: "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0".to_owned(),
            value: InfoHash::from_str("3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0").unwrap(),
        }
    }

    fn assert_error_response(error: &Error, error_message: &str) {
        assert!(
            error.failure_reason.contains(error_message),
            "Error response does not contain message: '{error_message}'. Error: {error:?}"
        );
    }

    #[test]
    fn it_should_extract_the_scrape_request_from_the_url_query_params() {
        let info_hash = test_info_hash();

        let raw_query = format!("info_hash={}", info_hash.bencoded);

        let scrape = extract_scrape_from(Some(&raw_query)).unwrap();

        assert_eq!(
            scrape,
            Scrape {
                info_hashes: vec![info_hash.value],
            }
        );
    }

    #[test]
    fn it_should_extract_the_scrape_request_from_the_url_query_params_with_more_than_one_info_hash() {
        let info_hash = test_info_hash();

        let raw_query = format!("info_hash={}&info_hash={}", info_hash.bencoded, info_hash.bencoded);

        let scrape = extract_scrape_from(Some(&raw_query)).unwrap();

        assert_eq!(
            scrape,
            Scrape {
                info_hashes: vec![info_hash.value, info_hash.value],
            }
        );
    }

    #[test]
    fn it_should_reject_a_request_without_query_params() {
        let response = extract_scrape_from(None).unwrap_err();

        assert_error_response(
            &response,
            "Bad request. Cannot parse query params for scrape request: missing query params for scrape request",
        );
    }

    #[test]
    fn it_should_reject_a_request_with_a_query_that_cannot_be_parsed() {
        let invalid_query = "param1=value1=value2";
        let response = extract_scrape_from(Some(invalid_query)).unwrap_err();

        assert_error_response(&response, "Bad request. Cannot parse query params");
    }

    #[test]
    fn it_should_reject_a_request_with_a_query_that_cannot_be_parsed_into_a_scrape_request() {
        let response = extract_scrape_from(Some("param1=value1")).unwrap_err();

        assert_error_response(&response, "Bad request. Cannot parse query params for scrape request");
    }
}
