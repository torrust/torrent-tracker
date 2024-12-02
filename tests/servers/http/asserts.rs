use std::panic::Location;

use reqwest::Response;

use super::responses::announce::{Announce, Compact, DeserializedCompact};
use super::responses::scrape;
use crate::servers::http::responses::error::Error;

pub fn assert_bencoded_error(response_text: &String, expected_failure_reason: &str, location: &'static Location<'static>) {
    let error_failure_reason = serde_bencode::from_str::<Error>(response_text)
    .unwrap_or_else(|_| panic!(
                "response body should be a valid bencoded string for the '{expected_failure_reason}' error, got \"{response_text}\""
    )
        )
        .failure_reason;

    assert!(
        error_failure_reason.contains(expected_failure_reason),
        r#":
  response: `"{error_failure_reason}"`
  does not contain: `"{expected_failure_reason}"`, {location}"#
    );
}

pub async fn assert_empty_announce_response(response: Response) {
    assert_eq!(response.status(), 200);
    let announce_response: Announce = serde_bencode::from_str(&response.text().await.unwrap()).unwrap();
    assert!(announce_response.peers.is_empty());
}

pub async fn assert_announce_response(response: Response, expected_announce_response: &Announce) {
    assert_eq!(response.status(), 200);

    let body = response.bytes().await.unwrap();

    let announce_response: Announce = serde_bencode::from_bytes(&body)
        .unwrap_or_else(|_| panic!("response body should be a valid announce response, got \"{:#?}\"", &body));

    assert_eq!(announce_response, *expected_announce_response);
}

pub async fn assert_compact_announce_response(response: Response, expected_response: &Compact) {
    assert_eq!(response.status(), 200);

    let bytes = response.bytes().await.unwrap();

    let compact_announce = DeserializedCompact::from_bytes(&bytes).unwrap_or_else(|_| {
        panic!(
            "response body should be a valid compact announce response, got \"{:?}\"",
            &bytes
        )
    });

    let actual_response = Compact::from(compact_announce);

    assert_eq!(actual_response, *expected_response);
}

/// Sample bencoded scrape response as byte array:
///
/// ```text
/// b"d5:filesd20:\x9c8B\"\x13\xe3\x0b\xff!+0\xc3`\xd2o\x9a\x02\x13d\"d8:completei1e10:downloadedi0e10:incompletei0eeee"
/// ```
pub async fn assert_scrape_response(response: Response, expected_response: &scrape::Response) {
    assert_eq!(response.status(), 200);

    let scrape_response = scrape::Response::try_from_bencoded(&response.bytes().await.unwrap()).unwrap();

    assert_eq!(scrape_response, *expected_response);
}

pub async fn assert_is_announce_response(response: Response) {
    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();
    let _announce_response: Announce = serde_bencode::from_str(&body)
        .unwrap_or_else(|_| panic!("response body should be a valid announce response, got \"{}\"", &body));
}

// Error responses

// Specific errors for announce request

pub async fn assert_missing_query_params_for_announce_request_error_response(response: Response) {
    assert_eq!(response.status(), 200);

    assert_bencoded_error(
        &response.text().await.unwrap(),
        "missing query params for announce request",
        Location::caller(),
    );
}

pub async fn assert_bad_announce_request_error_response(response: Response, failure: &str) {
    assert_cannot_parse_query_params_error_response(response, &format!(" for announce request: {failure}")).await;
}

// Specific errors for scrape request

pub async fn assert_missing_query_params_for_scrape_request_error_response(response: Response) {
    assert_eq!(response.status(), 200);

    assert_bencoded_error(
        &response.text().await.unwrap(),
        "missing query params for scrape request",
        Location::caller(),
    );
}

// Other errors

pub async fn assert_torrent_not_in_whitelist_error_response(response: Response) {
    assert_eq!(response.status(), 200);

    assert_bencoded_error(&response.text().await.unwrap(), "is not whitelisted", Location::caller());
}

pub async fn assert_could_not_find_remote_address_on_x_forwarded_for_header_error_response(response: Response) {
    assert_eq!(response.status(), 200);

    assert_bencoded_error(
        &response.text().await.unwrap(),
        "missing or invalid the right most X-Forwarded-For IP (mandatory on reverse proxy tracker configuration)",
        Location::caller(),
    );
}

pub async fn assert_cannot_parse_query_param_error_response(response: Response, failure: &str) {
    assert_cannot_parse_query_params_error_response(response, &format!(": {failure}")).await;
}

pub async fn assert_cannot_parse_query_params_error_response(response: Response, failure: &str) {
    assert_eq!(response.status(), 200);

    assert_bencoded_error(
        &response.text().await.unwrap(),
        &format!("Bad request. Cannot parse query params{failure}"),
        Location::caller(),
    );
}

pub async fn assert_authentication_error_response(response: Response) {
    assert_eq!(response.status(), 200);

    assert_bencoded_error(&response.text().await.unwrap(), "Authentication error", Location::caller());
}
