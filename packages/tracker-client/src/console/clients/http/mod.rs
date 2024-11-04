use std::sync::Arc;

use serde::Serialize;
use thiserror::Error;

use crate::http::client::responses::scrape::BencodeParseError;

pub mod app;

#[derive(Debug, Clone, Error, Serialize)]
#[serde(into = "String")]
pub enum Error {
    #[error("Http request did not receive a response within the timeout: {err:?}")]
    HttpClientError { err: crate::http::client::Error },
    #[error("Http failed to get a response at all: {err:?}")]
    ResponseError { err: Arc<reqwest::Error> },
    #[error("Failed to deserialize the bencoded response data with the error: \"{err:?}\"")]
    ParseBencodeError {
        data: hyper::body::Bytes,
        err: Arc<serde_bencode::Error>,
    },

    #[error("Failed to deserialize the bencoded response data with the error: \"{err:?}\"")]
    BencodeParseError {
        data: hyper::body::Bytes,
        err: Arc<BencodeParseError>,
    },
}

impl From<Error> for String {
    fn from(value: Error) -> Self {
        value.to_string()
    }
}
