//! `Scrape` request for the HTTP tracker.
//!
//! Data structures and logic for parsing the `scrape` request.
use std::panic::Location;

use bittorrent_primitives::info_hash::{self, InfoHash};
use thiserror::Error;
use torrust_tracker_located_error::{Located, LocatedError};

use crate::servers::http::percent_encoding::percent_decode_info_hash;
use crate::servers::http::v1::query::Query;
use crate::servers::http::v1::responses;

// Query param names
const INFO_HASH: &str = "info_hash";

#[derive(Debug, PartialEq)]
pub struct Scrape {
    pub info_hashes: Vec<InfoHash>,
}

#[derive(Error, Debug)]
pub enum ParseScrapeQueryError {
    #[error("missing query params for scrape request in {location}")]
    MissingParams { location: &'static Location<'static> },
    #[error("missing param {param_name} in {location}")]
    MissingParam {
        location: &'static Location<'static>,
        param_name: String,
    },
    #[error("invalid param value {param_value} for {param_name} in {source}")]
    InvalidInfoHashParam {
        param_name: String,
        param_value: String,
        source: LocatedError<'static, info_hash::ConversionError>,
    },
}

impl From<ParseScrapeQueryError> for responses::error::Error {
    fn from(err: ParseScrapeQueryError) -> Self {
        responses::error::Error {
            failure_reason: format!("Cannot parse query params for scrape request: {err}"),
        }
    }
}

impl TryFrom<Query> for Scrape {
    type Error = ParseScrapeQueryError;

    fn try_from(query: Query) -> Result<Self, Self::Error> {
        Ok(Self {
            info_hashes: extract_info_hashes(&query)?,
        })
    }
}

fn extract_info_hashes(query: &Query) -> Result<Vec<InfoHash>, ParseScrapeQueryError> {
    match query.get_param_vec(INFO_HASH) {
        Some(raw_params) => {
            let mut info_hashes = vec![];

            for raw_param in raw_params {
                let info_hash =
                    percent_decode_info_hash(&raw_param).map_err(|err| ParseScrapeQueryError::InvalidInfoHashParam {
                        param_name: INFO_HASH.to_owned(),
                        param_value: raw_param.clone(),
                        source: Located(err).into(),
                    })?;

                info_hashes.push(info_hash);
            }

            Ok(info_hashes)
        }
        None => Err(ParseScrapeQueryError::MissingParam {
            location: Location::caller(),
            param_name: INFO_HASH.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {

    mod scrape_request {

        use bittorrent_primitives::info_hash::InfoHash;

        use crate::servers::http::v1::query::Query;
        use crate::servers::http::v1::requests::scrape::{Scrape, INFO_HASH};

        #[test]
        fn should_be_instantiated_from_the_url_query_with_only_one_infohash() {
            let raw_query = Query::from(vec![(INFO_HASH, "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0")]).to_string();

            let query = raw_query.parse::<Query>().unwrap();

            let scrape_request = Scrape::try_from(query).unwrap();

            assert_eq!(
                scrape_request,
                Scrape {
                    info_hashes: vec!["3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap()],
                }
            );
        }

        mod when_it_is_instantiated_from_the_url_query_params {

            use crate::servers::http::v1::query::Query;
            use crate::servers::http::v1::requests::scrape::{Scrape, INFO_HASH};

            #[test]
            fn it_should_fail_if_the_query_does_not_include_the_info_hash_param() {
                let raw_query_without_info_hash = "another_param=NOT_RELEVANT";

                assert!(Scrape::try_from(raw_query_without_info_hash.parse::<Query>().unwrap()).is_err());
            }

            #[test]
            fn it_should_fail_if_the_info_hash_param_is_invalid() {
                let raw_query = Query::from(vec![(INFO_HASH, "INVALID_INFO_HASH_VALUE")]).to_string();

                assert!(Scrape::try_from(raw_query.parse::<Query>().unwrap()).is_err());
            }
        }
    }
}
