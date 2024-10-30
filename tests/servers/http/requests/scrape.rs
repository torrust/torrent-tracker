use std::fmt;
use std::str::FromStr;

use bittorrent_primitives::info_hash::InfoHash;

use crate::servers::http::{percent_encode_byte_array, ByteArray20};

pub struct Query {
    pub info_hash: Vec<ByteArray20>,
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.build())
    }
}

/// HTTP Tracker Scrape Request:
///
/// <https://www.bittorrent.org/beps/bep_0048.html>
impl Query {
    /// It builds the URL query component for the scrape request.
    ///
    /// This custom URL query params encoding is needed because `reqwest` does not allow
    /// bytes arrays in query parameters. More info on this issue:
    ///
    /// <https://github.com/seanmonstar/reqwest/issues/1613>
    pub fn build(&self) -> String {
        self.params().to_string()
    }

    pub fn params(&self) -> QueryParams {
        QueryParams::from(self)
    }
}

pub struct QueryBuilder {
    scrape_query: Query,
}

impl QueryBuilder {
    pub fn default() -> QueryBuilder {
        let default_scrape_query = Query {
            info_hash: [InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap().0].to_vec(),
        };
        Self {
            scrape_query: default_scrape_query,
        }
    }

    pub fn with_one_info_hash(mut self, info_hash: &InfoHash) -> Self {
        self.scrape_query.info_hash = [info_hash.0].to_vec();
        self
    }

    pub fn add_info_hash(mut self, info_hash: &InfoHash) -> Self {
        self.scrape_query.info_hash.push(info_hash.0);
        self
    }

    pub fn query(self) -> Query {
        self.scrape_query
    }
}

/// It contains all the GET parameters that can be used in a HTTP Scrape request.
///
/// The `info_hash` param is the percent encoded of the the 20-byte array info hash.
///
/// Sample Scrape URL with all the GET parameters:
///
/// For `IpV4`:
///
/// ```text
/// http://127.0.0.1:7070/scrape?info_hash=%9C8B%22%13%E3%0B%FF%21%2B0%C3%60%D2o%9A%02%13d%22
/// ```
///
/// For `IpV6`:
///
/// ```text
/// http://[::1]:7070/scrape?info_hash=%9C8B%22%13%E3%0B%FF%21%2B0%C3%60%D2o%9A%02%13d%22
/// ```
///
/// You can add as many info hashes as you want, just adding the same param again.
pub struct QueryParams {
    pub info_hash: Vec<String>,
}

impl QueryParams {
    pub fn set_one_info_hash_param(&mut self, info_hash: &str) {
        self.info_hash = vec![info_hash.to_string()];
    }
}

impl std::fmt::Display for QueryParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let query = self
            .info_hash
            .iter()
            .map(|info_hash| format!("info_hash={}", &info_hash))
            .collect::<Vec<String>>()
            .join("&");

        write!(f, "{query}")
    }
}

impl QueryParams {
    pub fn from(scrape_query: &Query) -> Self {
        let info_hashes = scrape_query
            .info_hash
            .iter()
            .map(percent_encode_byte_array)
            .collect::<Vec<String>>();

        Self { info_hash: info_hashes }
    }
}
