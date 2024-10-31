use std::str::FromStr as _;
use std::time::Duration;

use bittorrent_primitives::info_hash::InfoHash;
use serde::Serialize;
use url::Url;

use crate::console::clients::http::Error;
use crate::shared::bit_torrent::tracker::http::client::responses::announce::Announce;
use crate::shared::bit_torrent::tracker::http::client::responses::scrape;
use crate::shared::bit_torrent::tracker::http::client::{requests, Client};

#[derive(Debug, Clone, Serialize)]
pub struct Checks {
    url: Url,
    results: Vec<(Check, Result<(), Error>)>,
}

#[derive(Debug, Clone, Serialize)]
pub enum Check {
    Announce,
    Scrape,
}

pub async fn run(http_trackers: Vec<Url>, timeout: Duration) -> Vec<Result<Checks, Checks>> {
    let mut results = Vec::default();

    tracing::debug!("HTTP trackers ...");

    for ref url in http_trackers {
        let mut base_url = url.clone();
        base_url.set_path("");

        let mut checks = Checks {
            url: url.clone(),
            results: Vec::default(),
        };

        // Announce
        {
            let check = check_http_announce(&base_url, timeout).await.map(|_| ());

            checks.results.push((Check::Announce, check));
        }

        // Scrape
        {
            let check = check_http_scrape(&base_url, timeout).await.map(|_| ());

            checks.results.push((Check::Scrape, check));
        }

        if checks.results.iter().any(|f| f.1.is_err()) {
            results.push(Err(checks));
        } else {
            results.push(Ok(checks));
        }
    }

    results
}

async fn check_http_announce(url: &Url, timeout: Duration) -> Result<Announce, Error> {
    let info_hash_str = "9c38422213e30bff212b30c360d26f9a02136422".to_string(); // # DevSkim: ignore DS173237
    let info_hash = InfoHash::from_str(&info_hash_str).expect("a valid info-hash is required");

    let client = Client::new(url.clone(), timeout).map_err(|err| Error::HttpClientError { err })?;

    let response = client
        .announce(
            &requests::announce::QueryBuilder::with_default_values()
                .with_info_hash(&info_hash)
                .query(),
        )
        .await
        .map_err(|err| Error::HttpClientError { err })?;

    let response = response.bytes().await.map_err(|e| Error::ResponseError { err: e.into() })?;

    let response = serde_bencode::from_bytes::<Announce>(&response).map_err(|e| Error::ParseBencodeError {
        data: response,
        err: e.into(),
    })?;

    Ok(response)
}

async fn check_http_scrape(url: &Url, timeout: Duration) -> Result<scrape::Response, Error> {
    let info_hashes: Vec<String> = vec!["9c38422213e30bff212b30c360d26f9a02136422".to_string()]; // # DevSkim: ignore DS173237
    let query = requests::scrape::Query::try_from(info_hashes).expect("a valid array of info-hashes is required");

    let client = Client::new(url.clone(), timeout).map_err(|err| Error::HttpClientError { err })?;

    let response = client.scrape(&query).await.map_err(|err| Error::HttpClientError { err })?;

    let response = response.bytes().await.map_err(|e| Error::ResponseError { err: e.into() })?;

    let response = scrape::Response::try_from_bencoded(&response).map_err(|e| Error::BencodeParseError {
        data: response,
        err: e.into(),
    })?;

    Ok(response)
}
