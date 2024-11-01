//! HTTP Tracker client:
//!
//! Examples:
//!
//! `Announce` request:
//!
//! ```text
//! cargo run --bin http_tracker_client announce http://127.0.0.1:7070 9c38422213e30bff212b30c360d26f9a02136422 | jq
//! ```
//!
//! `Scrape` request:
//!
//! ```text
//! cargo run --bin http_tracker_client scrape http://127.0.0.1:7070 9c38422213e30bff212b30c360d26f9a02136422 | jq
//! ```
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bittorrent_primitives::info_hash::InfoHash;
use clap::{Parser, Subcommand};
use reqwest::Url;
use torrust_tracker_configuration::DEFAULT_TIMEOUT;

use crate::http::client::requests::announce::QueryBuilder;
use crate::http::client::responses::announce::Announce;
use crate::http::client::responses::scrape;
use crate::http::client::{requests, Client};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Announce { tracker_url: String, info_hash: String },
    Scrape { tracker_url: String, info_hashes: Vec<String> },
}

/// # Errors
///
/// Will return an error if the command fails.
pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Announce { tracker_url, info_hash } => {
            announce_command(tracker_url, info_hash, DEFAULT_TIMEOUT).await?;
        }
        Command::Scrape {
            tracker_url,
            info_hashes,
        } => {
            scrape_command(&tracker_url, &info_hashes, DEFAULT_TIMEOUT).await?;
        }
    }

    Ok(())
}

async fn announce_command(tracker_url: String, info_hash: String, timeout: Duration) -> anyhow::Result<()> {
    let base_url = Url::parse(&tracker_url).context("failed to parse HTTP tracker base URL")?;
    let info_hash =
        InfoHash::from_str(&info_hash).expect("Invalid infohash. Example infohash: `9c38422213e30bff212b30c360d26f9a02136422`");

    let response = Client::new(base_url, timeout)?
        .announce(&QueryBuilder::with_default_values().with_info_hash(&info_hash).query())
        .await?;

    let body = response.bytes().await?;

    let announce_response: Announce = serde_bencode::from_bytes(&body)
        .unwrap_or_else(|_| panic!("response body should be a valid announce response, got: \"{:#?}\"", &body));

    let json = serde_json::to_string(&announce_response).context("failed to serialize scrape response into JSON")?;

    println!("{json}");

    Ok(())
}

async fn scrape_command(tracker_url: &str, info_hashes: &[String], timeout: Duration) -> anyhow::Result<()> {
    let base_url = Url::parse(tracker_url).context("failed to parse HTTP tracker base URL")?;

    let query = requests::scrape::Query::try_from(info_hashes).context("failed to parse infohashes")?;

    let response = Client::new(base_url, timeout)?.scrape(&query).await?;

    let body = response.bytes().await?;

    let scrape_response = scrape::Response::try_from_bencoded(&body)
        .unwrap_or_else(|_| panic!("response body should be a valid scrape response, got: \"{:#?}\"", &body));

    let json = serde_json::to_string(&scrape_response).context("failed to serialize scrape response into JSON")?;

    println!("{json}");

    Ok(())
}
