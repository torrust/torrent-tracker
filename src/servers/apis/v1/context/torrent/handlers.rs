//! API handlers for the [`torrent`](crate::servers::apis::v1::context::torrent)
//! API context.
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::Query;
use bittorrent_primitives::info_hash::InfoHash;
use serde::{de, Deserialize, Deserializer};
use thiserror::Error;
use torrust_tracker_primitives::pagination::Pagination;

use super::responses::{torrent_info_response, torrent_list_response, torrent_not_known_response};
use crate::core::torrent::repository::in_memory::InMemoryTorrentRepository;
use crate::core::torrent::services::{get_torrent_info, get_torrents, get_torrents_page};
use crate::servers::apis::v1::responses::invalid_info_hash_param_response;
use crate::servers::apis::InfoHashParam;

/// It handles the request to get the torrent data.
///
/// It returns:
///
/// - `200` response with a json [`Torrent`](crate::servers::apis::v1::context::torrent::resources::torrent::Torrent).
/// - `500` with serialized error in debug format if the torrent is not known.
///
/// Refer to the [API endpoint documentation](crate::servers::apis::v1::context::torrent#get-a-torrent)
/// for more information about this endpoint.
pub async fn get_torrent_handler(
    State(in_memory_torrent_repository): State<Arc<InMemoryTorrentRepository>>,
    Path(info_hash): Path<InfoHashParam>,
) -> Response {
    match InfoHash::from_str(&info_hash.0) {
        Err(_) => invalid_info_hash_param_response(&info_hash.0),
        Ok(info_hash) => match get_torrent_info(in_memory_torrent_repository.clone(), &info_hash).await {
            Some(info) => torrent_info_response(info).into_response(),
            None => torrent_not_known_response(),
        },
    }
}

/// A container for the URL query parameters.
///
/// Pagination: `offset` and `limit`.
/// Array of infohashes: `info_hash`.
///
/// You can either get all torrents with pagination or get a list of torrents
/// providing a list of infohashes. For example:
///
/// First page of torrents:
///
/// <http://127.0.0.1:1212/api/v1/torrents?token=MyAccessToken>
///
///
/// Only two torrents:
///
/// <http://127.0.0.1:1212/api/v1/torrents?token=MyAccessToken&info_hash=9c38422213e30bff212b30c360d26f9a02136422&info_hash=2b66980093bc11806fab50cb3cb41835b95a0362>
///
///
/// NOTICE: Pagination is ignored if array of infohashes is provided.
#[derive(Deserialize, Debug)]
pub struct QueryParams {
    /// The offset of the first page to return. Starts at 0.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub offset: Option<u32>,
    /// The maximum number of items to return per page.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub limit: Option<u32>,
    /// A list of infohashes to retrieve.
    #[serde(default, rename = "info_hash")]
    pub info_hashes: Vec<String>,
}

/// It handles the request to get a list of torrents.
///
/// It returns a `200` response with a json array with [`crate::servers::apis::v1::context::torrent::resources::torrent::ListItem`] resources.
///
/// Refer to the [API endpoint documentation](crate::servers::apis::v1::context::torrent#list-torrents)
/// for more information about this endpoint.
pub async fn get_torrents_handler(
    State(in_memory_torrent_repository): State<Arc<InMemoryTorrentRepository>>,
    pagination: Query<QueryParams>,
) -> Response {
    tracing::debug!("pagination: {:?}", pagination);

    if pagination.0.info_hashes.is_empty() {
        torrent_list_response(
            &get_torrents_page(
                in_memory_torrent_repository.clone(),
                Some(&Pagination::new_with_options(pagination.0.offset, pagination.0.limit)),
            )
            .await,
        )
        .into_response()
    } else {
        match parse_info_hashes(pagination.0.info_hashes) {
            Ok(info_hashes) => {
                torrent_list_response(&get_torrents(in_memory_torrent_repository.clone(), &info_hashes).await).into_response()
            }
            Err(err) => match err {
                QueryParamError::InvalidInfoHash { info_hash } => invalid_info_hash_param_response(&info_hash),
            },
        }
    }
}

#[derive(Error, Debug)]
pub enum QueryParamError {
    #[error("invalid infohash {info_hash}")]
    InvalidInfoHash { info_hash: String },
}

fn parse_info_hashes(info_hashes_str: Vec<String>) -> Result<Vec<InfoHash>, QueryParamError> {
    let mut info_hashes: Vec<InfoHash> = Vec::new();

    for info_hash_str in info_hashes_str {
        match InfoHash::from_str(&info_hash_str) {
            Ok(info_hash) => info_hashes.push(info_hash),
            Err(_err) => {
                return Err(QueryParamError::InvalidInfoHash {
                    info_hash: info_hash_str,
                })
            }
        }
    }

    Ok(info_hashes)
}

/// Serde deserialization decorator to map empty Strings to None,
fn empty_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    let opt = Option::<String>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => FromStr::from_str(s).map_err(de::Error::custom).map(Some),
    }
}
