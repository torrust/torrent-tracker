//! API handlers for the [`whitelist`](crate::servers::apis::v1::context::whitelist)
//! API context.
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::Response;

use super::responses::{
    failed_to_reload_whitelist_response, failed_to_remove_torrent_from_whitelist_response, failed_to_whitelist_torrent_response,
};
use crate::core::Tracker;
use crate::servers::apis::v1::responses::{invalid_info_hash_param_response, ok_response};
use crate::servers::apis::InfoHashParam;
use crate::shared::bit_torrent::info_hash::InfoHash;

/// It handles the request to add a torrent to the whitelist.
///
/// It returns:
///
/// - `200` response with a [`ActionStatus::Ok`](crate::servers::apis::v1::responses::ActionStatus::Ok) in json.
/// - `500` with serialized error in debug format if the torrent couldn't be whitelisted.
///
/// Refer to the [API endpoint documentation](crate::servers::apis::v1::context::whitelist#add-a-torrent-to-the-whitelist)
/// for more information about this endpoint.
pub async fn add_torrent_to_whitelist_handler(
    State(tracker): State<Arc<Tracker>>,
    Path(info_hash): Path<InfoHashParam>,
) -> Response {
    match InfoHash::from_str(&info_hash.0) {
        Err(_) => invalid_info_hash_param_response(&info_hash.0),
        Ok(info_hash) => match tracker.add_torrent_to_whitelist(&info_hash).await {
            Ok(()) => ok_response(),
            Err(e) => failed_to_whitelist_torrent_response(e),
        },
    }
}

/// It handles the request to remove a torrent to the whitelist.
///
/// It returns:
///
/// - `200` response with a [`ActionStatus::Ok`](crate::servers::apis::v1::responses::ActionStatus::Ok) in json.
/// - `500` with serialized error in debug format if the torrent couldn't be
/// removed from the whitelisted.
///
/// Refer to the [API endpoint documentation](crate::servers::apis::v1::context::whitelist#remove-a-torrent-from-the-whitelist)
/// for more information about this endpoint.
pub async fn remove_torrent_from_whitelist_handler(
    State(tracker): State<Arc<Tracker>>,
    Path(info_hash): Path<InfoHashParam>,
) -> Response {
    match InfoHash::from_str(&info_hash.0) {
        Err(_) => invalid_info_hash_param_response(&info_hash.0),
        Ok(info_hash) => match tracker.remove_torrent_from_whitelist(&info_hash).await {
            Ok(()) => ok_response(),
            Err(e) => failed_to_remove_torrent_from_whitelist_response(e),
        },
    }
}

/// It handles the request to reload the torrent whitelist from the database.
///
/// It returns:
///
/// - `200` response with a [`ActionStatus::Ok`](crate::servers::apis::v1::responses::ActionStatus::Ok) in json.
/// - `500` with serialized error in debug format if the torrent whitelist
/// couldn't be reloaded from the database.
///
/// Refer to the [API endpoint documentation](crate::servers::apis::v1::context::whitelist#reload-the-whitelist)
/// for more information about this endpoint.
pub async fn reload_whitelist_handler(State(tracker): State<Arc<Tracker>>) -> Response {
    match tracker.load_whitelist_from_database().await {
        Ok(()) => ok_response(),
        Err(e) => failed_to_reload_whitelist_response(e),
    }
}
