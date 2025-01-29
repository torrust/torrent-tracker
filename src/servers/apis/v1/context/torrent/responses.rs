//! API responses for the [`torrent`](crate::servers::apis::v1::context::torrent)
//! API context.
use axum::response::{IntoResponse, Json, Response};
use serde_json::json;

use super::resources::torrent::{ListItem, Torrent};
use crate::core::torrent::services::{BasicInfo, Info};

/// `200` response that contains an array of
/// [`ListItem`]
/// resources as json.
pub fn torrent_list_response(basic_infos: &[BasicInfo]) -> Json<Vec<ListItem>> {
    Json(ListItem::new_vec(basic_infos))
}

/// `200` response that contains a
/// [`Torrent`]
/// resources as json.
pub fn torrent_info_response(info: Info) -> Json<Torrent> {
    Json(Torrent::from(info))
}

/// `500` error response in plain text returned when a torrent is not found.
#[must_use]
pub fn torrent_not_known_response() -> Response {
    Json(json!("torrent not known")).into_response()
}
