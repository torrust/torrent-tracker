//! API handlers for the [`auth_key`](crate::servers::apis::v1::context::auth_key) API context.
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{self, Path, State};
use axum::response::Response;
use serde::Deserialize;

use super::forms::AddKeyForm;
use super::responses::{
    auth_key_response, failed_to_delete_key_response, failed_to_generate_key_response, failed_to_reload_keys_response,
    invalid_auth_key_duration_response, invalid_auth_key_response,
};
use crate::core::authentication::handler::{AddKeyRequest, KeysHandler};
use crate::core::authentication::Key;
use crate::servers::apis::v1::context::auth_key::resources::AuthKey;
use crate::servers::apis::v1::responses::{invalid_auth_key_param_response, ok_response};

/// It handles the request to add a new authentication key.
///
/// It returns these types of responses:
///
/// - `200` with a json [`AuthKey`]
///    resource. If the key was generated successfully.
/// - `400` with an error if the key couldn't been added because of an invalid
///    request.
/// - `500` with serialized error in debug format. If the key couldn't be
///    generated.
///
/// Refer to the [API endpoint documentation](crate::servers::apis::v1::context::auth_key#generate-a-new-authentication-key)
/// for more information about this endpoint.
pub async fn add_auth_key_handler(
    State(keys_handler): State<Arc<KeysHandler>>,
    extract::Json(add_key_form): extract::Json<AddKeyForm>,
) -> Response {
    match keys_handler
        .add_peer_key(AddKeyRequest {
            opt_key: add_key_form.opt_key.clone(),
            opt_seconds_valid: add_key_form.opt_seconds_valid,
        })
        .await
    {
        Ok(auth_key) => auth_key_response(&AuthKey::from(auth_key)),
        Err(err) => match err {
            crate::core::error::PeerKeyError::DurationOverflow { seconds_valid } => {
                invalid_auth_key_duration_response(seconds_valid)
            }
            crate::core::error::PeerKeyError::InvalidKey { key, source } => invalid_auth_key_response(&key, source),
            crate::core::error::PeerKeyError::DatabaseError { source } => failed_to_generate_key_response(source),
        },
    }
}

/// It handles the request to generate a new authentication key.
///
/// It returns two types of responses:
///
/// - `200` with an json [`AuthKey`]
///    resource. If the key was generated successfully.
/// - `500` with serialized error in debug format. If the key couldn't be
///    generated.
///
/// Refer to the [API endpoint documentation](crate::servers::apis::v1::context::auth_key#generate-a-new-authentication-key)
/// for more information about this endpoint.
///
/// This endpoint has been deprecated. Use [`add_auth_key_handler`].
pub async fn generate_auth_key_handler(
    State(keys_handler): State<Arc<KeysHandler>>,
    Path(seconds_valid_or_key): Path<u64>,
) -> Response {
    let seconds_valid = seconds_valid_or_key;
    match keys_handler.generate_auth_key(Some(Duration::from_secs(seconds_valid))).await {
        Ok(auth_key) => auth_key_response(&AuthKey::from(auth_key)),
        Err(e) => failed_to_generate_key_response(e),
    }
}

/// A container for the `key` parameter extracted from the URL PATH.
///
/// It does not perform any validation, it just stores the value.
///
/// In the current API version, the `key` parameter can be either a valid key
/// like `xqD6NWH9TcKrOCwDmqcdH5hF5RrbL0A6` or the number of seconds the
/// key will be valid, for example two minutes `120`.
///
/// For example, the `key` is used in the following requests:
///
/// - `POST /api/v1/key/120`. It will generate a new key valid for two minutes.
/// - `DELETE /api/v1/key/xqD6NWH9TcKrOCwDmqcdH5hF5RrbL0A6`. It will delete the
///   key `xqD6NWH9TcKrOCwDmqcdH5hF5RrbL0A6`.
///
/// > **NOTICE**: this may change in the future, in the [API v2](https://github.com/torrust/torrust-tracker/issues/144).
#[derive(Deserialize)]
pub struct KeyParam(String);

/// It handles the request to delete an authentication key.
///
/// It returns two types of responses:
///
/// - `200` with an json [`ActionStatus::Ok`](crate::servers::apis::v1::responses::ActionStatus::Ok)
///    response. If the key was deleted successfully.
/// - `500` with serialized error in debug format. If the key couldn't be
///    deleted.
///
/// Refer to the [API endpoint documentation](crate::servers::apis::v1::context::auth_key#delete-an-authentication-key)
/// for more information about this endpoint.
pub async fn delete_auth_key_handler(
    State(keys_handler): State<Arc<KeysHandler>>,
    Path(seconds_valid_or_key): Path<KeyParam>,
) -> Response {
    match Key::from_str(&seconds_valid_or_key.0) {
        Err(_) => invalid_auth_key_param_response(&seconds_valid_or_key.0),
        Ok(key) => match keys_handler.remove_auth_key(&key).await {
            Ok(()) => ok_response(),
            Err(e) => failed_to_delete_key_response(e),
        },
    }
}

/// It handles the request to reload the authentication keys from the database
/// into memory.
///
/// It returns two types of responses:
///
/// - `200` with an json [`ActionStatus::Ok`](crate::servers::apis::v1::responses::ActionStatus::Ok)
///    response. If the keys were successfully reloaded.
/// - `500` with serialized error in debug format. If the they couldn't be
///    reloaded.
///
/// Refer to the [API endpoint documentation](crate::servers::apis::v1::context::auth_key#reload-authentication-keys)
/// for more information about this endpoint.
pub async fn reload_keys_handler(State(keys_handler): State<Arc<KeysHandler>>) -> Response {
    match keys_handler.load_keys_from_database().await {
        Ok(()) => ok_response(),
        Err(e) => failed_to_reload_keys_response(e),
    }
}
