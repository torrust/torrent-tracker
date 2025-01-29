use std::str::FromStr;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_api_client::v1::client::{headers_with_request_id, Client};
use torrust_tracker_test_helpers::configuration;
use uuid::Uuid;

use crate::common::logging::{self, logs_contains_a_line_with};
use crate::servers::api::connection_info::{connection_with_invalid_token, connection_with_no_token};
use crate::servers::api::v1::asserts::{
    assert_failed_to_reload_whitelist, assert_failed_to_remove_torrent_from_whitelist, assert_failed_to_whitelist_torrent,
    assert_invalid_infohash_param, assert_not_found, assert_ok, assert_token_not_valid, assert_unauthorized,
};
use crate::servers::api::v1::contract::fixtures::{
    invalid_infohashes_returning_bad_request, invalid_infohashes_returning_not_found,
};
use crate::servers::api::{force_database_error, Started};

#[tokio::test]
async fn should_allow_whitelisting_a_torrent() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let request_id = Uuid::new_v4();
    let info_hash = "9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d".to_owned(); // DevSkim: ignore DS173237

    let response = Client::new(env.get_connection_info())
        .whitelist_a_torrent(&info_hash, Some(headers_with_request_id(request_id)))
        .await;

    assert_ok(response).await;
    assert!(
        env.http_api_container
            .whitelist_manager
            .is_info_hash_whitelisted(&InfoHash::from_str(&info_hash).unwrap())
            .await
    );

    env.stop().await;
}

#[tokio::test]
async fn should_allow_whitelisting_a_torrent_that_has_been_already_whitelisted() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let info_hash = "9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d".to_owned(); // DevSkim: ignore DS173237

    let api_client = Client::new(env.get_connection_info());

    let request_id = Uuid::new_v4();

    let response = api_client
        .whitelist_a_torrent(&info_hash, Some(headers_with_request_id(request_id)))
        .await;
    assert_ok(response).await;

    let request_id = Uuid::new_v4();

    let response = api_client
        .whitelist_a_torrent(&info_hash, Some(headers_with_request_id(request_id)))
        .await;
    assert_ok(response).await;

    env.stop().await;
}

#[tokio::test]
async fn should_not_allow_whitelisting_a_torrent_for_unauthenticated_users() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let info_hash = "9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d".to_owned(); // DevSkim: ignore DS173237

    let request_id = Uuid::new_v4();

    let response = Client::new(connection_with_invalid_token(env.get_connection_info().origin))
        .whitelist_a_torrent(&info_hash, Some(headers_with_request_id(request_id)))
        .await;

    assert_token_not_valid(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    let request_id = Uuid::new_v4();

    let response = Client::new(connection_with_no_token(env.get_connection_info().origin))
        .whitelist_a_torrent(&info_hash, Some(headers_with_request_id(request_id)))
        .await;

    assert_unauthorized(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    env.stop().await;
}

#[tokio::test]
async fn should_fail_when_the_torrent_cannot_be_whitelisted() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let info_hash = "9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d".to_owned(); // DevSkim: ignore DS173237

    force_database_error(&env.database);

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .whitelist_a_torrent(&info_hash, Some(headers_with_request_id(request_id)))
        .await;

    assert_failed_to_whitelist_torrent(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    env.stop().await;
}

#[tokio::test]
async fn should_fail_whitelisting_a_torrent_when_the_provided_infohash_is_invalid() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let request_id = Uuid::new_v4();

    for invalid_infohash in &invalid_infohashes_returning_bad_request() {
        let response = Client::new(env.get_connection_info())
            .whitelist_a_torrent(invalid_infohash, Some(headers_with_request_id(request_id)))
            .await;

        assert_invalid_infohash_param(response, invalid_infohash).await;
    }

    let request_id = Uuid::new_v4();

    for invalid_infohash in &invalid_infohashes_returning_not_found() {
        let response = Client::new(env.get_connection_info())
            .whitelist_a_torrent(invalid_infohash, Some(headers_with_request_id(request_id)))
            .await;

        assert_not_found(response).await;
    }

    env.stop().await;
}

#[tokio::test]
async fn should_allow_removing_a_torrent_from_the_whitelist() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let hash = "9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d".to_owned(); // DevSkim: ignore DS173237
    let info_hash = InfoHash::from_str(&hash).unwrap();

    env.http_api_container
        .whitelist_manager
        .add_torrent_to_whitelist(&info_hash)
        .await
        .unwrap();

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .remove_torrent_from_whitelist(&hash, Some(headers_with_request_id(request_id)))
        .await;

    assert_ok(response).await;
    assert!(
        !env.http_api_container
            .whitelist_manager
            .is_info_hash_whitelisted(&info_hash)
            .await
    );

    env.stop().await;
}

#[tokio::test]
async fn should_not_fail_trying_to_remove_a_non_whitelisted_torrent_from_the_whitelist() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let non_whitelisted_torrent_hash = "9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d".to_owned(); // DevSkim: ignore DS173237

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .remove_torrent_from_whitelist(&non_whitelisted_torrent_hash, Some(headers_with_request_id(request_id)))
        .await;

    assert_ok(response).await;

    env.stop().await;
}

#[tokio::test]
async fn should_fail_removing_a_torrent_from_the_whitelist_when_the_provided_infohash_is_invalid() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    for invalid_infohash in &invalid_infohashes_returning_bad_request() {
        let request_id = Uuid::new_v4();

        let response = Client::new(env.get_connection_info())
            .remove_torrent_from_whitelist(invalid_infohash, Some(headers_with_request_id(request_id)))
            .await;

        assert_invalid_infohash_param(response, invalid_infohash).await;
    }

    for invalid_infohash in &invalid_infohashes_returning_not_found() {
        let request_id = Uuid::new_v4();

        let response = Client::new(env.get_connection_info())
            .remove_torrent_from_whitelist(invalid_infohash, Some(headers_with_request_id(request_id)))
            .await;

        assert_not_found(response).await;
    }

    env.stop().await;
}

#[tokio::test]
async fn should_fail_when_the_torrent_cannot_be_removed_from_the_whitelist() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let hash = "9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d".to_owned(); // DevSkim: ignore DS173237
    let info_hash = InfoHash::from_str(&hash).unwrap();
    env.http_api_container
        .whitelist_manager
        .add_torrent_to_whitelist(&info_hash)
        .await
        .unwrap();

    force_database_error(&env.database);

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .remove_torrent_from_whitelist(&hash, Some(headers_with_request_id(request_id)))
        .await;

    assert_failed_to_remove_torrent_from_whitelist(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    env.stop().await;
}

#[tokio::test]
async fn should_not_allow_removing_a_torrent_from_the_whitelist_for_unauthenticated_users() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let hash = "9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d".to_owned(); // DevSkim: ignore DS173237
    let info_hash = InfoHash::from_str(&hash).unwrap();

    env.http_api_container
        .whitelist_manager
        .add_torrent_to_whitelist(&info_hash)
        .await
        .unwrap();

    let request_id = Uuid::new_v4();

    let response = Client::new(connection_with_invalid_token(env.get_connection_info().origin))
        .remove_torrent_from_whitelist(&hash, Some(headers_with_request_id(request_id)))
        .await;

    assert_token_not_valid(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    env.http_api_container
        .whitelist_manager
        .add_torrent_to_whitelist(&info_hash)
        .await
        .unwrap();

    let request_id = Uuid::new_v4();

    let response = Client::new(connection_with_no_token(env.get_connection_info().origin))
        .remove_torrent_from_whitelist(&hash, Some(headers_with_request_id(request_id)))
        .await;

    assert_unauthorized(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    env.stop().await;
}

#[tokio::test]
async fn should_allow_reload_the_whitelist_from_the_database() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let hash = "9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d".to_owned(); // DevSkim: ignore DS173237
    let info_hash = InfoHash::from_str(&hash).unwrap();
    env.http_api_container
        .whitelist_manager
        .add_torrent_to_whitelist(&info_hash)
        .await
        .unwrap();

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .reload_whitelist(Some(headers_with_request_id(request_id)))
        .await;

    assert_ok(response).await;
    /* todo: this assert fails because the whitelist has not been reloaded yet.
       We could add a new endpoint GET /api/whitelist/:info_hash to check if a torrent
       is whitelisted and use that endpoint to check if the torrent is still there after reloading.
    assert!(
        !(env
            .tracker
            .is_info_hash_whitelisted(&InfoHash::from_str(&info_hash).unwrap())
            .await)
    );
    */

    env.stop().await;
}

#[tokio::test]
async fn should_fail_when_the_whitelist_cannot_be_reloaded_from_the_database() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let hash = "9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d".to_owned(); // DevSkim: ignore DS173237
    let info_hash = InfoHash::from_str(&hash).unwrap();
    env.http_api_container
        .whitelist_manager
        .add_torrent_to_whitelist(&info_hash)
        .await
        .unwrap();

    force_database_error(&env.database);

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .reload_whitelist(Some(headers_with_request_id(request_id)))
        .await;

    assert_failed_to_reload_whitelist(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    env.stop().await;
}
