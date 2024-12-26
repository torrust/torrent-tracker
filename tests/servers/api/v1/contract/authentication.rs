use torrust_tracker_test_helpers::configuration;
use uuid::Uuid;

use crate::common::http::{Query, QueryParam};
use crate::common::logging::{self, logs_contains_a_line_with};
use crate::servers::api::v1::asserts::{assert_token_not_valid, assert_unauthorized};
use crate::servers::api::v1::client::{headers_with_request_id, Client};
use crate::servers::api::Started;

#[tokio::test]
async fn should_authenticate_requests_by_using_a_token_query_param() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let token = env.get_connection_info().api_token.unwrap();

    let response = Client::new(env.get_connection_info())
        .get_request_with_query("stats", Query::params([QueryParam::new("token", &token)].to_vec()), None)
        .await;

    assert_eq!(response.status(), 200);

    env.stop().await;
}

#[tokio::test]
async fn should_not_authenticate_requests_when_the_token_is_missing() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let response = Client::new(env.get_connection_info())
        .get_request_with_query("stats", Query::default(), None)
        .await;

    assert_unauthorized(response).await;

    env.stop().await;
}

#[tokio::test]
async fn should_not_authenticate_requests_when_the_token_is_empty() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .get_request_with_query(
            "stats",
            Query::params([QueryParam::new("token", "")].to_vec()),
            Some(headers_with_request_id(request_id)),
        )
        .await;

    assert_token_not_valid(response).await;

    env.stop().await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );
}

#[tokio::test]
async fn should_not_authenticate_requests_when_the_token_is_invalid() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let response = Client::new(env.get_connection_info())
        .get_request_with_query(
            "stats",
            Query::params([QueryParam::new("token", "INVALID TOKEN")].to_vec()),
            None,
        )
        .await;

    assert_token_not_valid(response).await;

    env.stop().await;
}

#[tokio::test]
async fn should_allow_the_token_query_param_to_be_at_any_position_in_the_url_query() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let token = env.get_connection_info().api_token.unwrap();

    // At the beginning of the query component
    let response = Client::new(env.get_connection_info())
        .get_request(&format!("torrents?token={token}&limit=1"))
        .await;

    assert_eq!(response.status(), 200);

    // At the end of the query component
    let response = Client::new(env.get_connection_info())
        .get_request(&format!("torrents?limit=1&token={token}"))
        .await;

    assert_eq!(response.status(), 200);

    env.stop().await;
}
