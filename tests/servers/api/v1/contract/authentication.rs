use torrust_tracker_test_helpers::configuration;

use crate::common::http::{Query, QueryParam};
use crate::servers::api::v1::asserts::{assert_token_not_valid, assert_unauthorized};
use crate::servers::api::v1::client::Client;
use crate::servers::api::Started;

#[tokio::test]
async fn should_authenticate_requests_by_using_a_token_query_param() {
    let env = Started::new(&configuration::ephemeral().into()).await;

    let token = env.get_connection_info().api_token.unwrap();

    let response = Client::new(env.get_connection_info())
        .get_request_with_query("stats", Query::params([QueryParam::new("token", &token)].to_vec()))
        .await;

    assert_eq!(response.status(), 200);

    env.stop().await;
}

#[tokio::test]
async fn should_not_authenticate_requests_when_the_token_is_missing() {
    let env = Started::new(&configuration::ephemeral().into()).await;

    let response = Client::new(env.get_connection_info())
        .get_request_with_query("stats", Query::default())
        .await;

    assert_unauthorized(response).await;

    env.stop().await;
}

#[tokio::test]
async fn should_not_authenticate_requests_when_the_token_is_empty() {
    let env = Started::new(&configuration::ephemeral().into()).await;

    let response = Client::new(env.get_connection_info())
        .get_request_with_query("stats", Query::params([QueryParam::new("token", "")].to_vec()))
        .await;

    assert_token_not_valid(response).await;

    env.stop().await;
}

#[tokio::test]
async fn should_not_authenticate_requests_when_the_token_is_invalid() {
    let env = Started::new(&configuration::ephemeral().into()).await;

    let response = Client::new(env.get_connection_info())
        .get_request_with_query("stats", Query::params([QueryParam::new("token", "INVALID TOKEN")].to_vec()))
        .await;

    assert_token_not_valid(response).await;

    env.stop().await;
}

#[tokio::test]
async fn should_allow_the_token_query_param_to_be_at_any_position_in_the_url_query() {
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
