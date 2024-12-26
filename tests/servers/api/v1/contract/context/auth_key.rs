use std::time::Duration;

use serde::Serialize;
use torrust_tracker::core::auth::Key;
use torrust_tracker_test_helpers::configuration;
use uuid::Uuid;

use crate::common::logging::{self, logs_contains_a_line_with};
use crate::servers::api::connection_info::{connection_with_invalid_token, connection_with_no_token};
use crate::servers::api::v1::asserts::{
    assert_auth_key_utf8, assert_failed_to_delete_key, assert_failed_to_generate_key, assert_failed_to_reload_keys,
    assert_invalid_auth_key_get_param, assert_invalid_auth_key_post_param, assert_ok, assert_token_not_valid,
    assert_unauthorized, assert_unprocessable_auth_key_duration_param,
};
use crate::servers::api::v1::client::{headers_with_request_id, AddKeyForm, Client};
use crate::servers::api::{force_database_error, Started};

#[tokio::test]
async fn should_allow_generating_a_new_random_auth_key() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .add_auth_key(
            AddKeyForm {
                opt_key: None,
                seconds_valid: Some(60),
            },
            Some(headers_with_request_id(request_id)),
        )
        .await;

    let auth_key_resource = assert_auth_key_utf8(response).await;

    assert!(env
        .tracker
        .authenticate(&auth_key_resource.key.parse::<Key>().unwrap())
        .await
        .is_ok());

    env.stop().await;
}

#[tokio::test]
async fn should_allow_uploading_a_preexisting_auth_key() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .add_auth_key(
            AddKeyForm {
                opt_key: Some("Xc1L4PbQJSFGlrgSRZl8wxSFAuMa21z5".to_string()),
                seconds_valid: Some(60),
            },
            Some(headers_with_request_id(request_id)),
        )
        .await;

    let auth_key_resource = assert_auth_key_utf8(response).await;

    assert!(env
        .tracker
        .authenticate(&auth_key_resource.key.parse::<Key>().unwrap())
        .await
        .is_ok());

    env.stop().await;
}

#[tokio::test]
async fn should_not_allow_generating_a_new_auth_key_for_unauthenticated_users() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let request_id = Uuid::new_v4();

    let response = Client::new(connection_with_invalid_token(env.get_connection_info().bind_address.as_str()))
        .add_auth_key(
            AddKeyForm {
                opt_key: None,
                seconds_valid: Some(60),
            },
            Some(headers_with_request_id(request_id)),
        )
        .await;

    assert_token_not_valid(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    let request_id = Uuid::new_v4();

    let response = Client::new(connection_with_no_token(env.get_connection_info().bind_address.as_str()))
        .add_auth_key(
            AddKeyForm {
                opt_key: None,
                seconds_valid: Some(60),
            },
            Some(headers_with_request_id(request_id)),
        )
        .await;

    assert_unauthorized(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    env.stop().await;
}

#[tokio::test]
async fn should_fail_when_the_auth_key_cannot_be_generated() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    force_database_error(&env.tracker);

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .add_auth_key(
            AddKeyForm {
                opt_key: None,
                seconds_valid: Some(60),
            },
            Some(headers_with_request_id(request_id)),
        )
        .await;

    assert_failed_to_generate_key(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    env.stop().await;
}

#[tokio::test]
async fn should_allow_deleting_an_auth_key() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let seconds_valid = 60;
    let auth_key = env
        .tracker
        .generate_auth_key(Some(Duration::from_secs(seconds_valid)))
        .await
        .unwrap();

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .delete_auth_key(&auth_key.key.to_string(), Some(headers_with_request_id(request_id)))
        .await;

    assert_ok(response).await;

    env.stop().await;
}

#[tokio::test]
async fn should_fail_generating_a_new_auth_key_when_the_provided_key_is_invalid() {
    #[derive(Serialize, Debug)]
    pub struct InvalidAddKeyForm {
        #[serde(rename = "key")]
        pub opt_key: Option<String>,
        pub seconds_valid: u64,
    }

    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let invalid_keys = [
        // "", it returns 404
        // " ", it returns 404
        "-1",                               // Not a string
        "invalid",                          // Invalid string
        "GQEs2ZNcCm9cwEV9dBpcPB5OwNFWFiR",  // Not a 32-char string
        "%QEs2ZNcCm9cwEV9dBpcPB5OwNFWFiRd", // Invalid char.
    ];

    for invalid_key in invalid_keys {
        let request_id = Uuid::new_v4();

        let response = Client::new(env.get_connection_info())
            .post_form(
                "keys",
                &InvalidAddKeyForm {
                    opt_key: Some(invalid_key.to_string()),
                    seconds_valid: 60,
                },
                Some(headers_with_request_id(request_id)),
            )
            .await;

        assert_invalid_auth_key_post_param(response, invalid_key).await;
    }

    env.stop().await;
}

#[tokio::test]
async fn should_fail_generating_a_new_auth_key_when_the_key_duration_is_invalid() {
    #[derive(Serialize, Debug)]
    pub struct InvalidAddKeyForm {
        #[serde(rename = "key")]
        pub opt_key: Option<String>,
        pub seconds_valid: String,
    }

    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let invalid_key_durations = [
        // "", it returns 404
        // " ", it returns 404
        "-1", "text",
    ];

    for invalid_key_duration in invalid_key_durations {
        let request_id = Uuid::new_v4();

        let response = Client::new(env.get_connection_info())
            .post_form(
                "keys",
                &InvalidAddKeyForm {
                    opt_key: None,
                    seconds_valid: invalid_key_duration.to_string(),
                },
                Some(headers_with_request_id(request_id)),
            )
            .await;

        assert_unprocessable_auth_key_duration_param(response, invalid_key_duration).await;
    }

    env.stop().await;
}

#[tokio::test]
async fn should_fail_deleting_an_auth_key_when_the_key_id_is_invalid() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let invalid_auth_keys = [
        // "", it returns a 404
        // " ", it returns a 404
        "0",
        "-1",
        "INVALID AUTH KEY ID",
        "IrweYtVuQPGbG9Jzx1DihcPmJGGpVy8",   // 32 char key cspell:disable-line
        "IrweYtVuQPGbG9Jzx1DihcPmJGGpVy8zs", // 34 char key cspell:disable-line
    ];

    for invalid_auth_key in &invalid_auth_keys {
        let request_id = Uuid::new_v4();

        let response = Client::new(env.get_connection_info())
            .delete_auth_key(invalid_auth_key, Some(headers_with_request_id(request_id)))
            .await;

        assert_invalid_auth_key_get_param(response, invalid_auth_key).await;
    }

    env.stop().await;
}

#[tokio::test]
async fn should_fail_when_the_auth_key_cannot_be_deleted() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let seconds_valid = 60;
    let auth_key = env
        .tracker
        .generate_auth_key(Some(Duration::from_secs(seconds_valid)))
        .await
        .unwrap();

    force_database_error(&env.tracker);

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .delete_auth_key(&auth_key.key.to_string(), Some(headers_with_request_id(request_id)))
        .await;

    assert_failed_to_delete_key(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    env.stop().await;
}

#[tokio::test]
async fn should_not_allow_deleting_an_auth_key_for_unauthenticated_users() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let seconds_valid = 60;

    // Generate new auth key
    let auth_key = env
        .tracker
        .generate_auth_key(Some(Duration::from_secs(seconds_valid)))
        .await
        .unwrap();

    let request_id = Uuid::new_v4();

    let response = Client::new(connection_with_invalid_token(env.get_connection_info().bind_address.as_str()))
        .delete_auth_key(&auth_key.key.to_string(), Some(headers_with_request_id(request_id)))
        .await;

    assert_token_not_valid(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    // Generate new auth key
    let auth_key = env
        .tracker
        .generate_auth_key(Some(Duration::from_secs(seconds_valid)))
        .await
        .unwrap();

    let request_id = Uuid::new_v4();

    let response = Client::new(connection_with_no_token(env.get_connection_info().bind_address.as_str()))
        .delete_auth_key(&auth_key.key.to_string(), Some(headers_with_request_id(request_id)))
        .await;

    assert_unauthorized(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    env.stop().await;
}

#[tokio::test]
async fn should_allow_reloading_keys() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let seconds_valid = 60;
    env.tracker
        .generate_auth_key(Some(Duration::from_secs(seconds_valid)))
        .await
        .unwrap();

    let request_id = Uuid::new_v4();

    let response = Client::new(env.get_connection_info())
        .reload_keys(Some(headers_with_request_id(request_id)))
        .await;

    assert_ok(response).await;

    env.stop().await;
}

#[tokio::test]
async fn should_fail_when_keys_cannot_be_reloaded() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let request_id = Uuid::new_v4();
    let seconds_valid = 60;

    env.tracker
        .generate_auth_key(Some(Duration::from_secs(seconds_valid)))
        .await
        .unwrap();

    force_database_error(&env.tracker);

    let response = Client::new(env.get_connection_info())
        .reload_keys(Some(headers_with_request_id(request_id)))
        .await;

    assert_failed_to_reload_keys(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    env.stop().await;
}

#[tokio::test]
async fn should_not_allow_reloading_keys_for_unauthenticated_users() {
    logging::setup();

    let env = Started::new(&configuration::ephemeral().into()).await;

    let seconds_valid = 60;
    env.tracker
        .generate_auth_key(Some(Duration::from_secs(seconds_valid)))
        .await
        .unwrap();

    let request_id = Uuid::new_v4();

    let response = Client::new(connection_with_invalid_token(env.get_connection_info().bind_address.as_str()))
        .reload_keys(Some(headers_with_request_id(request_id)))
        .await;

    assert_token_not_valid(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    let request_id = Uuid::new_v4();

    let response = Client::new(connection_with_no_token(env.get_connection_info().bind_address.as_str()))
        .reload_keys(Some(headers_with_request_id(request_id)))
        .await;

    assert_unauthorized(response).await;

    assert!(
        logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
        "Expected logs to contain: ERROR ... API ... request_id={request_id}"
    );

    env.stop().await;
}

mod deprecated_generate_key_endpoint {

    use torrust_tracker::core::auth::Key;
    use torrust_tracker_test_helpers::configuration;
    use uuid::Uuid;

    use crate::common::logging::{self, logs_contains_a_line_with};
    use crate::servers::api::connection_info::{connection_with_invalid_token, connection_with_no_token};
    use crate::servers::api::v1::asserts::{
        assert_auth_key_utf8, assert_failed_to_generate_key, assert_invalid_key_duration_param, assert_token_not_valid,
        assert_unauthorized,
    };
    use crate::servers::api::v1::client::{headers_with_request_id, Client};
    use crate::servers::api::{force_database_error, Started};

    #[tokio::test]
    async fn should_allow_generating_a_new_auth_key() {
        logging::setup();

        let env = Started::new(&configuration::ephemeral().into()).await;

        let seconds_valid = 60;

        let response = Client::new(env.get_connection_info())
            .generate_auth_key(seconds_valid, None)
            .await;

        let auth_key_resource = assert_auth_key_utf8(response).await;

        assert!(env
            .tracker
            .authenticate(&auth_key_resource.key.parse::<Key>().unwrap())
            .await
            .is_ok());

        env.stop().await;
    }

    #[tokio::test]
    async fn should_not_allow_generating_a_new_auth_key_for_unauthenticated_users() {
        logging::setup();

        let env = Started::new(&configuration::ephemeral().into()).await;

        let request_id = Uuid::new_v4();
        let seconds_valid = 60;

        let response = Client::new(connection_with_invalid_token(env.get_connection_info().bind_address.as_str()))
            .generate_auth_key(seconds_valid, Some(headers_with_request_id(request_id)))
            .await;

        assert_token_not_valid(response).await;

        let response = Client::new(connection_with_no_token(env.get_connection_info().bind_address.as_str()))
            .generate_auth_key(seconds_valid, None)
            .await;

        assert_unauthorized(response).await;

        env.stop().await;

        assert!(
            logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
            "Expected logs to contain: ERROR ... API ... request_id={request_id}"
        );
    }

    #[tokio::test]
    async fn should_fail_generating_a_new_auth_key_when_the_key_duration_is_invalid() {
        logging::setup();

        let env = Started::new(&configuration::ephemeral().into()).await;

        let invalid_key_durations = [
            // "", it returns 404
            // " ", it returns 404
            "-1", "text",
        ];

        for invalid_key_duration in invalid_key_durations {
            let response = Client::new(env.get_connection_info())
                .post_empty(&format!("key/{invalid_key_duration}"), None)
                .await;

            assert_invalid_key_duration_param(response, invalid_key_duration).await;
        }

        env.stop().await;
    }

    #[tokio::test]
    async fn should_fail_when_the_auth_key_cannot_be_generated() {
        logging::setup();

        let env = Started::new(&configuration::ephemeral().into()).await;

        force_database_error(&env.tracker);

        let request_id = Uuid::new_v4();
        let seconds_valid = 60;
        let response = Client::new(env.get_connection_info())
            .generate_auth_key(seconds_valid, Some(headers_with_request_id(request_id)))
            .await;

        assert_failed_to_generate_key(response).await;

        env.stop().await;

        assert!(
            logs_contains_a_line_with(&["ERROR", "API", &format!("{request_id}")]),
            "Expected logs to contain: ERROR ... API ... request_id={request_id}"
        );
    }
}
