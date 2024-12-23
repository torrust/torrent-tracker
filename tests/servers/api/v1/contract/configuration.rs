// use std::sync::Arc;

// use axum_server::tls_rustls::RustlsConfig;
// use futures::executor::block_on;
// use torrust_tracker_test_helpers::configuration;

// use crate::common::app::setup_with_configuration;
// use crate::servers::api::environment::stopped_environment;

#[tokio::test]
#[ignore]
#[should_panic = "Could not receive bind_address."]
async fn should_fail_with_ssl_enabled_and_bad_ssl_config() {
    // let tracker = setup_with_configuration(&Arc::new(configuration::ephemeral()));

    // let config = tracker.config.http_api.clone();

    // let bind_to = config
    //     .bind_address
    //     .parse::<std::net::SocketAddr>()
    //     .expect("Tracker API bind_address invalid.");

    // let tls =
    //     if let (true, Some(cert), Some(key)) = (&true, &Some("bad cert path".to_string()), &Some("bad cert path".to_string())) {
    //         Some(block_on(RustlsConfig::from_pem_file(cert, key)).expect("Could not read tls cert."))
    //     } else {
    //         None
    //     };

    // let env = new_stopped(tracker, bind_to, tls);
    // env.start().await;
}
