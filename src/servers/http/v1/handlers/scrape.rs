//! Axum [`handlers`](axum#handlers) for the `announce` requests.
//!
//! Refer to [HTTP server](crate::servers::http) for more information about the
//! `scrape` request.
//!
//! The handlers perform the authentication and authorization of the request,
//! and resolve the client IP address.
use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use bittorrent_http_protocol::v1::requests::scrape::Scrape;
use bittorrent_http_protocol::v1::responses;
use bittorrent_http_protocol::v1::services::peer_ip_resolver::{self, ClientIpSources};
use hyper::StatusCode;
use torrust_tracker_configuration::Core;
use torrust_tracker_primitives::core::ScrapeData;

use crate::core::authentication::service::AuthenticationService;
use crate::core::authentication::Key;
use crate::core::scrape_handler::ScrapeHandler;
use crate::core::statistics::event::sender::Sender;
use crate::servers::http::v1::extractors::authentication_key::Extract as ExtractKey;
use crate::servers::http::v1::extractors::client_ip_sources::Extract as ExtractClientIpSources;
use crate::servers::http::v1::extractors::scrape_request::ExtractRequest;
use crate::servers::http::v1::services;

/// It handles the `scrape` request when the HTTP tracker is configured
/// to run in `public` mode.
#[allow(clippy::unused_async)]
#[allow(clippy::type_complexity)]
pub async fn handle_without_key(
    State(state): State<(
        Arc<Core>,
        Arc<ScrapeHandler>,
        Arc<AuthenticationService>,
        Arc<Option<Box<dyn Sender>>>,
    )>,
    ExtractRequest(scrape_request): ExtractRequest,
    ExtractClientIpSources(client_ip_sources): ExtractClientIpSources,
) -> Response {
    tracing::debug!("http scrape request: {:#?}", &scrape_request);

    handle(
        &state.0,
        &state.1,
        &state.2,
        &state.3,
        &scrape_request,
        &client_ip_sources,
        None,
    )
    .await
}

/// It handles the `scrape` request when the HTTP tracker is configured
/// to run in `private` or `private_listed` mode.
///
/// In this case, the authentication `key` parameter is required.
#[allow(clippy::unused_async)]
#[allow(clippy::type_complexity)]
pub async fn handle_with_key(
    State(state): State<(
        Arc<Core>,
        Arc<ScrapeHandler>,
        Arc<AuthenticationService>,
        Arc<Option<Box<dyn Sender>>>,
    )>,
    ExtractRequest(scrape_request): ExtractRequest,
    ExtractClientIpSources(client_ip_sources): ExtractClientIpSources,
    ExtractKey(key): ExtractKey,
) -> Response {
    tracing::debug!("http scrape request: {:#?}", &scrape_request);

    handle(
        &state.0,
        &state.1,
        &state.2,
        &state.3,
        &scrape_request,
        &client_ip_sources,
        Some(key),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle(
    core_config: &Arc<Core>,
    scrape_handler: &Arc<ScrapeHandler>,
    authentication_service: &Arc<AuthenticationService>,
    stats_event_sender: &Arc<Option<Box<dyn Sender>>>,
    scrape_request: &Scrape,
    client_ip_sources: &ClientIpSources,
    maybe_key: Option<Key>,
) -> Response {
    let scrape_data = match handle_scrape(
        core_config,
        scrape_handler,
        authentication_service,
        stats_event_sender,
        scrape_request,
        client_ip_sources,
        maybe_key,
    )
    .await
    {
        Ok(scrape_data) => scrape_data,
        Err(error) => return (StatusCode::OK, error.write()).into_response(),
    };
    build_response(scrape_data)
}

/* code-review: authentication, authorization and peer IP resolution could be moved
   from the handler (Axum) layer into the app layer `services::announce::invoke`.
   That would make the handler even simpler and the code more reusable and decoupled from Axum.
   See https://github.com/torrust/torrust-tracker/discussions/240.
*/

#[allow(clippy::too_many_arguments)]
async fn handle_scrape(
    core_config: &Arc<Core>,
    scrape_handler: &Arc<ScrapeHandler>,
    authentication_service: &Arc<AuthenticationService>,
    opt_stats_event_sender: &Arc<Option<Box<dyn Sender>>>,
    scrape_request: &Scrape,
    client_ip_sources: &ClientIpSources,
    maybe_key: Option<Key>,
) -> Result<ScrapeData, responses::error::Error> {
    // Authentication
    let return_real_scrape_data = if core_config.private {
        match maybe_key {
            Some(key) => match authentication_service.authenticate(&key).await {
                Ok(()) => true,
                Err(_error) => false,
            },
            None => false,
        }
    } else {
        true
    };

    // Authorization for scrape requests is handled at the `Tracker` level
    // for each torrent.

    let peer_ip = match peer_ip_resolver::invoke(core_config.net.on_reverse_proxy, client_ip_sources) {
        Ok(peer_ip) => peer_ip,
        Err(error) => return Err(responses::error::Error::from(error)),
    };

    if return_real_scrape_data {
        Ok(services::scrape::invoke(scrape_handler, opt_stats_event_sender, &scrape_request.info_hashes, &peer_ip).await)
    } else {
        Ok(services::scrape::fake(opt_stats_event_sender, &scrape_request.info_hashes, &peer_ip).await)
    }
}

fn build_response(scrape_data: ScrapeData) -> Response {
    let response = responses::scrape::Bencoded::from(scrape_data);

    (StatusCode::OK, response.body()).into_response()
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::Arc;

    use bittorrent_http_protocol::v1::requests::scrape::Scrape;
    use bittorrent_http_protocol::v1::responses;
    use bittorrent_http_protocol::v1::services::peer_ip_resolver::ClientIpSources;
    use bittorrent_primitives::info_hash::InfoHash;
    use torrust_tracker_configuration::{Configuration, Core};
    use torrust_tracker_test_helpers::configuration;

    use crate::core::authentication::key::repository::in_memory::InMemoryKeyRepository;
    use crate::core::authentication::service::AuthenticationService;
    use crate::core::scrape_handler::ScrapeHandler;
    use crate::core::services::statistics;
    use crate::core::torrent::repository::in_memory::InMemoryTorrentRepository;
    use crate::core::whitelist::authorization::WhitelistAuthorization;
    use crate::core::whitelist::repository::in_memory::InMemoryWhitelist;

    struct CoreTrackerServices {
        pub core_config: Arc<Core>,
        pub scrape_handler: Arc<ScrapeHandler>,
        pub stats_event_sender: Arc<Option<Box<dyn crate::core::statistics::event::sender::Sender>>>,
        pub authentication_service: Arc<AuthenticationService>,
    }

    fn initialize_private_tracker() -> CoreTrackerServices {
        initialize_core_tracker_services(&configuration::ephemeral_private())
    }

    fn initialize_listed_tracker() -> CoreTrackerServices {
        initialize_core_tracker_services(&configuration::ephemeral_listed())
    }

    fn initialize_tracker_on_reverse_proxy() -> CoreTrackerServices {
        initialize_core_tracker_services(&configuration::ephemeral_with_reverse_proxy())
    }

    fn initialize_tracker_not_on_reverse_proxy() -> CoreTrackerServices {
        initialize_core_tracker_services(&configuration::ephemeral_without_reverse_proxy())
    }

    fn initialize_core_tracker_services(config: &Configuration) -> CoreTrackerServices {
        let core_config = Arc::new(config.core.clone());
        let in_memory_whitelist = Arc::new(InMemoryWhitelist::default());
        let whitelist_authorization = Arc::new(WhitelistAuthorization::new(&config.core, &in_memory_whitelist.clone()));
        let in_memory_key_repository = Arc::new(InMemoryKeyRepository::default());
        let authentication_service = Arc::new(AuthenticationService::new(&config.core, &in_memory_key_repository));
        let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());
        let (stats_event_sender, _stats_repository) = statistics::setup::factory(config.core.tracker_usage_statistics);
        let stats_event_sender = Arc::new(stats_event_sender);
        let scrape_handler = Arc::new(ScrapeHandler::new(&whitelist_authorization, &in_memory_torrent_repository));

        CoreTrackerServices {
            core_config,
            scrape_handler,
            stats_event_sender,
            authentication_service,
        }
    }

    fn sample_scrape_request() -> Scrape {
        Scrape {
            info_hashes: vec!["3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap()], // DevSkim: ignore DS173237
        }
    }

    fn sample_client_ip_sources() -> ClientIpSources {
        ClientIpSources {
            right_most_x_forwarded_for: Some(IpAddr::from_str("203.0.113.195").unwrap()),
            connection_info_ip: Some(IpAddr::from_str("203.0.113.196").unwrap()),
        }
    }

    fn assert_error_response(error: &responses::error::Error, error_message: &str) {
        assert!(
            error.failure_reason.contains(error_message),
            "Error response does not contain message: '{error_message}'. Error: {error:?}"
        );
    }

    mod with_tracker_in_private_mode {
        use std::str::FromStr;

        use torrust_tracker_primitives::core::ScrapeData;

        use super::{initialize_private_tracker, sample_client_ip_sources, sample_scrape_request};
        use crate::core::authentication;
        use crate::servers::http::v1::handlers::scrape::handle_scrape;

        #[tokio::test]
        async fn it_should_return_zeroed_swarm_metadata_when_the_authentication_key_is_missing() {
            let core_tracker_services = initialize_private_tracker();

            let scrape_request = sample_scrape_request();
            let maybe_key = None;

            let scrape_data = handle_scrape(
                &core_tracker_services.core_config,
                &core_tracker_services.scrape_handler,
                &core_tracker_services.authentication_service,
                &core_tracker_services.stats_event_sender,
                &scrape_request,
                &sample_client_ip_sources(),
                maybe_key,
            )
            .await
            .unwrap();

            let expected_scrape_data = ScrapeData::zeroed(&scrape_request.info_hashes);

            assert_eq!(scrape_data, expected_scrape_data);
        }

        #[tokio::test]
        async fn it_should_return_zeroed_swarm_metadata_when_the_authentication_key_is_invalid() {
            let core_tracker_services = initialize_private_tracker();

            let scrape_request = sample_scrape_request();
            let unregistered_key = authentication::Key::from_str("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap();
            let maybe_key = Some(unregistered_key);

            let scrape_data = handle_scrape(
                &core_tracker_services.core_config,
                &core_tracker_services.scrape_handler,
                &core_tracker_services.authentication_service,
                &core_tracker_services.stats_event_sender,
                &scrape_request,
                &sample_client_ip_sources(),
                maybe_key,
            )
            .await
            .unwrap();

            let expected_scrape_data = ScrapeData::zeroed(&scrape_request.info_hashes);

            assert_eq!(scrape_data, expected_scrape_data);
        }
    }

    mod with_tracker_in_listed_mode {

        use torrust_tracker_primitives::core::ScrapeData;

        use super::{initialize_listed_tracker, sample_client_ip_sources, sample_scrape_request};
        use crate::servers::http::v1::handlers::scrape::handle_scrape;

        #[tokio::test]
        async fn it_should_return_zeroed_swarm_metadata_when_the_torrent_is_not_whitelisted() {
            let core_tracker_services = initialize_listed_tracker();

            let scrape_request = sample_scrape_request();

            let scrape_data = handle_scrape(
                &core_tracker_services.core_config,
                &core_tracker_services.scrape_handler,
                &core_tracker_services.authentication_service,
                &core_tracker_services.stats_event_sender,
                &scrape_request,
                &sample_client_ip_sources(),
                None,
            )
            .await
            .unwrap();

            let expected_scrape_data = ScrapeData::zeroed(&scrape_request.info_hashes);

            assert_eq!(scrape_data, expected_scrape_data);
        }
    }

    mod with_tracker_on_reverse_proxy {

        use bittorrent_http_protocol::v1::services::peer_ip_resolver::ClientIpSources;

        use super::{initialize_tracker_on_reverse_proxy, sample_scrape_request};
        use crate::servers::http::v1::handlers::scrape::handle_scrape;
        use crate::servers::http::v1::handlers::scrape::tests::assert_error_response;

        #[tokio::test]
        async fn it_should_fail_when_the_right_most_x_forwarded_for_header_ip_is_not_available() {
            let core_tracker_services = initialize_tracker_on_reverse_proxy();

            let client_ip_sources = ClientIpSources {
                right_most_x_forwarded_for: None,
                connection_info_ip: None,
            };

            let response = handle_scrape(
                &core_tracker_services.core_config,
                &core_tracker_services.scrape_handler,
                &core_tracker_services.authentication_service,
                &core_tracker_services.stats_event_sender,
                &sample_scrape_request(),
                &client_ip_sources,
                None,
            )
            .await
            .unwrap_err();

            assert_error_response(
                &response,
                "Error resolving peer IP: missing or invalid the right most X-Forwarded-For IP",
            );
        }
    }

    mod with_tracker_not_on_reverse_proxy {

        use bittorrent_http_protocol::v1::services::peer_ip_resolver::ClientIpSources;

        use super::{initialize_tracker_not_on_reverse_proxy, sample_scrape_request};
        use crate::servers::http::v1::handlers::scrape::handle_scrape;
        use crate::servers::http::v1::handlers::scrape::tests::assert_error_response;

        #[tokio::test]
        async fn it_should_fail_when_the_client_ip_from_the_connection_info_is_not_available() {
            let core_tracker_services = initialize_tracker_not_on_reverse_proxy();

            let client_ip_sources = ClientIpSources {
                right_most_x_forwarded_for: None,
                connection_info_ip: None,
            };

            let response = handle_scrape(
                &core_tracker_services.core_config,
                &core_tracker_services.scrape_handler,
                &core_tracker_services.authentication_service,
                &core_tracker_services.stats_event_sender,
                &sample_scrape_request(),
                &client_ip_sources,
                None,
            )
            .await
            .unwrap_err();

            assert_error_response(
                &response,
                "Error resolving peer IP: cannot get the client IP from the connection info",
            );
        }
    }
}
