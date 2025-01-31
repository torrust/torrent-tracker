//! Axum [`handlers`](axum#handlers) for the `announce` requests.
//!
//! Refer to [HTTP server](crate::servers::http) for more information about the
//! `announce` request.
//!
//! The handlers perform the authentication and authorization of the request,
//! and resolve the client IP address.
use std::net::{IpAddr, SocketAddr};
use std::panic::Location;
use std::sync::Arc;

use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use bittorrent_http_protocol::v1::requests::announce::{Announce, Compact, Event};
use bittorrent_http_protocol::v1::responses::{self};
use bittorrent_http_protocol::v1::services::peer_ip_resolver;
use bittorrent_http_protocol::v1::services::peer_ip_resolver::ClientIpSources;
use bittorrent_tracker_core::announce_handler::{AnnounceHandler, PeersWanted};
use bittorrent_tracker_core::authentication::service::AuthenticationService;
use bittorrent_tracker_core::authentication::Key;
use bittorrent_tracker_core::whitelist;
use hyper::StatusCode;
use torrust_tracker_clock::clock::Time;
use torrust_tracker_configuration::Core;
use torrust_tracker_primitives::core::AnnounceData;
use torrust_tracker_primitives::peer;

use super::common::auth::map_auth_error_to_error_response;
use crate::packages::http_tracker_core;
use crate::servers::http::v1::extractors::announce_request::ExtractRequest;
use crate::servers::http::v1::extractors::authentication_key::Extract as ExtractKey;
use crate::servers::http::v1::extractors::client_ip_sources::Extract as ExtractClientIpSources;
use crate::servers::http::v1::handlers::common::auth;
use crate::servers::http::v1::services::{self};
use crate::CurrentClock;

/// It handles the `announce` request when the HTTP tracker does not require
/// authentication (no PATH `key` parameter required).
#[allow(clippy::unused_async)]
#[allow(clippy::type_complexity)]
pub async fn handle_without_key(
    State(state): State<(
        Arc<Core>,
        Arc<AnnounceHandler>,
        Arc<AuthenticationService>,
        Arc<whitelist::authorization::WhitelistAuthorization>,
        Arc<Option<Box<dyn http_tracker_core::statistics::event::sender::Sender>>>,
    )>,
    ExtractRequest(announce_request): ExtractRequest,
    ExtractClientIpSources(client_ip_sources): ExtractClientIpSources,
) -> Response {
    tracing::debug!("http announce request: {:#?}", announce_request);

    handle(
        &state.0,
        &state.1,
        &state.2,
        &state.3,
        &state.4,
        &announce_request,
        &client_ip_sources,
        None,
    )
    .await
}

/// It handles the `announce` request when the HTTP tracker requires
/// authentication (PATH `key` parameter required).
#[allow(clippy::unused_async)]
#[allow(clippy::type_complexity)]
pub async fn handle_with_key(
    State(state): State<(
        Arc<Core>,
        Arc<AnnounceHandler>,
        Arc<AuthenticationService>,
        Arc<whitelist::authorization::WhitelistAuthorization>,
        Arc<Option<Box<dyn http_tracker_core::statistics::event::sender::Sender>>>,
    )>,
    ExtractRequest(announce_request): ExtractRequest,
    ExtractClientIpSources(client_ip_sources): ExtractClientIpSources,
    ExtractKey(key): ExtractKey,
) -> Response {
    tracing::debug!("http announce request: {:#?}", announce_request);

    handle(
        &state.0,
        &state.1,
        &state.2,
        &state.3,
        &state.4,
        &announce_request,
        &client_ip_sources,
        Some(key),
    )
    .await
}

/// It handles the `announce` request.
///
/// Internal implementation that handles both the `authenticated` and
/// `unauthenticated` modes.
#[allow(clippy::too_many_arguments)]
async fn handle(
    config: &Arc<Core>,
    announce_handler: &Arc<AnnounceHandler>,
    authentication_service: &Arc<AuthenticationService>,
    whitelist_authorization: &Arc<whitelist::authorization::WhitelistAuthorization>,
    opt_http_stats_event_sender: &Arc<Option<Box<dyn http_tracker_core::statistics::event::sender::Sender>>>,
    announce_request: &Announce,
    client_ip_sources: &ClientIpSources,
    maybe_key: Option<Key>,
) -> Response {
    let announce_data = match handle_announce(
        config,
        announce_handler,
        authentication_service,
        whitelist_authorization,
        opt_http_stats_event_sender,
        announce_request,
        client_ip_sources,
        maybe_key,
    )
    .await
    {
        Ok(announce_data) => announce_data,
        Err(error) => return (StatusCode::OK, error.write()).into_response(),
    };
    build_response(announce_request, announce_data)
}

/* code-review: authentication, authorization and peer IP resolution could be moved
   from the handler (Axum) layer into the app layer `services::announce::invoke`.
   That would make the handler even simpler and the code more reusable and decoupled from Axum.
   See https://github.com/torrust/torrust-tracker/discussions/240.
*/

#[allow(clippy::too_many_arguments)]
async fn handle_announce(
    core_config: &Arc<Core>,
    announce_handler: &Arc<AnnounceHandler>,
    authentication_service: &Arc<AuthenticationService>,
    whitelist_authorization: &Arc<whitelist::authorization::WhitelistAuthorization>,
    opt_http_stats_event_sender: &Arc<Option<Box<dyn http_tracker_core::statistics::event::sender::Sender>>>,
    announce_request: &Announce,
    client_ip_sources: &ClientIpSources,
    maybe_key: Option<Key>,
) -> Result<AnnounceData, responses::error::Error> {
    // Authentication
    if core_config.private {
        match maybe_key {
            Some(key) => match authentication_service.authenticate(&key).await {
                Ok(()) => (),
                Err(error) => return Err(map_auth_error_to_error_response(&error)),
            },
            None => {
                return Err(responses::error::Error::from(auth::Error::MissingAuthKey {
                    location: Location::caller(),
                }))
            }
        }
    }

    // Authorization
    match whitelist_authorization.authorize(&announce_request.info_hash).await {
        Ok(()) => (),
        Err(error) => return Err(responses::error::Error::from(error)),
    }

    let peer_ip = match peer_ip_resolver::invoke(core_config.net.on_reverse_proxy, client_ip_sources) {
        Ok(peer_ip) => peer_ip,
        Err(error) => return Err(responses::error::Error::from(error)),
    };

    let mut peer = peer_from_request(announce_request, &peer_ip);
    let peers_wanted = match announce_request.numwant {
        Some(numwant) => PeersWanted::only(numwant),
        None => PeersWanted::All,
    };

    let announce_data = services::announce::invoke(
        announce_handler.clone(),
        opt_http_stats_event_sender.clone(),
        announce_request.info_hash,
        &mut peer,
        &peers_wanted,
    )
    .await;

    Ok(announce_data)
}

fn build_response(announce_request: &Announce, announce_data: AnnounceData) -> Response {
    if announce_request.compact.as_ref().is_some_and(|f| *f == Compact::Accepted) {
        let response: responses::Announce<responses::Compact> = announce_data.into();
        let bytes: Vec<u8> = response.data.into();
        (StatusCode::OK, bytes).into_response()
    } else {
        let response: responses::Announce<responses::Normal> = announce_data.into();
        let bytes: Vec<u8> = response.data.into();
        (StatusCode::OK, bytes).into_response()
    }
}

/// It builds a `Peer` from the announce request.
///
/// It ignores the peer address in the announce request params.
#[must_use]
fn peer_from_request(announce_request: &Announce, peer_ip: &IpAddr) -> peer::Peer {
    peer::Peer {
        peer_id: announce_request.peer_id,
        peer_addr: SocketAddr::new(*peer_ip, announce_request.port),
        updated: CurrentClock::now(),
        uploaded: announce_request.uploaded.unwrap_or(NumberOfBytes::new(0)),
        downloaded: announce_request.downloaded.unwrap_or(NumberOfBytes::new(0)),
        left: announce_request.left.unwrap_or(NumberOfBytes::new(0)),
        event: map_to_torrust_event(&announce_request.event),
    }
}

#[must_use]
pub fn map_to_aquatic_event(event: &Option<Event>) -> aquatic_udp_protocol::AnnounceEvent {
    match event {
        Some(event) => match &event {
            Event::Started => aquatic_udp_protocol::AnnounceEvent::Started,
            Event::Stopped => aquatic_udp_protocol::AnnounceEvent::Stopped,
            Event::Completed => aquatic_udp_protocol::AnnounceEvent::Completed,
        },
        None => aquatic_udp_protocol::AnnounceEvent::None,
    }
}

#[must_use]
pub fn map_to_torrust_event(event: &Option<Event>) -> AnnounceEvent {
    match event {
        Some(event) => match &event {
            Event::Started => AnnounceEvent::Started,
            Event::Stopped => AnnounceEvent::Stopped,
            Event::Completed => AnnounceEvent::Completed,
        },
        None => AnnounceEvent::None,
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use aquatic_udp_protocol::PeerId;
    use bittorrent_http_protocol::v1::requests::announce::Announce;
    use bittorrent_http_protocol::v1::responses;
    use bittorrent_http_protocol::v1::services::peer_ip_resolver::ClientIpSources;
    use bittorrent_tracker_core::announce_handler::AnnounceHandler;
    use bittorrent_tracker_core::authentication::key::repository::in_memory::InMemoryKeyRepository;
    use bittorrent_tracker_core::authentication::service::AuthenticationService;
    use bittorrent_tracker_core::core_tests::sample_info_hash;
    use bittorrent_tracker_core::databases::setup::initialize_database;
    use bittorrent_tracker_core::torrent::repository::in_memory::InMemoryTorrentRepository;
    use bittorrent_tracker_core::torrent::repository::persisted::DatabasePersistentTorrentRepository;
    use bittorrent_tracker_core::whitelist::authorization::WhitelistAuthorization;
    use bittorrent_tracker_core::whitelist::repository::in_memory::InMemoryWhitelist;
    use torrust_tracker_configuration::{Configuration, Core};
    use torrust_tracker_test_helpers::configuration;

    use crate::packages::http_tracker_core;

    struct CoreTrackerServices {
        pub core_config: Arc<Core>,
        pub announce_handler: Arc<AnnounceHandler>,
        pub whitelist_authorization: Arc<WhitelistAuthorization>,
        pub authentication_service: Arc<AuthenticationService>,
    }

    struct CoreHttpTrackerServices {
        pub http_stats_event_sender: Arc<Option<Box<dyn http_tracker_core::statistics::event::sender::Sender>>>,
    }

    fn initialize_private_tracker() -> (CoreTrackerServices, CoreHttpTrackerServices) {
        initialize_core_tracker_services(&configuration::ephemeral_private())
    }

    fn initialize_listed_tracker() -> (CoreTrackerServices, CoreHttpTrackerServices) {
        initialize_core_tracker_services(&configuration::ephemeral_listed())
    }

    fn initialize_tracker_on_reverse_proxy() -> (CoreTrackerServices, CoreHttpTrackerServices) {
        initialize_core_tracker_services(&configuration::ephemeral_with_reverse_proxy())
    }

    fn initialize_tracker_not_on_reverse_proxy() -> (CoreTrackerServices, CoreHttpTrackerServices) {
        initialize_core_tracker_services(&configuration::ephemeral_without_reverse_proxy())
    }

    fn initialize_core_tracker_services(config: &Configuration) -> (CoreTrackerServices, CoreHttpTrackerServices) {
        let core_config = Arc::new(config.core.clone());
        let database = initialize_database(config);
        let in_memory_whitelist = Arc::new(InMemoryWhitelist::default());
        let whitelist_authorization = Arc::new(WhitelistAuthorization::new(&config.core, &in_memory_whitelist.clone()));
        let in_memory_key_repository = Arc::new(InMemoryKeyRepository::default());
        let authentication_service = Arc::new(AuthenticationService::new(&config.core, &in_memory_key_repository));
        let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());
        let db_torrent_repository = Arc::new(DatabasePersistentTorrentRepository::new(&database));
        let announce_handler = Arc::new(AnnounceHandler::new(
            &config.core,
            &in_memory_torrent_repository,
            &db_torrent_repository,
        ));

        // HTTP stats
        let (http_stats_event_sender, http_stats_repository) =
            http_tracker_core::statistics::setup::factory(config.core.tracker_usage_statistics);
        let http_stats_event_sender = Arc::new(http_stats_event_sender);
        let _http_stats_repository = Arc::new(http_stats_repository);

        (
            CoreTrackerServices {
                core_config,
                announce_handler,
                whitelist_authorization,
                authentication_service,
            },
            CoreHttpTrackerServices { http_stats_event_sender },
        )
    }

    fn sample_announce_request() -> Announce {
        Announce {
            info_hash: sample_info_hash(),
            peer_id: PeerId(*b"-qB00000000000000001"),
            port: 17548,
            downloaded: None,
            uploaded: None,
            left: None,
            event: None,
            compact: None,
            numwant: None,
        }
    }

    fn sample_client_ip_sources() -> ClientIpSources {
        ClientIpSources {
            right_most_x_forwarded_for: None,
            connection_info_ip: None,
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

        use bittorrent_tracker_core::authentication;

        use super::{initialize_private_tracker, sample_announce_request, sample_client_ip_sources};
        use crate::servers::http::v1::handlers::announce::handle_announce;
        use crate::servers::http::v1::handlers::announce::tests::assert_error_response;

        #[tokio::test]
        async fn it_should_fail_when_the_authentication_key_is_missing() {
            let (core_tracker_services, http_core_tracker_services) = initialize_private_tracker();

            let maybe_key = None;

            let response = handle_announce(
                &core_tracker_services.core_config,
                &core_tracker_services.announce_handler,
                &core_tracker_services.authentication_service,
                &core_tracker_services.whitelist_authorization,
                &http_core_tracker_services.http_stats_event_sender,
                &sample_announce_request(),
                &sample_client_ip_sources(),
                maybe_key,
            )
            .await
            .unwrap_err();

            assert_error_response(
                &response,
                "Authentication error: Missing authentication key param for private tracker",
            );
        }

        #[tokio::test]
        async fn it_should_fail_when_the_authentication_key_is_invalid() {
            let (core_tracker_services, http_core_tracker_services) = initialize_private_tracker();

            let unregistered_key = authentication::Key::from_str("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap();

            let maybe_key = Some(unregistered_key);

            let response = handle_announce(
                &core_tracker_services.core_config,
                &core_tracker_services.announce_handler,
                &core_tracker_services.authentication_service,
                &core_tracker_services.whitelist_authorization,
                &http_core_tracker_services.http_stats_event_sender,
                &sample_announce_request(),
                &sample_client_ip_sources(),
                maybe_key,
            )
            .await
            .unwrap_err();

            assert_error_response(&response, "Authentication error: Failed to read key");
        }
    }

    mod with_tracker_in_listed_mode {

        use super::{initialize_listed_tracker, sample_announce_request, sample_client_ip_sources};
        use crate::servers::http::v1::handlers::announce::handle_announce;
        use crate::servers::http::v1::handlers::announce::tests::assert_error_response;

        #[tokio::test]
        async fn it_should_fail_when_the_announced_torrent_is_not_whitelisted() {
            let (core_tracker_services, http_core_tracker_services) = initialize_listed_tracker();

            let announce_request = sample_announce_request();

            let response = handle_announce(
                &core_tracker_services.core_config,
                &core_tracker_services.announce_handler,
                &core_tracker_services.authentication_service,
                &core_tracker_services.whitelist_authorization,
                &http_core_tracker_services.http_stats_event_sender,
                &announce_request,
                &sample_client_ip_sources(),
                None,
            )
            .await
            .unwrap_err();

            assert_error_response(
                &response,
                &format!(
                    "Tracker error: The torrent: {}, is not whitelisted",
                    announce_request.info_hash
                ),
            );
        }
    }

    mod with_tracker_on_reverse_proxy {

        use bittorrent_http_protocol::v1::services::peer_ip_resolver::ClientIpSources;

        use super::{initialize_tracker_on_reverse_proxy, sample_announce_request};
        use crate::servers::http::v1::handlers::announce::handle_announce;
        use crate::servers::http::v1::handlers::announce::tests::assert_error_response;

        #[tokio::test]
        async fn it_should_fail_when_the_right_most_x_forwarded_for_header_ip_is_not_available() {
            let (core_tracker_services, http_core_tracker_services) = initialize_tracker_on_reverse_proxy();

            let client_ip_sources = ClientIpSources {
                right_most_x_forwarded_for: None,
                connection_info_ip: None,
            };

            let response = handle_announce(
                &core_tracker_services.core_config,
                &core_tracker_services.announce_handler,
                &core_tracker_services.authentication_service,
                &core_tracker_services.whitelist_authorization,
                &http_core_tracker_services.http_stats_event_sender,
                &sample_announce_request(),
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

        use super::{initialize_tracker_not_on_reverse_proxy, sample_announce_request};
        use crate::servers::http::v1::handlers::announce::handle_announce;
        use crate::servers::http::v1::handlers::announce::tests::assert_error_response;

        #[tokio::test]
        async fn it_should_fail_when_the_client_ip_from_the_connection_info_is_not_available() {
            let (core_tracker_services, http_core_tracker_services) = initialize_tracker_not_on_reverse_proxy();

            let client_ip_sources = ClientIpSources {
                right_most_x_forwarded_for: None,
                connection_info_ip: None,
            };

            let response = handle_announce(
                &core_tracker_services.core_config,
                &core_tracker_services.announce_handler,
                &core_tracker_services.authentication_service,
                &core_tracker_services.whitelist_authorization,
                &http_core_tracker_services.http_stats_event_sender,
                &sample_announce_request(),
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
