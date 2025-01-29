//! HTTP server routes for version `v1`.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use axum::http::HeaderName;
use axum::response::Response;
use axum::routing::get;
use axum::{BoxError, Router};
use axum_client_ip::SecureClientIpSource;
use hyper::{Request, StatusCode};
use torrust_tracker_configuration::DEFAULT_TIMEOUT;
use tower::timeout::TimeoutLayer;
use tower::ServiceBuilder;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::compression::CompressionLayer;
use tower_http::propagate_header::PropagateHeaderLayer;
use tower_http::request_id::{MakeRequestUuid, SetRequestIdLayer};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tower_http::LatencyUnit;
use tracing::{instrument, Level, Span};

use super::handlers::{announce, health_check, scrape};
use crate::container::HttpTrackerContainer;
use crate::servers::http::HTTP_TRACKER_LOG_TARGET;
use crate::servers::logging::Latency;

/// It adds the routes to the router.
///
/// > **NOTICE**: it's added a layer to get the client IP from the connection
/// > info. The tracker could use the connection info to get the client IP.
#[instrument(skip(http_tracker_container, server_socket_addr))]
pub fn router(http_tracker_container: Arc<HttpTrackerContainer>, server_socket_addr: SocketAddr) -> Router {
    Router::new()
        // Health check
        .route("/health_check", get(health_check::handler))
        // Announce request
        .route(
            "/announce",
            get(announce::handle_without_key).with_state((
                http_tracker_container.core_config.clone(),
                http_tracker_container.announce_handler.clone(),
                http_tracker_container.authentication_service.clone(),
                http_tracker_container.whitelist_authorization.clone(),
                http_tracker_container.stats_event_sender.clone(),
            )),
        )
        .route(
            "/announce/{key}",
            get(announce::handle_with_key).with_state((
                http_tracker_container.core_config.clone(),
                http_tracker_container.announce_handler.clone(),
                http_tracker_container.authentication_service.clone(),
                http_tracker_container.whitelist_authorization.clone(),
                http_tracker_container.stats_event_sender.clone(),
            )),
        )
        // Scrape request
        .route(
            "/scrape",
            get(scrape::handle_without_key).with_state((
                http_tracker_container.core_config.clone(),
                http_tracker_container.scrape_handler.clone(),
                http_tracker_container.authentication_service.clone(),
                http_tracker_container.stats_event_sender.clone(),
            )),
        )
        .route(
            "/scrape/{key}",
            get(scrape::handle_with_key).with_state((
                http_tracker_container.core_config.clone(),
                http_tracker_container.scrape_handler.clone(),
                http_tracker_container.authentication_service.clone(),
                http_tracker_container.stats_event_sender.clone(),
            )),
        )
        // Add extension to get the client IP from the connection info
        .layer(SecureClientIpSource::ConnectInfo.into_extension())
        .layer(CompressionLayer::new())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateHeaderLayer::new(HeaderName::from_static("x-request-id")))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(move |request: &Request<axum::body::Body>, span: &Span| {
                    let method = request.method().to_string();
                    let uri = request.uri().to_string();
                    let request_id = request
                        .headers()
                        .get("x-request-id")
                        .map(|v| v.to_str().unwrap_or_default())
                        .unwrap_or_default();

                    span.record("request_id", request_id);

                    tracing::event!(
                        target: HTTP_TRACKER_LOG_TARGET,
                        tracing::Level::INFO, %server_socket_addr, %method, %uri, %request_id, "request");
                })
                .on_response(move |response: &Response, latency: Duration, span: &Span| {
                    let latency_ms = latency.as_millis();
                    let status_code = response.status();
                    let request_id = response
                        .headers()
                        .get("x-request-id")
                        .map(|v| v.to_str().unwrap_or_default())
                        .unwrap_or_default();

                    span.record("request_id", request_id);

                    if status_code.is_server_error() {
                        tracing::event!(
                            target: HTTP_TRACKER_LOG_TARGET,
                            tracing::Level::ERROR, %server_socket_addr, %latency_ms, %status_code, %request_id, "response");
                    } else {
                        tracing::event!(
                            target: HTTP_TRACKER_LOG_TARGET,
                            tracing::Level::INFO, %server_socket_addr, %latency_ms, %status_code, %request_id, "response");
                    }
                })
                .on_failure(
                    |failure_classification: ServerErrorsFailureClass, latency: Duration, _span: &Span| {
                        let latency = Latency::new(LatencyUnit::Millis, latency);

                        tracing::event!(
                            target: HTTP_TRACKER_LOG_TARGET,
                            tracing::Level::ERROR, %failure_classification, %latency, "response failed");
                    },
                ),
        )
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(
            ServiceBuilder::new()
                // this middleware goes above `TimeoutLayer` because it will receive
                // errors returned by `TimeoutLayer`
                .layer(HandleErrorLayer::new(|_: BoxError| async { StatusCode::REQUEST_TIMEOUT }))
                .layer(TimeoutLayer::new(DEFAULT_TIMEOUT)),
        )
}
