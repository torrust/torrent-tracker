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
use crate::core::Tracker;
use crate::servers::http::HTTP_TRACKER_LOG_TARGET;
use crate::servers::logging::Latency;

/// It adds the routes to the router.
///
/// > **NOTICE**: it's added a layer to get the client IP from the connection
/// > info. The tracker could use the connection info to get the client IP.
#[allow(clippy::needless_pass_by_value)]
#[instrument(skip(tracker, server_socket_addr))]
pub fn router(tracker: Arc<Tracker>, server_socket_addr: SocketAddr) -> Router {
    Router::new()
        // Health check
        .route("/health_check", get(health_check::handler))
        // Announce request
        .route("/announce", get(announce::handle_without_key).with_state(tracker.clone()))
        .route("/announce/:key", get(announce::handle_with_key).with_state(tracker.clone()))
        // Scrape request
        .route("/scrape", get(scrape::handle_without_key).with_state(tracker.clone()))
        .route("/scrape/:key", get(scrape::handle_with_key).with_state(tracker))
        // Add extension to get the client IP from the connection info
        .layer(SecureClientIpSource::ConnectInfo.into_extension())
        .layer(CompressionLayer::new())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateHeaderLayer::new(HeaderName::from_static("x-request-id")))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(move |request: &Request<axum::body::Body>, _span: &Span| {
                    let method = request.method().to_string();
                    let uri = request.uri().to_string();
                    let request_id = request
                        .headers()
                        .get("x-request-id")
                        .map(|v| v.to_str().unwrap_or_default())
                        .unwrap_or_default();

                    tracing::span!(
                        target: HTTP_TRACKER_LOG_TARGET,
                        tracing::Level::INFO, "request", server_socket_addr= %server_socket_addr, method = %method, uri = %uri, request_id = %request_id);
                })
                .on_response(move |response: &Response, latency: Duration, _span: &Span| {
                    let status_code = response.status();
                    let request_id = response
                        .headers()
                        .get("x-request-id")
                        .map(|v| v.to_str().unwrap_or_default())
                        .unwrap_or_default();
                    let latency_ms = latency.as_millis();

                    tracing::span!(
                        target: HTTP_TRACKER_LOG_TARGET,
                        tracing::Level::INFO, "response", server_socket_addr= %server_socket_addr, latency = %latency_ms, status = %status_code, request_id = %request_id);
                })
                .on_failure(|failure_classification: ServerErrorsFailureClass, latency: Duration, _span: &Span| {
                    let latency = Latency::new(
                        LatencyUnit::Millis,
                        latency,
                    );
                    tracing::error!(target: HTTP_TRACKER_LOG_TARGET, "response failed classification={failure_classification} latency={latency}");
                })
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
