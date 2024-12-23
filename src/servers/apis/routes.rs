//! API routes.
//!
//! It loads all the API routes for all API versions and adds the authentication
//! middleware to them.
//!
//! All the API routes have the `/api` prefix and the version number as the
//! first path segment. For example: `/api/v1/torrents`.
use std::sync::Arc;
use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use axum::http::HeaderName;
use axum::response::Response;
use axum::routing::get;
use axum::{middleware, BoxError, Router};
use hyper::{Request, StatusCode};
use torrust_tracker_configuration::{AccessTokens, DEFAULT_TIMEOUT};
use tower::timeout::TimeoutLayer;
use tower::ServiceBuilder;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::compression::CompressionLayer;
use tower_http::propagate_header::PropagateHeaderLayer;
use tower_http::request_id::{MakeRequestUuid, SetRequestIdLayer};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tower_http::LatencyUnit;
use tracing::{instrument, Level, Span};

use super::v1;
use super::v1::context::health_check::handlers::health_check_handler;
use super::v1::middlewares::auth::State;
use crate::core::Tracker;
use crate::servers::apis::API_LOG_TARGET;
use crate::servers::logging::Latency;

/// Add all API routes to the router.
#[allow(clippy::needless_pass_by_value)]
#[instrument(skip(tracker, access_tokens))]
pub fn router(tracker: Arc<Tracker>, access_tokens: Arc<AccessTokens>) -> Router {
    let router = Router::new();

    let api_url_prefix = "/api";

    let router = v1::routes::add(api_url_prefix, router, tracker.clone());

    let state = State { access_tokens };

    router
        .layer(middleware::from_fn_with_state(state, v1::middlewares::auth::auth))
        .route(&format!("{api_url_prefix}/health_check"), get(health_check_handler))
        .layer(CompressionLayer::new())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateHeaderLayer::new(HeaderName::from_static("x-request-id")))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(|request: &Request<axum::body::Body>, _span: &Span| {
                    let method = request.method().to_string();
                    let uri = request.uri().to_string();
                    let request_id = request
                        .headers()
                        .get("x-request-id")
                        .map(|v| v.to_str().unwrap_or_default())
                        .unwrap_or_default();

                    tracing::span!(
                        target: API_LOG_TARGET,
                        tracing::Level::INFO, "request", method = %method, uri = %uri, request_id = %request_id);
                })
                .on_response(|response: &Response, latency: Duration, _span: &Span| {
                    let status_code = response.status();
                    let request_id = response
                        .headers()
                        .get("x-request-id")
                        .map(|v| v.to_str().unwrap_or_default())
                        .unwrap_or_default();
                    let latency_ms = latency.as_millis();

                    tracing::span!(
                        target: API_LOG_TARGET,
                        tracing::Level::INFO, "response", latency = %latency_ms, status = %status_code, request_id = %request_id);
                })
                .on_failure(|failure_classification: ServerErrorsFailureClass, latency: Duration, _span: &Span| {
                    let latency = Latency::new(
                        LatencyUnit::Millis,
                        latency,
                    );
                    tracing::error!(target: API_LOG_TARGET, "response failed classification={failure_classification} latency={latency}");
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
