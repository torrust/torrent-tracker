//! Module to handle the HTTP server instances.
use std::net::SocketAddr;
use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use derive_more::Constructor;
use futures::future::BoxFuture;
use tokio::sync::oneshot::{Receiver, Sender};
use tracing::instrument;

use super::v1::routes::router;
use crate::bootstrap::jobs::Started;
use crate::core::{statistics, Tracker};
use crate::servers::custom_axum_server::{self, TimeoutAcceptor};
use crate::servers::http::HTTP_TRACKER_LOG_TARGET;
use crate::servers::logging::STARTED_ON;
use crate::servers::registar::{ServiceHealthCheckJob, ServiceRegistration, ServiceRegistrationForm};
use crate::servers::signals::{graceful_shutdown, Halted};

/// Error that can occur when starting or stopping the HTTP server.
///
/// Some errors triggered while starting the server are:
///
/// - The spawned server cannot send its `SocketAddr` back to the main thread.
/// - The launcher cannot receive the `SocketAddr` from the spawned server.
///
/// Some errors triggered while stopping the server are:
///
/// - The channel to send the shutdown signal to the server is closed.
/// - The task to shutdown the server on the spawned server failed to execute to
///   completion.
#[derive(Debug)]
pub enum Error {
    Error(String),
}

#[derive(Constructor, Debug)]
pub struct Launcher {
    pub bind_to: SocketAddr,
    pub tls: Option<RustlsConfig>,
}

impl Launcher {
    #[instrument(skip(self, tracker, stats_event_sender, tx_start, rx_halt))]
    fn start(
        &self,
        tracker: Arc<Tracker>,
        stats_event_sender: Arc<Option<Box<dyn statistics::event::sender::Sender>>>,
        tx_start: Sender<Started>,
        rx_halt: Receiver<Halted>,
    ) -> BoxFuture<'static, ()> {
        let socket = std::net::TcpListener::bind(self.bind_to).expect("Could not bind tcp_listener to address.");
        let address = socket.local_addr().expect("Could not get local_addr from tcp_listener.");

        let handle = Handle::new();

        tokio::task::spawn(graceful_shutdown(
            handle.clone(),
            rx_halt,
            format!("Shutting down HTTP server on socket address: {address}"),
        ));

        let tls = self.tls.clone();
        let protocol = if tls.is_some() { "https" } else { "http" };

        tracing::info!(target: HTTP_TRACKER_LOG_TARGET, "Starting on: {protocol}://{}", address);

        let app = router(tracker, stats_event_sender, address);

        let running = Box::pin(async {
            match tls {
                Some(tls) => custom_axum_server::from_tcp_rustls_with_timeouts(socket, tls)
                    .handle(handle)
                    // The TimeoutAcceptor is commented because TSL does not work with it.
                    // See: https://github.com/torrust/torrust-index/issues/204#issuecomment-2115529214
                    //.acceptor(TimeoutAcceptor)
                    .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                    .await
                    .expect("Axum server crashed."),
                None => custom_axum_server::from_tcp_with_timeouts(socket)
                    .handle(handle)
                    .acceptor(TimeoutAcceptor)
                    .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                    .await
                    .expect("Axum server crashed."),
            }
        });

        tracing::info!(target: HTTP_TRACKER_LOG_TARGET, "{STARTED_ON}: {protocol}://{}", address);

        tx_start
            .send(Started { address })
            .expect("the HTTP(s) Tracker service should not be dropped");

        running
    }
}

/// A HTTP server instance controller with no HTTP instance running.
#[allow(clippy::module_name_repetitions)]
pub type StoppedHttpServer = HttpServer<Stopped>;

/// A HTTP server instance controller with a running HTTP instance.
#[allow(clippy::module_name_repetitions)]
pub type RunningHttpServer = HttpServer<Running>;

/// A HTTP server instance controller.
///
/// It's responsible for:
///
/// - Keeping the initial configuration of the server.
/// - Starting and stopping the server.
/// - Keeping the state of the server: `running` or `stopped`.
///
/// It's an state machine. Configurations cannot be changed. This struct
/// represents concrete configuration and state. It allows to start and stop the
/// server but always keeping the same configuration.
///
/// > **NOTICE**: if the configurations changes after running the server it will
/// > reset to the initial value after stopping the server. This struct is not
/// > intended to persist configurations between runs.
#[allow(clippy::module_name_repetitions)]
pub struct HttpServer<S> {
    /// The state of the server: `running` or `stopped`.
    pub state: S,
}

/// A stopped HTTP server state.
pub struct Stopped {
    launcher: Launcher,
}

/// A running HTTP server state.
pub struct Running {
    /// The address where the server is bound.
    pub binding: SocketAddr,
    pub halt_task: tokio::sync::oneshot::Sender<Halted>,
    pub task: tokio::task::JoinHandle<Launcher>,
}

impl HttpServer<Stopped> {
    /// It creates a new `HttpServer` controller in `stopped` state.
    #[must_use]
    pub fn new(launcher: Launcher) -> Self {
        Self {
            state: Stopped { launcher },
        }
    }

    /// It starts the server and returns a `HttpServer` controller in `running`
    /// state.
    ///
    /// # Errors
    ///
    /// It would return an error if no `SocketAddr` is returned after launching the server.
    ///
    /// # Panics
    ///
    /// It would panic spawned HTTP server launcher cannot send the bound `SocketAddr`
    /// back to the main thread.
    pub async fn start(
        self,
        tracker: Arc<Tracker>,
        stats_event_sender: Arc<Option<Box<dyn statistics::event::sender::Sender>>>,
        form: ServiceRegistrationForm,
    ) -> Result<HttpServer<Running>, Error> {
        let (tx_start, rx_start) = tokio::sync::oneshot::channel::<Started>();
        let (tx_halt, rx_halt) = tokio::sync::oneshot::channel::<Halted>();

        let launcher = self.state.launcher;

        let task = tokio::spawn(async move {
            let server = launcher.start(tracker, stats_event_sender, tx_start, rx_halt);

            server.await;

            launcher
        });

        let binding = rx_start.await.expect("it should be able to start the service").address;

        form.send(ServiceRegistration::new(binding, check_fn))
            .expect("it should be able to send service registration");

        Ok(HttpServer {
            state: Running {
                binding,
                halt_task: tx_halt,
                task,
            },
        })
    }
}

impl HttpServer<Running> {
    /// It stops the server and returns a `HttpServer` controller in `stopped`
    /// state.
    ///
    /// # Errors
    ///
    /// It would return an error if the channel for the task killer signal was closed.
    pub async fn stop(self) -> Result<HttpServer<Stopped>, Error> {
        self.state
            .halt_task
            .send(Halted::Normal)
            .map_err(|_| Error::Error("Task killer channel was closed.".to_string()))?;

        let launcher = self.state.task.await.map_err(|e| Error::Error(e.to_string()))?;

        Ok(HttpServer {
            state: Stopped { launcher },
        })
    }
}

/// Checks the Health by connecting to the HTTP tracker endpoint.
///
/// # Errors
///
/// This function will return an error if unable to connect.
/// Or if the request returns an error.
#[must_use]
pub fn check_fn(binding: &SocketAddr) -> ServiceHealthCheckJob {
    let url = format!("http://{binding}/health_check"); // DevSkim: ignore DS137138

    let info = format!("checking http tracker health check at: {url}");

    let job = tokio::spawn(async move {
        match reqwest::get(url).await {
            Ok(response) => Ok(response.status().to_string()),
            Err(err) => Err(err.to_string()),
        }
    });

    ServiceHealthCheckJob::new(*binding, info, job)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use torrust_tracker_test_helpers::configuration::ephemeral_public;

    use crate::bootstrap::app::{initialize_global_services, initialize_tracker};
    use crate::bootstrap::jobs::make_rust_tls;
    use crate::core::services::statistics;
    use crate::servers::http::server::{HttpServer, Launcher};
    use crate::servers::registar::Registar;

    #[tokio::test]
    async fn it_should_be_able_to_start_and_stop() {
        let cfg = Arc::new(ephemeral_public());

        let (stats_event_sender, _stats_repository) = statistics::setup::factory(cfg.core.tracker_usage_statistics);
        let stats_event_sender = Arc::new(stats_event_sender);

        initialize_global_services(&cfg);
        let tracker = Arc::new(initialize_tracker(&cfg));

        let http_trackers = cfg.http_trackers.clone().expect("missing HTTP trackers configuration");
        let config = &http_trackers[0];

        let bind_to = config.bind_address;

        let tls = make_rust_tls(&config.tsl_config)
            .await
            .map(|tls| tls.expect("tls config failed"));

        let register = &Registar::default();

        let stopped = HttpServer::new(Launcher::new(bind_to, tls));
        let started = stopped
            .start(tracker, stats_event_sender, register.give_form())
            .await
            .expect("it should start the server");
        let stopped = started.stop().await.expect("it should stop the server");

        assert_eq!(stopped.state.launcher.bind_to, bind_to);
    }
}
