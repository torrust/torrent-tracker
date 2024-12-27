use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::oneshot::{self, Sender};
use tokio::task::JoinHandle;
use torrust_tracker_configuration::HealthCheckApi;
use torrust_tracker_lib::bootstrap::jobs::Started;
use torrust_tracker_lib::servers::health_check_api::{server, HEALTH_CHECK_API_LOG_TARGET};
use torrust_tracker_lib::servers::registar::Registar;
use torrust_tracker_lib::servers::signals::{self, Halted};

#[derive(Debug)]
pub enum Error {
    #[allow(dead_code)]
    Error(String),
}

pub struct Running {
    pub binding: SocketAddr,
    pub halt_task: Sender<signals::Halted>,
    pub task: JoinHandle<SocketAddr>,
}

pub struct Stopped {
    pub bind_to: SocketAddr,
}

pub struct Environment<S> {
    pub registar: Registar,
    pub state: S,
}

impl Environment<Stopped> {
    pub fn new(config: &Arc<HealthCheckApi>, registar: Registar) -> Self {
        let bind_to = config.bind_address;

        Self {
            registar,
            state: Stopped { bind_to },
        }
    }

    /// Start the test environment for the Health Check API.
    /// It runs the API server.
    pub async fn start(self) -> Environment<Running> {
        let (tx_start, rx_start) = oneshot::channel::<Started>();
        let (tx_halt, rx_halt) = tokio::sync::oneshot::channel::<Halted>();

        let register = self.registar.entries();

        tracing::debug!(target: HEALTH_CHECK_API_LOG_TARGET, "Spawning task to launch the service ...");

        let server = tokio::spawn(async move {
            tracing::debug!(target: HEALTH_CHECK_API_LOG_TARGET, "Starting the server in a spawned task ...");

            server::start(self.state.bind_to, tx_start, rx_halt, register)
                .await
                .expect("it should start the health check service");

            tracing::debug!(target: HEALTH_CHECK_API_LOG_TARGET, "Server started. Sending the binding {} ...", self.state.bind_to);

            self.state.bind_to
        });

        tracing::debug!(target: HEALTH_CHECK_API_LOG_TARGET, "Waiting for spawning task to send the binding ...");

        let binding = rx_start.await.expect("it should send service binding").address;

        Environment {
            registar: self.registar.clone(),
            state: Running {
                task: server,
                halt_task: tx_halt,
                binding,
            },
        }
    }
}

impl Environment<Running> {
    pub async fn new(config: &Arc<HealthCheckApi>, registar: Registar) -> Self {
        Environment::<Stopped>::new(config, registar).start().await
    }

    pub async fn stop(self) -> Result<Environment<Stopped>, Error> {
        self.state
            .halt_task
            .send(Halted::Normal)
            .map_err(|e| Error::Error(e.to_string()))?;

        let bind_to = self.state.task.await.expect("it should shutdown the service");

        Ok(Environment {
            registar: self.registar.clone(),
            state: Stopped { bind_to },
        })
    }
}
