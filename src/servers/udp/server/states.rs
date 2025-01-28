use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use derive_more::derive::Display;
use derive_more::Constructor;
use tokio::task::JoinHandle;
use tracing::{instrument, Level};

use super::spawner::Spawner;
use super::{Server, UdpError};
use crate::bootstrap::jobs::Started;
use crate::container::UdpTrackerContainer;
use crate::servers::registar::{ServiceRegistration, ServiceRegistrationForm};
use crate::servers::signals::Halted;
use crate::servers::udp::server::launcher::Launcher;
use crate::servers::udp::UDP_TRACKER_LOG_TARGET;

/// A UDP server instance controller with no UDP instance running.
#[allow(clippy::module_name_repetitions)]
pub type StoppedUdpServer = Server<Stopped>;

/// A UDP server instance controller with a running UDP instance.
#[allow(clippy::module_name_repetitions)]
pub type RunningUdpServer = Server<Running>;

/// A stopped UDP server state.
#[derive(Debug, Display)]
#[display("Stopped: {spawner}")]
pub struct Stopped {
    pub spawner: Spawner,
}

/// A running UDP server state.
#[derive(Debug, Display, Constructor)]
#[display("Running (with local address): {local_addr}")]
pub struct Running {
    /// The address where the server is bound.
    pub local_addr: SocketAddr,
    pub halt_task: tokio::sync::oneshot::Sender<Halted>,
    pub task: JoinHandle<Spawner>,
}

impl Server<Stopped> {
    /// Creates a new `UdpServer` instance in `stopped`state.
    #[must_use]
    pub fn new(spawner: Spawner) -> Self {
        Self {
            state: Stopped { spawner },
        }
    }

    /// It starts the server and returns a `UdpServer` controller in `running`
    /// state.
    ///
    /// # Errors
    ///
    /// Will return `Err` if UDP can't bind to given bind address.
    ///
    /// # Panics
    ///
    /// It panics if unable to receive the bound socket address from service.
    #[instrument(skip(self, udp_tracker_container, form), err, ret(Display, level = Level::INFO))]
    pub async fn start(
        self,
        udp_tracker_container: Arc<UdpTrackerContainer>,
        form: ServiceRegistrationForm,
        cookie_lifetime: Duration,
    ) -> Result<Server<Running>, std::io::Error> {
        let (tx_start, rx_start) = tokio::sync::oneshot::channel::<Started>();
        let (tx_halt, rx_halt) = tokio::sync::oneshot::channel::<Halted>();

        assert!(!tx_halt.is_closed(), "Halt channel for UDP tracker should be open");

        // May need to wrap in a task to about a tokio bug.
        let task = self
            .state
            .spawner
            .spawn_launcher(udp_tracker_container, cookie_lifetime, tx_start, rx_halt);

        let local_addr = rx_start.await.expect("it should be able to start the service").address;

        form.send(ServiceRegistration::new(local_addr, Launcher::check))
            .expect("it should be able to send service registration");

        let running_udp_server: Server<Running> = Server {
            state: Running {
                local_addr,
                halt_task: tx_halt,
                task,
            },
        };

        let local_addr = format!("udp://{local_addr}");
        tracing::trace!(target: UDP_TRACKER_LOG_TARGET, local_addr, "UdpServer<Stopped>::start (running)");

        Ok(running_udp_server)
    }
}

impl Server<Running> {
    /// It stops the server and returns a `UdpServer` controller in `stopped`
    /// state.
    ///     
    /// # Errors
    ///
    /// Will return `Err` if the oneshot channel to send the stop signal
    /// has already been called once.
    ///
    /// # Panics
    ///
    /// It panics if unable to shutdown service.
    #[instrument(skip(self), err, ret(Display, level = Level::INFO))]
    pub async fn stop(self) -> Result<Server<Stopped>, UdpError> {
        self.state
            .halt_task
            .send(Halted::Normal)
            .map_err(|e| UdpError::FailedToStartOrStopServer(e.to_string()))?;

        let launcher = self.state.task.await.expect("it should shutdown service");

        let stopped_api_server: Server<Stopped> = Server {
            state: Stopped { spawner: launcher },
        };

        Ok(stopped_api_server)
    }
}
