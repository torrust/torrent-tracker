use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::executor::block_on;
use torrust_tracker::bootstrap::app::tracker;
use torrust_tracker::bootstrap::jobs::make_rust_tls;
use torrust_tracker::core::Tracker;
use torrust_tracker::servers::apis::server::{ApiHandle, ApiLauncher};
use torrust_tracker::servers::registar::Registar;
use torrust_tracker::servers::service::{Service, Started, Stopped};
use torrust_tracker_configuration::{Configuration, HttpApi};
use torrust_tracker_primitives::info_hash::InfoHash;
use torrust_tracker_primitives::peer;

use super::connection_info::ConnectionInfo;

pub struct Environment<S: Debug> {
    pub config: Arc<HttpApi>,
    pub tracker: Arc<Tracker>,
    pub registar: Registar,
    pub server: Service<S, ApiLauncher, ApiHandle>,
    pub addr: Option<SocketAddr>,
}

impl<S: Debug> Environment<S> {
    /// Add a torrent to the tracker
    pub async fn add_torrent_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        self.tracker.upsert_peer_and_get_stats(info_hash, peer).await;
    }
}

impl Environment<Stopped> {
    pub fn new(configuration: &Arc<Configuration>) -> Self {
        let tracker = tracker(configuration);

        let config = Arc::new(configuration.http_api.clone());
        let access_tokens = Arc::new(config.access_tokens.clone());

        let addr = config
            .bind_address
            .parse::<std::net::SocketAddr>()
            .expect("Tracker API bind_address invalid.");

        let tls = block_on(make_rust_tls(config.ssl_enabled, &config.ssl_cert_path, &config.ssl_key_path))
            .map(|tls| tls.expect("tls config failed"));

        let stopped = Service::new(ApiLauncher::new(tracker.clone(), access_tokens, addr, tls));

        Self {
            config,
            tracker,
            registar: Registar::default(),
            server: stopped,
            addr: None,
        }
    }

    pub async fn start(self) -> Environment<Started<ApiHandle>> {
        let server = self.server.start().unwrap();

        // reg_form wait for the service to be ready before proceeding
        let () = server
            .reg_form(self.registar.form())
            .await
            .expect("it should register a form");

        let addr = server.listening().await.expect("it should get address");

        Environment {
            config: self.config,
            tracker: self.tracker.clone(),
            registar: self.registar.clone(),
            server,
            addr: Some(addr),
        }
    }
}

impl Environment<Started<ApiHandle>> {
    pub async fn new(configuration: &Arc<Configuration>) -> Self {
        Environment::<Stopped>::new(configuration).start().await
    }

    pub async fn stop(self) -> Environment<Stopped> {
        Environment {
            config: self.config,
            tracker: self.tracker,
            registar: Registar::default(),
            server: self.server.stop().await.unwrap(),
            addr: None,
        }
    }

    pub fn bind_address(&self) -> std::net::SocketAddr {
        self.addr.expect("it should get the listening address")
    }

    pub fn get_connection_info(&self) -> ConnectionInfo {
        ConnectionInfo {
            bind_address: self.bind_address().to_string(),
            api_token: self.config.access_tokens.as_ref().get("admin").cloned(),
        }
    }
}
