use std::net::SocketAddr;
use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use bittorrent_tracker_core::authentication::service::AuthenticationService;
use bittorrent_tracker_core::databases::Database;
use futures::executor::block_on;
use torrust_tracker_api_client::connection_info::{ConnectionInfo, Origin};
use torrust_tracker_configuration::Configuration;
use torrust_tracker_lib::bootstrap::app::{initialize_app_container, initialize_global_services};
use torrust_tracker_lib::bootstrap::jobs::make_rust_tls;
use torrust_tracker_lib::container::HttpApiContainer;
use torrust_tracker_lib::servers::apis::server::{ApiServer, Launcher, Running, Stopped};
use torrust_tracker_lib::servers::registar::Registar;
use torrust_tracker_primitives::peer;

pub struct Environment<S>
where
    S: std::fmt::Debug + std::fmt::Display,
{
    pub http_api_container: Arc<HttpApiContainer>,

    pub database: Arc<Box<dyn Database>>,
    pub authentication_service: Arc<AuthenticationService>,

    pub registar: Registar,
    pub server: ApiServer<S>,
}

impl<S> Environment<S>
where
    S: std::fmt::Debug + std::fmt::Display,
{
    /// Add a torrent to the tracker
    pub fn add_torrent_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        let () = self
            .http_api_container
            .in_memory_torrent_repository
            .upsert_peer(info_hash, peer);
    }
}

impl Environment<Stopped> {
    pub fn new(configuration: &Arc<Configuration>) -> Self {
        initialize_global_services(configuration);

        let app_container = initialize_app_container(configuration);

        let http_api_config = Arc::new(configuration.http_api.clone().expect("missing API configuration"));

        let bind_to = http_api_config.bind_address;

        let tls = block_on(make_rust_tls(&http_api_config.tsl_config)).map(|tls| tls.expect("tls config failed"));

        let server = ApiServer::new(Launcher::new(bind_to, tls));

        let http_api_container = Arc::new(HttpApiContainer {
            http_api_config: http_api_config.clone(),
            core_config: app_container.core_config.clone(),
            in_memory_torrent_repository: app_container.in_memory_torrent_repository.clone(),
            keys_handler: app_container.keys_handler.clone(),
            whitelist_manager: app_container.whitelist_manager.clone(),
            ban_service: app_container.ban_service.clone(),
            http_stats_repository: app_container.http_stats_repository.clone(),
            udp_stats_repository: app_container.udp_stats_repository.clone(),
        });

        Self {
            http_api_container,

            database: app_container.database.clone(),
            authentication_service: app_container.authentication_service.clone(),

            registar: Registar::default(),
            server,
        }
    }

    pub async fn start(self) -> Environment<Running> {
        let access_tokens = Arc::new(self.http_api_container.http_api_config.access_tokens.clone());

        Environment {
            http_api_container: self.http_api_container.clone(),

            database: self.database.clone(),
            authentication_service: self.authentication_service.clone(),

            registar: self.registar.clone(),
            server: self
                .server
                .start(self.http_api_container, self.registar.give_form(), access_tokens)
                .await
                .unwrap(),
        }
    }
}

impl Environment<Running> {
    pub async fn new(configuration: &Arc<Configuration>) -> Self {
        Environment::<Stopped>::new(configuration).start().await
    }

    pub async fn stop(self) -> Environment<Stopped> {
        Environment {
            http_api_container: self.http_api_container,

            database: self.database,
            authentication_service: self.authentication_service,

            registar: Registar::default(),
            server: self.server.stop().await.unwrap(),
        }
    }

    pub fn get_connection_info(&self) -> ConnectionInfo {
        let origin = Origin::new(&format!("http://{}/", self.server.state.local_addr)).unwrap(); // DevSkim: ignore DS137138

        ConnectionInfo {
            origin,
            api_token: self.http_api_container.http_api_config.access_tokens.get("admin").cloned(),
        }
    }

    pub fn bind_address(&self) -> SocketAddr {
        self.server.state.local_addr
    }
}
