use std::sync::Arc;

use tokio::sync::RwLock;

use crate::core::authentication::service::AuthenticationService;
use crate::core::statistics::event::sender::Sender;
use crate::core::statistics::repository::Repository;
use crate::core::whitelist::manager::WhiteListManager;
use crate::core::{authentication, whitelist, Tracker};
use crate::servers::udp::server::banning::BanService;

pub struct AppContainer {
    pub tracker: Arc<Tracker>,
    pub authentication_service: Arc<AuthenticationService>,
    pub whitelist_authorization: Arc<whitelist::authorization::Authorization>,
    pub ban_service: Arc<RwLock<BanService>>,
    pub stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    pub stats_repository: Arc<Repository>,
    pub whitelist_manager: Arc<WhiteListManager>,
    pub authentication: Arc<authentication::Facade>,
}
