//! This file contains only functions used for testing.
use std::sync::Arc;

use torrust_tracker_configuration::Configuration;

use crate::core::authentication::handler::KeysHandler;
use crate::core::authentication::key::repository::in_memory::InMemoryKeyRepository;
use crate::core::authentication::key::repository::persisted::DatabaseKeyRepository;
use crate::core::authentication::service::{self, AuthenticationService};
use crate::core::databases::Database;
use crate::core::services::initialize_database;
use crate::core::torrent::manager::TorrentsManager;
use crate::core::torrent::repository::in_memory::InMemoryTorrentRepository;
use crate::core::torrent::repository::persisted::DatabasePersistentTorrentRepository;
use crate::core::whitelist;
use crate::core::whitelist::repository::in_memory::InMemoryWhitelist;

/// Initialize the tracker dependencies.
#[allow(clippy::type_complexity)]
#[must_use]
pub fn initialize_tracker_dependencies(
    config: &Configuration,
) -> (
    Arc<Box<dyn Database>>,
    Arc<InMemoryWhitelist>,
    Arc<whitelist::authorization::Authorization>,
    Arc<AuthenticationService>,
    Arc<InMemoryTorrentRepository>,
    Arc<DatabasePersistentTorrentRepository>,
    Arc<TorrentsManager>,
) {
    let database = initialize_database(config);
    let in_memory_whitelist = Arc::new(InMemoryWhitelist::default());
    let whitelist_authorization = Arc::new(whitelist::authorization::Authorization::new(
        &config.core,
        &in_memory_whitelist.clone(),
    ));
    let db_key_repository = Arc::new(DatabaseKeyRepository::new(&database));
    let in_memory_key_repository = Arc::new(InMemoryKeyRepository::default());
    let authentication_service = Arc::new(service::AuthenticationService::new(&config.core, &in_memory_key_repository));
    let _keys_handler = Arc::new(KeysHandler::new(
        &db_key_repository.clone(),
        &in_memory_key_repository.clone(),
    ));
    let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());
    let db_torrent_repository = Arc::new(DatabasePersistentTorrentRepository::new(&database));
    let torrents_manager = Arc::new(TorrentsManager::new(
        &config.core,
        &in_memory_torrent_repository,
        &db_torrent_repository,
    ));

    (
        database,
        in_memory_whitelist,
        whitelist_authorization,
        authentication_service,
        in_memory_torrent_repository,
        db_torrent_repository,
        torrents_manager,
    )
}
