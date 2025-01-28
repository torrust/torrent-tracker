use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;

use super::repository::in_memory::InMemoryWhitelist;
use super::repository::persisted::DatabaseWhitelist;
use crate::core::databases;

/// It handles the list of allowed torrents. Only for listed trackers.
pub struct WhiteListManager {
    /// The in-memory list of allowed torrents.
    in_memory_whitelist: Arc<InMemoryWhitelist>,

    /// The persisted list of allowed torrents.
    database_whitelist: Arc<DatabaseWhitelist>,
}

impl WhiteListManager {
    #[must_use]
    pub fn new(database_whitelist: Arc<DatabaseWhitelist>, in_memory_whitelist: Arc<InMemoryWhitelist>) -> Self {
        Self {
            in_memory_whitelist,
            database_whitelist,
        }
    }

    /// It adds a torrent to the whitelist.
    /// Adding torrents is not relevant to public trackers.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `info_hash` into the whitelist database.
    pub async fn add_torrent_to_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        self.database_whitelist.add(info_hash)?;
        self.in_memory_whitelist.add(info_hash).await;
        Ok(())
    }

    /// It removes a torrent from the whitelist.
    /// Removing torrents is not relevant to public trackers.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `info_hash` from the whitelist database.
    pub async fn remove_torrent_from_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        self.database_whitelist.remove(info_hash)?;
        self.in_memory_whitelist.remove(info_hash).await;
        Ok(())
    }

    /// It removes a torrent from the whitelist in the database.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `info_hash` from the whitelist database.
    pub fn remove_torrent_from_database_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        self.database_whitelist.remove(info_hash)
    }

    /// It adds a torrent from the whitelist in memory.
    pub async fn add_torrent_to_memory_whitelist(&self, info_hash: &InfoHash) -> bool {
        self.in_memory_whitelist.add(info_hash).await
    }

    /// It removes a torrent from the whitelist in memory.
    pub async fn remove_torrent_from_memory_whitelist(&self, info_hash: &InfoHash) -> bool {
        self.in_memory_whitelist.remove(info_hash).await
    }

    /// It checks if a torrent is whitelisted.
    pub async fn is_info_hash_whitelisted(&self, info_hash: &InfoHash) -> bool {
        self.in_memory_whitelist.contains(info_hash).await
    }

    /// It loads the whitelist from the database.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to load the list whitelisted `info_hash`s from the database.
    pub async fn load_whitelist_from_database(&self) -> Result<(), databases::error::Error> {
        let whitelisted_torrents_from_database = self.database_whitelist.load_from_database()?;

        self.in_memory_whitelist.clear().await;

        for info_hash in whitelisted_torrents_from_database {
            let _: bool = self.in_memory_whitelist.add(&info_hash).await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use bittorrent_primitives::info_hash::InfoHash;
    use torrust_tracker_test_helpers::configuration;

    use crate::app_test::initialize_tracker_dependencies;
    use crate::core::announce_handler::AnnounceHandler;
    use crate::core::scrape_handler::ScrapeHandler;
    use crate::core::services::initialize_whitelist_manager;
    use crate::core::whitelist;
    use crate::core::whitelist::manager::WhiteListManager;

    #[allow(clippy::type_complexity)]
    fn whitelisted_tracker() -> (
        Arc<AnnounceHandler>,
        Arc<whitelist::authorization::Authorization>,
        Arc<WhiteListManager>,
        Arc<ScrapeHandler>,
    ) {
        let config = configuration::ephemeral_listed();

        let (
            database,
            in_memory_whitelist,
            whitelist_authorization,
            _authentication_service,
            in_memory_torrent_repository,
            db_torrent_repository,
            _torrents_manager,
        ) = initialize_tracker_dependencies(&config);

        let whitelist_manager = initialize_whitelist_manager(database.clone(), in_memory_whitelist.clone());

        let announce_handler = Arc::new(AnnounceHandler::new(
            &config.core,
            &in_memory_torrent_repository,
            &db_torrent_repository,
        ));

        let scrape_handler = Arc::new(ScrapeHandler::new(&whitelist_authorization, &in_memory_torrent_repository));

        (announce_handler, whitelist_authorization, whitelist_manager, scrape_handler)
    }

    fn sample_info_hash() -> InfoHash {
        "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap()
    }

    mod configured_as_whitelisted {

        mod handling_the_torrent_whitelist {
            use crate::core::whitelist::manager::tests::{sample_info_hash, whitelisted_tracker};

            // todo: after extracting the WhitelistManager from the Tracker,
            // there is no need to use the tracker to test the whitelist.
            // Test not using the `tracker` (`_tracker` variable) should be
            // moved to the whitelist module.

            #[tokio::test]
            async fn it_should_add_a_torrent_to_the_whitelist() {
                let (_announce_handler, _whitelist_authorization, whitelist_manager, _scrape_handler) = whitelisted_tracker();

                let info_hash = sample_info_hash();

                whitelist_manager.add_torrent_to_whitelist(&info_hash).await.unwrap();

                assert!(whitelist_manager.is_info_hash_whitelisted(&info_hash).await);
            }

            #[tokio::test]
            async fn it_should_remove_a_torrent_from_the_whitelist() {
                let (_announce_handler, _whitelist_authorization, whitelist_manager, _scrape_handler) = whitelisted_tracker();

                let info_hash = sample_info_hash();

                whitelist_manager.add_torrent_to_whitelist(&info_hash).await.unwrap();

                whitelist_manager.remove_torrent_from_whitelist(&info_hash).await.unwrap();

                assert!(!whitelist_manager.is_info_hash_whitelisted(&info_hash).await);
            }

            mod persistence {
                use crate::core::whitelist::manager::tests::{sample_info_hash, whitelisted_tracker};

                #[tokio::test]
                async fn it_should_load_the_whitelist_from_the_database() {
                    let (_announce_handler, _whitelist_authorization, whitelist_manager, _scrape_handler) = whitelisted_tracker();

                    let info_hash = sample_info_hash();

                    whitelist_manager.add_torrent_to_whitelist(&info_hash).await.unwrap();

                    whitelist_manager.remove_torrent_from_memory_whitelist(&info_hash).await;

                    assert!(!whitelist_manager.is_info_hash_whitelisted(&info_hash).await);

                    whitelist_manager.load_whitelist_from_database().await.unwrap();

                    assert!(whitelist_manager.is_info_hash_whitelisted(&info_hash).await);
                }
            }
        }
    }
}
