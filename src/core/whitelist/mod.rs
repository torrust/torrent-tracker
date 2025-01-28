pub mod authorization;
pub mod manager;
pub mod repository;

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

        mod handling_authorization {
            use crate::core::whitelist::tests::{sample_info_hash, whitelisted_tracker};

            #[tokio::test]
            async fn it_should_authorize_the_announce_and_scrape_actions_on_whitelisted_torrents() {
                let (_announce_handler, whitelist_authorization, whitelist_manager, _scrape_handler) = whitelisted_tracker();

                let info_hash = sample_info_hash();

                let result = whitelist_manager.add_torrent_to_whitelist(&info_hash).await;
                assert!(result.is_ok());

                let result = whitelist_authorization.authorize(&info_hash).await;
                assert!(result.is_ok());
            }

            #[tokio::test]
            async fn it_should_not_authorize_the_announce_and_scrape_actions_on_not_whitelisted_torrents() {
                let (_announce_handler, whitelist_authorization, _whitelist_manager, _scrape_handler) = whitelisted_tracker();

                let info_hash = sample_info_hash();

                let result = whitelist_authorization.authorize(&info_hash).await;
                assert!(result.is_err());
            }
        }
    }
}
