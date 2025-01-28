pub mod authorization;
pub mod manager;
pub mod repository;
pub mod whitelist_tests;

#[cfg(test)]
mod tests {

    mod configured_as_whitelisted {

        mod handling_authorization {
            use crate::core::core_tests::sample_info_hash;
            use crate::core::whitelist::whitelist_tests::initialize_whitelist_services_for_listed_tracker;

            #[tokio::test]
            async fn it_should_authorize_the_announce_and_scrape_actions_on_whitelisted_torrents() {
                let (whitelist_authorization, whitelist_manager) = initialize_whitelist_services_for_listed_tracker();

                let info_hash = sample_info_hash();

                let result = whitelist_manager.add_torrent_to_whitelist(&info_hash).await;
                assert!(result.is_ok());

                let result = whitelist_authorization.authorize(&info_hash).await;
                assert!(result.is_ok());
            }

            #[tokio::test]
            async fn it_should_not_authorize_the_announce_and_scrape_actions_on_not_whitelisted_torrents() {
                let (whitelist_authorization, _whitelist_manager) = initialize_whitelist_services_for_listed_tracker();

                let info_hash = sample_info_hash();

                let result = whitelist_authorization.authorize(&info_hash).await;
                assert!(result.is_err());
            }
        }
    }
}
