use std::panic::Location;
use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_configuration::Core;
use tracing::instrument;

use super::repository::in_memory::InMemoryWhitelist;
use crate::core::error::Error;

pub struct WhitelistAuthorization {
    /// Core tracker configuration.
    config: Core,

    /// The in-memory list of allowed torrents.
    in_memory_whitelist: Arc<InMemoryWhitelist>,
}

impl WhitelistAuthorization {
    /// Creates a new authorization instance.
    pub fn new(config: &Core, in_memory_whitelist: &Arc<InMemoryWhitelist>) -> Self {
        Self {
            config: config.clone(),
            in_memory_whitelist: in_memory_whitelist.clone(),
        }
    }

    /// It returns true if the torrent is authorized.
    ///
    /// # Errors
    ///
    /// Will return an error if the tracker is running in `listed` mode
    /// and the infohash is not whitelisted.
    #[instrument(skip(self, info_hash), err)]
    pub async fn authorize(&self, info_hash: &InfoHash) -> Result<(), Error> {
        if !self.is_listed() {
            return Ok(());
        }

        if self.is_info_hash_whitelisted(info_hash).await {
            return Ok(());
        }

        Err(Error::TorrentNotWhitelisted {
            info_hash: *info_hash,
            location: Location::caller(),
        })
    }

    /// Returns `true` is the tracker is in listed mode.
    fn is_listed(&self) -> bool {
        self.config.listed
    }

    /// It checks if a torrent is whitelisted.
    async fn is_info_hash_whitelisted(&self, info_hash: &InfoHash) -> bool {
        self.in_memory_whitelist.contains(info_hash).await
    }
}

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
