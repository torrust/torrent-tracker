use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_primitives::core::ScrapeData;
use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;

use super::torrent::repository::in_memory::InMemoryTorrentRepository;
use super::whitelist;

pub struct ScrapeHandler {
    /// The service to check is a torrent is whitelisted.
    whitelist_authorization: Arc<whitelist::authorization::Authorization>,

    /// The in-memory torrents repository.
    in_memory_torrent_repository: Arc<InMemoryTorrentRepository>,
}

impl ScrapeHandler {
    #[must_use]
    pub fn new(
        whitelist_authorization: &Arc<whitelist::authorization::Authorization>,
        in_memory_torrent_repository: &Arc<InMemoryTorrentRepository>,
    ) -> Self {
        Self {
            whitelist_authorization: whitelist_authorization.clone(),
            in_memory_torrent_repository: in_memory_torrent_repository.clone(),
        }
    }

    /// It handles a scrape request.
    ///
    /// # Context: Tracker
    ///
    /// BEP 48: [Tracker Protocol Extension: Scrape](https://www.bittorrent.org/beps/bep_0048.html).
    pub async fn scrape(&self, info_hashes: &Vec<InfoHash>) -> ScrapeData {
        let mut scrape_data = ScrapeData::empty();

        for info_hash in info_hashes {
            let swarm_metadata = match self.whitelist_authorization.authorize(info_hash).await {
                Ok(()) => self.in_memory_torrent_repository.get_swarm_metadata(info_hash),
                Err(_) => SwarmMetadata::zeroed(),
            };
            scrape_data.add_file(info_hash, swarm_metadata);
        }

        scrape_data
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bittorrent_primitives::info_hash::InfoHash;
    use torrust_tracker_primitives::core::ScrapeData;
    use torrust_tracker_test_helpers::configuration;

    use super::ScrapeHandler;
    use crate::core::torrent::repository::in_memory::InMemoryTorrentRepository;
    use crate::core::whitelist::repository::in_memory::InMemoryWhitelist;
    use crate::core::whitelist::{self};

    fn scrape_handler() -> ScrapeHandler {
        let config = configuration::ephemeral_public();

        let in_memory_whitelist = Arc::new(InMemoryWhitelist::default());
        let whitelist_authorization = Arc::new(whitelist::authorization::Authorization::new(
            &config.core,
            &in_memory_whitelist.clone(),
        ));
        let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());

        ScrapeHandler::new(&whitelist_authorization, &in_memory_torrent_repository)
    }

    #[tokio::test]
    async fn it_should_return_a_zeroed_swarm_metadata_for_the_requested_file_if_the_tracker_does_not_have_that_torrent() {
        let scrape_handler = scrape_handler();

        let info_hashes = vec!["3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap()]; // # DevSkim: ignore DS173237

        let scrape_data = scrape_handler.scrape(&info_hashes).await;

        let mut expected_scrape_data = ScrapeData::empty();

        expected_scrape_data.add_file_with_zeroed_metadata(&info_hashes[0]);

        assert_eq!(scrape_data, expected_scrape_data);
    }

    #[tokio::test]
    async fn it_should_allow_scraping_for_multiple_torrents() {
        let scrape_handler = scrape_handler();

        let info_hashes = vec![
            "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap(), // # DevSkim: ignore DS173237
            "99c82bb73505a3c0b453f9fa0e881d6e5a32a0c1".parse::<InfoHash>().unwrap(), // # DevSkim: ignore DS173237
        ];

        let scrape_data = scrape_handler.scrape(&info_hashes).await;

        let mut expected_scrape_data = ScrapeData::empty();
        expected_scrape_data.add_file_with_zeroed_metadata(&info_hashes[0]);
        expected_scrape_data.add_file_with_zeroed_metadata(&info_hashes[1]);

        assert_eq!(scrape_data, expected_scrape_data);
    }
}
