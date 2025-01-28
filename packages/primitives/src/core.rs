use std::collections::HashMap;
use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use derive_more::derive::Constructor;
use torrust_tracker_configuration::AnnouncePolicy;

use crate::peer;
use crate::swarm_metadata::SwarmMetadata;

/// Structure that holds the data returned by the `announce` request.
#[derive(Clone, Debug, PartialEq, Constructor, Default)]
pub struct AnnounceData {
    /// The list of peers that are downloading the same torrent.
    /// It excludes the peer that made the request.
    pub peers: Vec<Arc<peer::Peer>>,
    /// Swarm statistics
    pub stats: SwarmMetadata,
    pub policy: AnnouncePolicy,
}

/// Structure that holds the data returned by the `scrape` request.
#[derive(Debug, PartialEq, Default)]
pub struct ScrapeData {
    /// A map of infohashes and swarm metadata for each torrent.
    pub files: HashMap<InfoHash, SwarmMetadata>,
}

impl ScrapeData {
    /// Creates a new empty `ScrapeData` with no files (torrents).
    #[must_use]
    pub fn empty() -> Self {
        let files: HashMap<InfoHash, SwarmMetadata> = HashMap::new();
        Self { files }
    }

    /// Creates a new `ScrapeData` with zeroed metadata for each torrent.
    #[must_use]
    pub fn zeroed(info_hashes: &Vec<InfoHash>) -> Self {
        let mut scrape_data = Self::empty();

        for info_hash in info_hashes {
            scrape_data.add_file(info_hash, SwarmMetadata::zeroed());
        }

        scrape_data
    }

    /// Adds a torrent to the `ScrapeData`.
    pub fn add_file(&mut self, info_hash: &InfoHash, swarm_metadata: SwarmMetadata) {
        self.files.insert(*info_hash, swarm_metadata);
    }

    /// Adds a torrent to the `ScrapeData` with zeroed metadata.
    pub fn add_file_with_zeroed_metadata(&mut self, info_hash: &InfoHash) {
        self.files.insert(*info_hash, SwarmMetadata::zeroed());
    }
}

#[cfg(test)]
mod tests {

    use bittorrent_primitives::info_hash::InfoHash;

    use crate::core::ScrapeData;

    /// # Panics
    ///
    /// Will panic if the string representation of the info hash is not a valid info hash.
    #[must_use]
    pub fn sample_info_hash() -> InfoHash {
        "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0" // DevSkim: ignore DS173237
            .parse::<InfoHash>()
            .expect("String should be a valid info hash")
    }

    #[test]
    fn it_should_be_able_to_build_a_zeroed_scrape_data_for_a_list_of_info_hashes() {
        // Zeroed scrape data is used when the authentication for the scrape request fails.

        let sample_info_hash = sample_info_hash();

        let mut expected_scrape_data = ScrapeData::empty();
        expected_scrape_data.add_file_with_zeroed_metadata(&sample_info_hash);

        assert_eq!(ScrapeData::zeroed(&vec![sample_info_hash]), expected_scrape_data);
    }
}
