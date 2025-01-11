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
