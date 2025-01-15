use bittorrent_primitives::info_hash::InfoHash;

/// The in-memory list of allowed torrents.
#[derive(Debug, Default)]
pub struct InMemoryWhitelist {
    /// The list of allowed torrents.
    whitelist: tokio::sync::RwLock<std::collections::HashSet<InfoHash>>,
}

impl InMemoryWhitelist {
    /// It adds a torrent from the whitelist in memory.
    pub async fn add(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.write().await.insert(*info_hash)
    }

    /// It removes a torrent from the whitelist in memory.
    pub async fn remove(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.write().await.remove(info_hash)
    }

    /// It checks if it contains an info-hash.
    pub async fn contains(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.read().await.contains(info_hash)
    }

    /// It clears the whitelist.
    pub async fn clear(&self) {
        let mut whitelist = self.whitelist.write().await;
        whitelist.clear();
    }
}

#[cfg(test)]
mod tests {
    use bittorrent_primitives::info_hash::InfoHash;

    use crate::core::whitelist::in_memory::InMemoryWhitelist;

    fn sample_info_hash() -> InfoHash {
        "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap() // # DevSkim: ignore DS173237
    }

    #[tokio::test]
    async fn should_allow_adding_a_new_torrent_to_the_whitelist() {
        let info_hash = sample_info_hash();

        let whitelist = InMemoryWhitelist::default();

        whitelist.add(&info_hash).await;

        assert!(whitelist.contains(&info_hash).await);
    }

    #[tokio::test]
    async fn should_allow_removing_a_new_torrent_to_the_whitelist() {
        let info_hash = sample_info_hash();

        let whitelist = InMemoryWhitelist::default();

        whitelist.add(&info_hash).await;
        whitelist.remove(&sample_info_hash()).await;

        assert!(!whitelist.contains(&info_hash).await);
    }

    #[tokio::test]
    async fn should_allow_clearing_the_whitelist() {
        let info_hash = sample_info_hash();

        let whitelist = InMemoryWhitelist::default();

        whitelist.add(&info_hash).await;
        whitelist.clear().await;

        assert!(!whitelist.contains(&info_hash).await);
    }

    #[tokio::test]
    async fn should_allow_checking_if_an_infohash_is_whitelisted() {
        let info_hash = sample_info_hash();

        let whitelist = InMemoryWhitelist::default();

        whitelist.add(&info_hash).await;

        assert!(whitelist.contains(&info_hash).await);
    }
}
