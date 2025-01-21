use crate::core::authentication::key::{Key, PeerKey};

/// In-memory implementation of the authentication key repository.
#[derive(Debug, Default)]
pub struct InMemoryKeyRepository {
    /// Tracker users' keys. Only for private trackers.
    keys: tokio::sync::RwLock<std::collections::HashMap<Key, PeerKey>>,
}

impl InMemoryKeyRepository {
    /// It adds a new authentication key.
    pub async fn insert(&self, auth_key: &PeerKey) {
        self.keys.write().await.insert(auth_key.key.clone(), auth_key.clone());
    }

    /// It removes an authentication key.
    pub async fn remove(&self, key: &Key) {
        self.keys.write().await.remove(key);
    }

    pub async fn get(&self, key: &Key) -> Option<PeerKey> {
        self.keys.read().await.get(key).cloned()
    }

    /// It clears all the authentication keys.
    pub async fn clear(&self) {
        let mut keys = self.keys.write().await;
        keys.clear();
    }
}
