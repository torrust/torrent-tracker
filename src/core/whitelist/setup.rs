use std::sync::Arc;

use super::manager::WhitelistManager;
use super::repository::in_memory::InMemoryWhitelist;
use super::repository::persisted::DatabaseWhitelist;
use crate::core::databases::Database;

#[must_use]
pub fn initialize_whitelist_manager(
    database: Arc<Box<dyn Database>>,
    in_memory_whitelist: Arc<InMemoryWhitelist>,
) -> Arc<WhitelistManager> {
    let database_whitelist = Arc::new(DatabaseWhitelist::new(database));
    Arc::new(WhitelistManager::new(database_whitelist, in_memory_whitelist))
}
