use std::sync::Arc;

use super::databases::Database;
use super::whitelist::manager::WhitelistManager;
use super::whitelist::repository::in_memory::InMemoryWhitelist;
use super::whitelist::repository::persisted::DatabaseWhitelist;

#[must_use]
pub fn initialize_whitelist_manager(
    database: Arc<Box<dyn Database>>,
    in_memory_whitelist: Arc<InMemoryWhitelist>,
) -> Arc<WhitelistManager> {
    let database_whitelist = Arc::new(DatabaseWhitelist::new(database));
    Arc::new(WhitelistManager::new(database_whitelist, in_memory_whitelist))
}
