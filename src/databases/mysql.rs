use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use log::debug;
use r2d2::Pool;
use r2d2_mysql::mysql::prelude::Queryable;
use r2d2_mysql::mysql::{params, Opts, OptsBuilder};
use r2d2_mysql::MysqlConnectionManager;
use torrust_tracker_primitives::DatabaseDriver;

use crate::databases::{Database, Error};
use crate::protocol::common::AUTH_KEY_LENGTH;
use crate::protocol::info_hash::InfoHash;
use crate::tracker::auth;

const DRIVER: DatabaseDriver = DatabaseDriver::MySQL;

pub struct Mysql {
    pool: Pool<MysqlConnectionManager>,
}

#[async_trait]
impl Database for Mysql {
    /// # Errors
    ///
    /// Will return `r2d2::Error` if `db_path` is not able to create `MySQL` database.
    fn new(db_path: &str) -> Result<Self, Error> {
        let opts = Opts::from_url(db_path)?;
        let builder = OptsBuilder::from_opts(opts);
        let manager = MysqlConnectionManager::new(builder);
        let pool = r2d2::Pool::builder().build(manager).map_err(|e| (e, DRIVER))?;

        Ok(Self { pool })
    }

    fn create_database_tables(&self) -> Result<(), Error> {
        let create_whitelist_table = "
        CREATE TABLE IF NOT EXISTS whitelist (
            id integer PRIMARY KEY AUTO_INCREMENT,
            info_hash VARCHAR(40) NOT NULL UNIQUE
        );"
        .to_string();

        let create_torrents_table = "
        CREATE TABLE IF NOT EXISTS torrents (
            id integer PRIMARY KEY AUTO_INCREMENT,
            info_hash VARCHAR(40) NOT NULL UNIQUE,
            completed INTEGER DEFAULT 0 NOT NULL
        );"
        .to_string();

        let create_keys_table = format!(
            "
        CREATE TABLE IF NOT EXISTS `keys` (
          `id` INT NOT NULL AUTO_INCREMENT,
          `key` VARCHAR({}) NOT NULL,
          `valid_until` INT(10) NOT NULL,
          PRIMARY KEY (`id`),
          UNIQUE (`key`)
        );",
            i8::try_from(AUTH_KEY_LENGTH).expect("auth::Auth Key Length Should fit within a i8!")
        );

        let mut conn = self.pool.get().map_err(|e| (e, DRIVER))?;

        conn.query_drop(&create_torrents_table)
            .expect("Could not create torrents table.");
        conn.query_drop(&create_keys_table).expect("Could not create keys table.");
        conn.query_drop(&create_whitelist_table)
            .expect("Could not create whitelist table.");

        Ok(())
    }

    fn drop_database_tables(&self) -> Result<(), Error> {
        let drop_whitelist_table = "
        DROP TABLE `whitelist`;"
            .to_string();

        let drop_torrents_table = "
        DROP TABLE `torrents`;"
            .to_string();

        let drop_keys_table = "
            DROP TABLE `keys`;"
            .to_string();

        let mut conn = self.pool.get().map_err(|e| (e, DRIVER))?;

        conn.query_drop(&drop_whitelist_table)
            .expect("Could not drop `whitelist` table.");
        conn.query_drop(&drop_torrents_table)
            .expect("Could not drop `torrents` table.");
        conn.query_drop(&drop_keys_table).expect("Could not drop `keys` table.");

        Ok(())
    }

    async fn load_persistent_torrents(&self) -> Result<Vec<(InfoHash, u32)>, Error> {
        let mut conn = self.pool.get().map_err(|e| (e, DRIVER))?;

        let torrents = conn.query_map(
            "SELECT info_hash, completed FROM torrents",
            |(info_hash_string, completed): (String, u32)| {
                let info_hash = InfoHash::from_str(&info_hash_string).unwrap();
                (info_hash, completed)
            },
        )?;

        Ok(torrents)
    }

    async fn load_keys(&self) -> Result<Vec<auth::Key>, Error> {
        let mut conn = self.pool.get().map_err(|e| (e, DRIVER))?;

        let keys = conn.query_map(
            "SELECT `key`, valid_until FROM `keys`",
            |(key, valid_until): (String, i64)| auth::Key {
                key,
                valid_until: Some(Duration::from_secs(valid_until.unsigned_abs())),
            },
        )?;

        Ok(keys)
    }

    async fn load_whitelist(&self) -> Result<Vec<InfoHash>, Error> {
        let mut conn = self.pool.get().map_err(|e| (e, DRIVER))?;

        let info_hashes = conn.query_map("SELECT info_hash FROM whitelist", |info_hash: String| {
            InfoHash::from_str(&info_hash).unwrap()
        })?;

        Ok(info_hashes)
    }

    async fn save_persistent_torrent(&self, info_hash: &InfoHash, completed: u32) -> Result<(), Error> {
        const COMMAND : &str = "INSERT INTO torrents (info_hash, completed) VALUES (:info_hash_str, :completed) ON DUPLICATE KEY UPDATE completed = VALUES(completed)";

        let mut conn = self.pool.get().map_err(|e| (e, DRIVER))?;

        let info_hash_str = info_hash.to_string();

        debug!("{}", info_hash_str);

        Ok(conn.exec_drop(COMMAND, params! { info_hash_str, completed })?)
    }

    async fn get_info_hash_from_whitelist(&self, info_hash: &str) -> Result<Option<InfoHash>, Error> {
        let mut conn = self.pool.get().map_err(|e| (e, DRIVER))?;

        let select = conn.exec_first::<String, _, _>(
            "SELECT info_hash FROM whitelist WHERE info_hash = :info_hash",
            params! { info_hash },
        )?;

        let info_hash = select.map(|f| InfoHash::from_str(&f).expect("Failed to decode InfoHash String from DB!"));

        Ok(info_hash)
    }

    async fn add_info_hash_to_whitelist(&self, info_hash: InfoHash) -> Result<usize, Error> {
        let mut conn = self.pool.get().map_err(|e| (e, DRIVER))?;

        let info_hash_str = info_hash.to_string();

        conn.exec_drop(
            "INSERT INTO whitelist (info_hash) VALUES (:info_hash_str)",
            params! { info_hash_str },
        )?;

        Ok(1)
    }

    async fn remove_info_hash_from_whitelist(&self, info_hash: InfoHash) -> Result<usize, Error> {
        let mut conn = self.pool.get().map_err(|e| (e, DRIVER))?;

        let info_hash = info_hash.to_string();

        conn.exec_drop("DELETE FROM whitelist WHERE info_hash = :info_hash", params! { info_hash })?;

        Ok(1)
    }

    async fn get_key_from_keys(&self, key: &str) -> Result<Option<auth::Key>, Error> {
        let mut conn = self.pool.get().map_err(|e| (e, DRIVER))?;

        let query =
            conn.exec_first::<(String, i64), _, _>("SELECT `key`, valid_until FROM `keys` WHERE `key` = :key", params! { key });

        let key = query?;

        Ok(key.map(|(key, expiry)| auth::Key {
            key,
            valid_until: Some(Duration::from_secs(expiry.unsigned_abs())),
        }))
    }

    async fn add_key_to_keys(&self, auth_key: &auth::Key) -> Result<usize, Error> {
        let mut conn = self.pool.get().map_err(|e| (e, DRIVER))?;

        let key = auth_key.key.to_string();
        let valid_until = auth_key.valid_until.unwrap_or(Duration::ZERO).as_secs().to_string();

        conn.exec_drop(
            "INSERT INTO `keys` (`key`, valid_until) VALUES (:key, :valid_until)",
            params! { key, valid_until },
        )?;

        Ok(1)
    }

    async fn remove_key_from_keys(&self, key: &str) -> Result<usize, Error> {
        let mut conn = self.pool.get().map_err(|e| (e, DRIVER))?;

        conn.exec_drop("DELETE FROM `keys` WHERE key = :key", params! { key })?;

        Ok(1)
    }
}
