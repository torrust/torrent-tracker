# Database Migrations

We don't support automatic migrations yet. The tracker creates all the needed tables when it starts. The SQL sentences are hardcoded in each database driver.

The migrations in this folder were introduced to add some new changes (permanent keys) and to allow users to migrate to the new version. In the future, we will remove the hardcoded SQL and start using a Rust crate for database migrations. For the time being, if you are using the initial schema described in the migration `20240730183000_torrust_tracker_create_all_tables.sql` you will need to run all the subsequent migrations manually.
