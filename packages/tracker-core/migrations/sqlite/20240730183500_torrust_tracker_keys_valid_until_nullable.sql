CREATE TABLE
    IF NOT EXISTS keys_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL UNIQUE,
        valid_until INTEGER
    );

INSERT INTO keys_new SELECT * FROM `keys`;

DROP TABLE `keys`;

ALTER TABLE keys_new RENAME TO `keys`;