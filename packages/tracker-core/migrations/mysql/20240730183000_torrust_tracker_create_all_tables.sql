CREATE TABLE
    IF NOT EXISTS whitelist (
        id integer PRIMARY KEY AUTO_INCREMENT,
        info_hash VARCHAR(40) NOT NULL UNIQUE
    );

CREATE TABLE
    IF NOT EXISTS torrents (
        id integer PRIMARY KEY AUTO_INCREMENT,
        info_hash VARCHAR(40) NOT NULL UNIQUE,
        completed INTEGER DEFAULT 0 NOT NULL
    );

CREATE TABLE
    IF NOT EXISTS `keys` (
        `id` INT NOT NULL AUTO_INCREMENT,
        `key` VARCHAR(32) NOT NULL,
        `valid_until` INT (10) NOT NULL,
        PRIMARY KEY (`id`),
        UNIQUE (`key`)
    );