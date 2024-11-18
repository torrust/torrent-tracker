//! **Torrust Tracker** is a modern and feature-rich (private) [`BitTorrent`](https://www.bittorrent.org/) tracker.
//!
//! [`BitTorrent`](https://en.wikipedia.org/wiki/BitTorrent) is a protocol for distributing files using a peer-to-peer network.
//!
//! Peers in the networks need to know where they can find other peers with the files they are looking for.
//!
//! Tracker are services that allow peers to quickly find other peers. Client peers announce their existence to a tracker,
//! and the tracker responds to the peer with a list of other peers in the swarm.
//!
//! You can learn more about `BitTorrent` and `BitTorrent` Trackers on these sites:
//!
//! - <https://www.bittorrent.org/>
//! - <https://en.wikipedia.org/wiki/BitTorrent>
//! - <https://en.wikipedia.org/wiki/BitTorrent_tracker>
//!
//! Torrust Tracker is a `BitTorrent` tracker with a focus on:
//!
//! - Performance
//! - Robustness
//! - Extensibility
//! - Security
//! - Usability
//! - And with a community-driven development
//!
//! # Table of contents
//!
//! - [Features](#features)
//! - [Services](#services)
//! - [Installation](#installation)
//!     - [Minimum requirements](#minimum-requirements)
//!     - [Prerequisites](#prerequisites)
//!     - [Install from sources](#install-from-sources)
//!     - [Run with docker](#run-with-docker)
//! - [Configuration](#configuration)
//! - [Usage](#usage)
//!     - [API](#api)
//!     - [HTTP Tracker](#http-tracker)
//!     - [UDP Tracker](#udp-tracker)
//! - [Components](#components)
//! - [Implemented BEPs](#implemented-beps)
//! - [Contributing](#contributing)
//! - [Documentation](#documentation)
//!
//! # Features
//!
//! - Multiple UDP server and HTTP(S) server blocks for socket binding possible
//! - Full IPv4 and IPv6 support for both UDP and HTTP(S)
//! - Private and Whitelisted mode
//! - Built-in API
//! - Peer authentication using time-bound keys
//! - Database persistence for authentication keys, whitelist and completed peers counter
//! - DB Support for `SQLite` and `MySQl`
//!
//! # Services
//!
//! From the end-user perspective the Torrust Tracker exposes three different services.
//!
//! - A REST [`API`](crate::servers::apis)
//! - One or more [`UDP`](crate::servers::udp) trackers
//! - One or more [`HTTP`](crate::servers::http) trackers
//!
//! # Installation
//!
//! ## Minimum requirements
//!
//! - Rust Stable `1.68`
//! - You might have problems compiling with a machine with low resources.
//!
//! It has been tested with:
//!
//! Docker containers with:
//!
//! - 6 CPUs
//! - 7.5G of ram
//! - 2GB of swap
//!
//! [VM](https://github.com/torrust/torrust-tracker/issues/321) with:
//!
//! - 1 core of Intel Xeon Processor (Icelake)
//! - 1G of ram
//! - 25G of disk
//! - Debian 11
//! - no swap by default
//!
//! Adding swap may help with compilation. See issue [#321](https://github.com/torrust/torrust-tracker/issues/321).
//!
//! ## Prerequisites
//!
//! The tracker has some system dependencies:
//!
//! Since we are using the `openssl` crate with the [vendored feature](https://docs.rs/openssl/latest/openssl/#vendored),
//! enabled, you will need to install the following dependencies:
//!
//! ```text
//! sudo apt-get install pkg-config libssl-dev make
//! ```
//!
//! If you are using `SQLite3` as database driver, you will need to install the
//! following dependency:
//!
//! ```text
//! sudo apt-get install libsqlite3-dev
//! ```
//!
//! > **NOTICE**: those are the commands for `Ubuntu`. If you are using a
//! > different OS, you will need to install the equivalent packages. Please
//! > refer to the documentation of your OS.
//!
//! With the default configuration you will need to create the `storage` directory:
//!
//! ```text
//! ./storage/
//! └── tracker
//!     ├── etc
//!     ├── lib
//!     │   ├── database
//!     │   │   └── sqlite3.db
//!     │   └── tls
//!     └── log
//! ```
//!
//! The default configuration expects a directory `./storage/tracker/lib/database` to be writable by the tracker process.
//!
//! By default the tracker uses `SQLite` and the database file name `sqlite3.db`.
//!
//! You only need the `tls` directory in case you are setting up SSL for the HTTP tracker or the tracker API.
//! Visit [`HTTP`](crate::servers::http) or [`API`](crate::servers::apis) if you want to know how you can use HTTPS.
//!
//! ## Install from sources
//!
//! First, you need to create a folder to clone the repository.
//!
//! ```text
//! cd /tmp
//! mkdir torrust
//! ```
//!
//! ```text
//! git clone https://github.com/torrust/torrust-tracker.git \
//!   && cd torrust-tracker \
//!   && cargo build --release \
//!   && mkdir -p ./storage/tracker/etc \
//!   && mkdir -p ./storage/tracker/lib/database \
//!   && mkdir -p ./storage/tracker/lib/tls \
//!   && mkdir -p ./storage/tracker/log
//! ```
//!
//! To run the tracker we will have to use the command "cargo run" this will
//! compile and after being compiled it will start running the tracker.
//!
//! ```text
//! cargo run
//! ```
//!
//! ## Run with docker
//!
//! You can run the tracker with a pre-built docker image. Please refer to the
//! [tracker docker documentation](https://github.com/torrust/torrust-tracker/blob/develop/docs/containers.md).
//!
//! # Configuration
//!
//! In order to run the tracker you need to provide the configuration. If you
//! run the tracker without providing the configuration, the tracker will
//! generate the default configuration the first time you run it. It will
//! generate a `tracker.toml` file with in the root directory.
//!
//! The default configuration is:
//!
//! ```toml
//! [logging]
//! threshold = "info"
//!
//! [core]
//! inactive_peer_cleanup_interval = 600
//! listed = false
//! private = false
//! tracker_usage_statistics = true
//!
//! [core.announce_policy]
//! interval = 120
//! interval_min = 120
//!
//! [core.database]
//! driver = "sqlite3"
//! path = "./storage/tracker/lib/database/sqlite3.db"
//!
//! [core.net]
//! external_ip = "0.0.0.0"
//! on_reverse_proxy = false
//!
//! [core.tracker_policy]
//! max_peer_timeout = 900
//! persistent_torrent_completed_stat = false
//! remove_peerless_torrents = true
//!
//! [health_check_api]
//! bind_address = "127.0.0.1:1313"
//!```
//!
//! The default configuration includes one disabled UDP server, one disabled
//! HTTP server and the enabled API.
//!
//! For more information about each service and options you can visit the
//! documentation for the [torrust-tracker-configuration crate](https://docs.rs/torrust-tracker-configuration).
//!
//! Alternatively to the `tracker.toml` file you can use one environment
//! variable `TORRUST_TRACKER_CONFIG_TOML` to pass the configuration to the tracker:
//!
//! ```text
//! TORRUST_TRACKER_CONFIG_TOML=$(cat ./share/default/config/tracker.development.sqlite3.toml) ./target/release/torrust-tracker
//! ```
//!
//! In the previous example you are just setting the env var with the contents
//! of the `tracker.toml` file.
//!
//! The env var contains the same data as the `tracker.toml`. It's particularly
//! useful in you are [running the tracker with docker](https://github.com/torrust/torrust-tracker/blob/develop/docs/containers.md).
//!
//! > NOTICE: The `TORRUST_TRACKER_CONFIG_TOML` env var has priority over the `tracker.toml` file.
//!
//! By default, if you don’t specify any `tracker.toml` file, the application
//! will use `./share/default/config/tracker.development.sqlite3.toml`.
//!
//! > IMPORTANT: Every time you change the configuration you need to restart the
//! > service.
//!
//! # Usage
//!
//! Running the tracker with the default configuration and enabling the UDP and
//! HTTP trackers will expose the services on these URLs:
//!
//! - REST API: <http://localhost:1212>
//! - UDP tracker: <http://localhost:6969>
//! - HTTP tracker: <http://localhost:7070>
//!
//! ## API
//!
//! In order to use the tracker API you need to enable it in the configuration:
//!
//! ```toml
//! [http_api]
//! bind_address = "127.0.0.1:1212"
//!
//! [http_api.access_tokens]
//! admin = "MyAccessToken"
//! ```
//!
//! By default it's enabled on port `1212`. You also need to add access tokens in the configuration:
//!
//! ```toml
//! [http_api.access_tokens]
//! admin = "MyAccessToken"
//! LABEL = "YOUR_TOKEN"
//! ```
//!
//! All tokens give full access the the API. Once you have defined you token you can make request adding the token as a `GET` parameter. For example:
//!
//! <http://127.0.0.1:1212/api/v1/stats?token=MyAccessToken>
//!
//! That endpoint will give you the tracker metrics:
//!
//! ```json
//! {
//!     "torrents": 0,
//!     "seeders": 0,
//!     "completed": 0,
//!     "leechers": 0,
//!     "tcp4_connections_handled": 0,
//!     "tcp4_announces_handled": 0,
//!     "tcp4_scrapes_handled": 0,
//!     "tcp6_connections_handled": 0,
//!     "tcp6_announces_handled": 0,
//!     "tcp6_scrapes_handled": 0,
//!     "udp4_connections_handled": 0,
//!     "udp4_announces_handled": 0,
//!     "udp4_scrapes_handled": 0,
//!     "udp6_connections_handled": 0,
//!     "udp6_announces_handled": 0,
//!     "udp6_scrapes_handled": 0
//! }
//! ```
//!
//! Refer to the [`API`](crate::servers::apis) documentation for more information about the [`API`](crate::servers::apis) endpoints.
//!
//! ## HTTP tracker
//!
//! The HTTP tracker implements two type of requests:
//!
//! - Announce: <http://127.0.0.1:7070/announce>
//! - Scrape: <http://127.0.0.1:7070/scrape>
//!
//! In you are using the tracker in `private` or `private_listed` mode you will need to append the authentication key:
//!
//! - Announce: <http://127.0.0.1:7070/announce/key>
//! - Scrape: <http://127.0.0.1:7070/scrape/key>
//!
//! In order to use the HTTP tracker you need to enable at least one server in the configuration:
//!
//! ```toml
//! [[http_trackers]]
//! bind_address = "0.0.0.0:7070"
//! ```
//!
//! Refer to the [`HTTP`](crate::servers::http) documentation for more information about the [`HTTP`](crate::servers::http) tracker.
//!
//! ### Announce
//!
//! The `announce` request allows a peer to announce itself and obtain a list of peer for an specific torrent.
//!
//! A sample `announce` request:
//!
//! <http://0.0.0.0:7070/announce?info_hash=%81%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00&peer_addr=2.137.87.41&downloaded=0&uploaded=0&peer_id=-qB00000000000000001&port=17548&left=0&event=completed&compact=0>
//!
//! If you want to know more about the `announce` request:
//!
//! - [BEP 03. The `BitTorrent` Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)
//! - [BEP 23. Tracker Returns Compact Peer Lists](https://www.bittorrent.org/beps/bep_0023.html)
//! - [Vuze announce docs](https://wiki.vuze.com/w/Announce)
//!
//! ### Scrape
//!
//! The `scrape` request allows a peer to get swarm metadata for multiple torrents at the same time.
//!
//! A sample `scrape` request for only one torrent:
//!
//! <http://0.0.0.0:7070/scrape?info_hash=%81%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00>
//!
//! The response contains the swarm metadata for that torrent:
//!
//! - `complete`: the number of active peers that have completed downloading, also known as seeders. Peers from which other peers can get a full copy of the torrent.
//! - `downloaded`: the number of peers that have ever completed downloading.
//! - `incomplete`: the number of active peers that have not completed downloading, also known as leechers.
//!
//! The `scrape` response is a bencoded byte array like the following:
//!
//! ```text
//! d5:filesd20:xxxxxxxxxxxxxxxxxxxxd8:completei11e10:downloadedi13772e10:incompletei19e20:yyyyyyyyyyyyyyyyyyyyd8:completei21e10:downloadedi206e10:incompletei20eee
//! ```
//!
//! If you save the response as a file and you open it with a program that can handle binary data you would see:
//!
//! ```text
//! 00000000: 6435 3a66 696c 6573 6432 303a 8100 0000  d5:filesd20:....
//! 00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
//! 00000020: 6438 3a63 6f6d 706c 6574 6569 3165 3130  d8:completei1e10
//! 00000030: 3a64 6f77 6e6c 6f61 6465 6469 3065 3130  :downloadedi0e10
//! 00000040: 3a69 6e63 6f6d 706c 6574 6569 3065 6565  :incompletei0eee
//! 00000050: 65                                       e
//! ```
//!
//! `BitTorrent` uses a data formatting specification called [Bencode](https://en.wikipedia.org/wiki/Bencode).
//!
//! If you want to know more about the `scrape` request:
//!
//! - [BEP 48. Tracker Protocol Extension: Scrape](https://www.bittorrent.org/beps/bep_0048.html)
//! - [Vuze scrape docs](https://wiki.vuze.com/w/Scrape)
//!
//! ### Authentication keys
//!
//! If the tracker is running in `private` or `private_listed` mode you will need to provide a valid authentication key.
//!
//! Right now the only way to add new keys is via the REST [`API`](crate::servers::apis). The endpoint `POST /api/vi/key/:duration_in_seconds`
//! will return an expiring key that will be valid for `duration_in_seconds` seconds.
//!
//! Using `curl` you can create a 2-minute valid auth key:
//!
//! ```text
//! $ curl -X POST "http://127.0.0.1:1212/api/v1/key/120?token=MyAccessToken"
//! ```
//!
//! Response:
//!
//! ```json
//! {
//!     "key": "nvCFlJCq7fz7Qx6KoKTDiMZvns8l5Kw7",
//!     "valid_until": 1679334334,
//!     "expiry_time": "2023-03-20 17:45:34.712077008 UTC"
//! }
//! ```
//!
//! You can also use the Torrust Tracker together with the [Torrust Index](https://github.com/torrust/torrust-index). If that's the case,
//! the Index will create the keys by using the tracker [API](crate::servers::apis).
//!
//! ## UDP tracker
//!
//! The UDP tracker also implements two type of requests:
//!
//! - Announce: <udp://127.0.0.1:6969>
//! - Scrape: <udp://127.0.0.1:6969>
//!
//! In order to use the UDP tracker you need to enable at least one server in the configuration:
//!
//! ```toml
//! [[udp_trackers]]
//! bind_address = "0.0.0.0:6969"
//! ```
//!
//! Refer to the [`UDP`](crate::servers::udp) documentation for more information about the [`UDP`](crate::servers::udp) tracker.
//!
//! If you want to know more about the UDP tracker protocol:
//!
//! - [BEP 15. UDP Tracker Protocol for `BitTorrent`](https://www.bittorrent.org/beps/bep_0015.html)
//!
//! # Components
//!
//! Torrust Tracker has four main components:
//!
//! - The core tracker [`core`]
//! - The tracker REST [`API`](crate::servers::apis)
//! - The [`UDP`](crate::servers::udp) tracker
//! - The [`HTTP`](crate::servers::http) tracker
//!
//! ![Torrust Tracker Components](https://raw.githubusercontent.com/torrust/torrust-tracker/main/docs/media/torrust-tracker-components.png)
//!
//! ## Core tracker
//!
//! The core tracker is the main containing the tracker generic tracker logic.
//!
//! The core tracker handles:
//!
//! - Authentication with keys
//! - Authorization using a torrent whitelist
//! - Statistics
//! - Persistence
//!
//! See [`core`] for more details on the  [`core`] module.
//!
//! ## Tracker API
//!
//! The tracker exposes a REST API. The API has four resource groups:
//!
//! - Authentication keys: to handle the keys for the HTTP tracker
//! - Statistics: to get the tracker metrics like requests counters
//! - Torrents: to get peers for a torrent
//! - Whitelist: to handle the torrent whitelist when the tracker runs on `listed` or `private_listed` mode
//!
//! See [`API`](crate::servers::apis) for more details on the REST API.
//!
//! ## UDP tracker
//!
//! UDP trackers are trackers with focus on performance. By Using UDP instead of HTTP the tracker removed the overhead
//! of opening and closing TCP connections. It also reduces the response size.
//!
//! You can find more information about UDP tracker on:
//!
//! - [Wikipedia: UDP tracker](https://en.wikipedia.org/wiki/UDP_tracker)
//! - [BEP 15: UDP Tracker Protocol for `BitTorrent`](https://www.bittorrent.org/beps/bep_0015.html)
//!
//! See [`UDP`](crate::servers::udp) for more details on the UDP tracker.
//!
//! ## HTTP tracker
//!
//! HTTP tracker was the original tracker specification defined on the [BEP 3]((https://www.bittorrent.org/beps/bep_0003.html)).
//!
//! See [`HTTP`](crate::servers::http) for more details on the HTTP tracker.
//!
//! You can find more information about UDP tracker on:
//!
//! - [Wikipedia: `BitTorrent` tracker](https://en.wikipedia.org/wiki/BitTorrent_tracker)
//! - [BEP 3: The `BitTorrent` Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)
//!
//! # Implemented BEPs
//!
//! BEP stands for `BitTorrent` Enhancement Proposal. BEPs are documents providing information to the `BitTorrent`
//! community or describing a new feature for the `BitTorrent` protocols.
//!
//! You can find all BEPs on <https://www.bittorrent.org/>
//!
//! Torrust Tracker implements these BEPs:
//!
//! - [BEP 3](https://www.bittorrent.org/beps/bep_0003.html): The `BitTorrent` Protocol
//! - [BEP 7](https://www.bittorrent.org/beps/bep_0007.html): IPv6 Support
//! - [BEP 15](https://www.bittorrent.org/beps/bep_0015.html): UDP Tracker Protocol for `BitTorrent`
//! - [BEP 23](https://www.bittorrent.org/beps/bep_0023.html): Tracker Returns Compact Peer Lists
//! - [BEP 27](https://www.bittorrent.org/beps/bep_0027.html): Private Torrents
//! - [BEP 48](https://www.bittorrent.org/beps/bep_0048.html): Tracker Protocol Extension: Scrape
//!
//! # Contributing
//!
//! If you want to contribute to this documentation you can [open a new pull request](https://github.com/torrust/torrust-tracker/pulls).
//!
//! # Documentation
//!
//! You can find this documentation on [docs.rs](https://docs.rs/torrust-tracker/).
//!
//! If you want to contribute to this documentation you can [open a new pull request](https://github.com/torrust/torrust-tracker/pulls).
//!
//! In addition to the production code documentation you can find a lot of
//! examples on the integration and unit tests.

use torrust_tracker_clock::clock;

pub mod app;
pub mod bootstrap;
pub mod console;
pub mod core;
pub mod servers;
pub mod shared;

#[macro_use]
extern crate lazy_static;

/// This code needs to be copied into each crate.
/// Working version, for production.
#[cfg(not(test))]
#[allow(dead_code)]
pub(crate) type CurrentClock = clock::Working;

/// Stopped version, for testing.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) type CurrentClock = clock::Stopped;
