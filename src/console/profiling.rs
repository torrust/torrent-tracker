//! This binary is used for profiling with [valgrind](https://valgrind.org/)
//! and [kcachegrind](https://kcachegrind.github.io/).
//!
//! # Requirements
//!
//! [valgrind](https://valgrind.org/) and [kcachegrind](https://kcachegrind.github.io/).
//!
//! On Ubuntu you can install them with:
//!
//! ```text
//! sudo apt install valgrind kcachegrind
//! ```
//!
//! > NOTICE: valgrind executes the program you wan to profile and waits until
//! > it ends. Since the tracker is a service and does not end the profiling
//! > binary accepts an arguments with the duration you want to run the tracker,
//! > so that it terminates automatically after that period of time.
//!
//! # Run profiling
//!
//! To run the profiling you have to:
//!
//! 1. Build and run the tracker for profiling.
//! 2. Run the aquatic UDP load test tool to start collecting data in the tracker.
//!
//! Build and run the tracker for profiling:
//!
//! ```text
//! RUSTFLAGS='-g' cargo build --release --bin profiling \
//!   && export TORRUST_TRACKER_CONFIG_TOML_PATH="./share/default/config/tracker.udp.benchmarking.toml" \
//!   && valgrind \
//!     --tool=callgrind \
//!     --callgrind-out-file=callgrind.out \
//!     --collect-jumps=yes \
//!     --simulate-cache=yes \
//!     ./target/release/profiling 60
//! ```
//!
//! The output should be something like:
//!
//! ```text
//! RUSTFLAGS='-g' cargo build --release --bin profiling \
//!    && export TORRUST_TRACKER_CONFIG_TOML_PATH="./share/default/config/tracker.udp.benchmarking.toml" \
//!    && valgrind \
//!      --tool=callgrind \
//!      --callgrind-out-file=callgrind.out \
//!      --collect-jumps=yes \
//!      --simulate-cache=yes \
//!      ./target/release/profiling 60
//!
//!    Compiling torrust-tracker v3.0.0-alpha.12-develop (/home/developer/Documents/git/committer/me/github/torrust/torrust-tracker)
//!     Finished `release` profile [optimized + debuginfo] target(s) in 1m 15s
//! ==122801== Callgrind, a call-graph generating cache profiler
//! ==122801== Copyright (C) 2002-2017, and GNU GPL'd, by Josef Weidendorfer et al.
//! ==122801== Using Valgrind-3.19.0 and LibVEX; rerun with -h for copyright info
//! ==122801== Command: ./target/release/profiling 60
//! ==122801==
//! --122801-- warning: L3 cache found, using its data for the LL simulation.
//! ==122801== For interactive control, run 'callgrind_control -h'.
//! Loading configuration file: `./share/default/config/tracker.udp.benchmarking.toml` ...
//! Torrust successfully shutdown.
//! ==122801==
//! ==122801== Events    : Ir Dr Dw I1mr D1mr D1mw ILmr DLmr DLmw
//! ==122801== Collected : 1160654816 278135882 247755311 24453652 12650490 16315690 10932 2481624 4832145
//! ==122801==
//! ==122801== I   refs:      1,160,654,816
//! ==122801== I1  misses:       24,453,652
//! ==122801== LLi misses:           10,932
//! ==122801== I1  miss rate:          2.11%
//! ==122801== LLi miss rate:          0.00%
//! ==122801==
//! ==122801== D   refs:        525,891,193  (278,135,882 rd + 247,755,311 wr)
//! ==122801== D1  misses:       28,966,180  ( 12,650,490 rd +  16,315,690 wr)
//! ==122801== LLd misses:        7,313,769  (  2,481,624 rd +   4,832,145 wr)
//! ==122801== D1  miss rate:           5.5% (        4.5%   +         6.6%  )
//! ==122801== LLd miss rate:           1.4% (        0.9%   +         2.0%  )
//! ==122801==
//! ==122801== LL refs:          53,419,832  ( 37,104,142 rd +  16,315,690 wr)
//! ==122801== LL misses:         7,324,701  (  2,492,556 rd +   4,832,145 wr)
//! ==122801== LL miss rate:            0.4% (        0.2%   +         2.0%  )
//! ```
//!
//! > NOTICE: We are using an specific tracker configuration for profiling that
//! > removes all features except the UDP tracker and sets the logging level to `error`.
//!
//! Build the aquatic UDP load test command:
//!
//! ```text
//! cd /tmp
//! git clone git@github.com:greatest-ape/aquatic.git
//! cd aquatic
//! cargo build --profile=release-debug -p aquatic_udp_load_test
//! ./target/release-debug/aquatic_udp_load_test -p > "load-test-config.toml"
//! ```
//!
//! Modify the "load-test-config.toml" file to change the UDP tracker port from
//! `3000` to `6969`.
//!
//! Running the aquatic UDP load test command:
//!
//! ```text
//! ./target/release-debug/aquatic_udp_load_test -c "load-test-config.toml"
//! ```
//!
//! The output should be something like this:
//!
//! ```text
//! Starting client with config: Config {
//!     server_address: 127.0.0.1:6969,
//!     log_level: Error,
//!     workers: 1,
//!     duration: 0,
//!     summarize_last: 0,
//!     extra_statistics: true,
//!     network: NetworkConfig {
//!         multiple_client_ipv4s: true,
//!         sockets_per_worker: 4,
//!         recv_buffer: 8000000,
//!     },
//!     requests: RequestConfig {
//!         number_of_torrents: 1000000,
//!         number_of_peers: 2000000,
//!         scrape_max_torrents: 10,
//!         announce_peers_wanted: 30,
//!         weight_connect: 50,
//!         weight_announce: 50,
//!         weight_scrape: 1,
//!         peer_seeder_probability: 0.75,
//!     },
//! }
//!
//! Requests out: 45097.51/second
//! Responses in: 4212.70/second
//!   - Connect responses:  2098.15
//!   - Announce responses: 2074.95
//!   - Scrape responses:   39.59
//!   - Error responses:    0.00
//! Peers per announce response: 0.00
//! Announce responses per info hash:
//!   - p10: 1
//!   - p25: 1
//!   - p50: 1
//!   - p75: 2
//!   - p90: 3
//!   - p95: 4
//!   - p99: 6
//!   - p99.9: 8
//!   - p100: 10
//! ```
//!
//! After running the tracker for some seconds the tracker will automatically stop
//! and `valgrind`will write the file `callgrind.out` with the data.
//!
//! You can now analyze the collected data with:
//!
//! ```text
//! kcachegrind callgrind.out
//! ```
use std::env;
use std::time::Duration;

use tokio::time::sleep;

use crate::{app, bootstrap};

pub async fn run() {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    // Ensure an argument for duration is provided
    if args.len() != 2 {
        eprintln!("Usage: {} <duration_in_seconds>", args[0]);
        return;
    }

    // Parse duration argument
    let Ok(duration_secs) = args[1].parse::<u64>() else {
        eprintln!("Invalid duration provided");
        return;
    };

    let (config, tracker, ban_service, stats_event_sender, stats_repository) = bootstrap::app::setup();

    let jobs = app::start(&config, tracker, ban_service, stats_event_sender, stats_repository).await;

    // Run the tracker for a fixed duration
    let run_duration = sleep(Duration::from_secs(duration_secs));

    tokio::select! {
        () = run_duration => {
            tracing::info!("Torrust timed shutdown..");
        },
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Torrust shutting down via Ctrl+C ...");
            // Await for all jobs to shutdown
            futures::future::join_all(jobs).await;
        }
    }

    println!("Torrust successfully shutdown.");
}
