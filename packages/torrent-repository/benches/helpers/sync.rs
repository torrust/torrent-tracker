use std::sync::Arc;
use std::time::{Duration, Instant};

use bittorrent_primitives::info_hash::InfoHash;
use futures::stream::FuturesUnordered;
use torrust_tracker_torrent_repository::repository::Repository;

use super::utils::{generate_unique_info_hashes, DEFAULT_PEER};

// Simply add one torrent
#[must_use]
pub fn add_one_torrent<V, T>(samples: u64) -> Duration
where
    V: Repository<T> + Default,
{
    let start = Instant::now();

    for _ in 0..samples {
        let torrent_repository = V::default();

        let info_hash = InfoHash::default();

        torrent_repository.upsert_peer(&info_hash, &DEFAULT_PEER);

        torrent_repository.get_swarm_metadata(&info_hash);
    }

    start.elapsed()
}

// Add one torrent ten thousand times in parallel (depending on the set worker threads)
pub async fn update_one_torrent_in_parallel<V, T>(runtime: &tokio::runtime::Runtime, samples: u64, sleep: Option<u64>) -> Duration
where
    V: Repository<T> + Default,
    Arc<V>: Clone + Send + Sync + 'static,
{
    let torrent_repository = Arc::<V>::default();
    let info_hash = InfoHash::default();
    let handles = FuturesUnordered::new();

    // Add the torrent/peer to the torrent repository
    torrent_repository.upsert_peer(&info_hash, &DEFAULT_PEER);

    torrent_repository.get_swarm_metadata(&info_hash);

    let start = Instant::now();

    for _ in 0..samples {
        let torrent_repository_clone = torrent_repository.clone();

        let handle = runtime.spawn(async move {
            torrent_repository_clone.upsert_peer(&info_hash, &DEFAULT_PEER);

            torrent_repository_clone.get_swarm_metadata(&info_hash);

            if let Some(sleep_time) = sleep {
                let start_time = std::time::Instant::now();

                while start_time.elapsed().as_nanos() < u128::from(sleep_time) {}
            }
        });

        handles.push(handle);
    }

    // Await all tasks
    futures::future::join_all(handles).await;

    start.elapsed()
}

// Add ten thousand torrents in parallel (depending on the set worker threads)
pub async fn add_multiple_torrents_in_parallel<V, T>(
    runtime: &tokio::runtime::Runtime,
    samples: u64,
    sleep: Option<u64>,
) -> Duration
where
    V: Repository<T> + Default,
    Arc<V>: Clone + Send + Sync + 'static,
{
    let torrent_repository = Arc::<V>::default();
    let info_hashes = generate_unique_info_hashes(samples.try_into().expect("it should fit in a usize"));
    let handles = FuturesUnordered::new();

    let start = Instant::now();

    for info_hash in info_hashes {
        let torrent_repository_clone = torrent_repository.clone();

        let handle = runtime.spawn(async move {
            torrent_repository_clone.upsert_peer(&info_hash, &DEFAULT_PEER);

            torrent_repository_clone.get_swarm_metadata(&info_hash);

            if let Some(sleep_time) = sleep {
                let start_time = std::time::Instant::now();

                while start_time.elapsed().as_nanos() < u128::from(sleep_time) {}
            }
        });

        handles.push(handle);
    }

    // Await all tasks
    futures::future::join_all(handles).await;

    start.elapsed()
}

// Update ten thousand torrents in parallel (depending on the set worker threads)
pub async fn update_multiple_torrents_in_parallel<V, T>(
    runtime: &tokio::runtime::Runtime,
    samples: u64,
    sleep: Option<u64>,
) -> Duration
where
    V: Repository<T> + Default,
    Arc<V>: Clone + Send + Sync + 'static,
{
    let torrent_repository = Arc::<V>::default();
    let info_hashes = generate_unique_info_hashes(samples.try_into().expect("it should fit in usize"));
    let handles = FuturesUnordered::new();

    // Add the torrents/peers to the torrent repository
    for info_hash in &info_hashes {
        torrent_repository.upsert_peer(info_hash, &DEFAULT_PEER);
        torrent_repository.get_swarm_metadata(info_hash);
    }

    let start = Instant::now();

    for info_hash in info_hashes {
        let torrent_repository_clone = torrent_repository.clone();

        let handle = runtime.spawn(async move {
            torrent_repository_clone.upsert_peer(&info_hash, &DEFAULT_PEER);
            torrent_repository_clone.get_swarm_metadata(&info_hash);

            if let Some(sleep_time) = sleep {
                let start_time = std::time::Instant::now();

                while start_time.elapsed().as_nanos() < u128::from(sleep_time) {}
            }
        });

        handles.push(handle);
    }

    // Await all tasks
    futures::future::join_all(handles).await;

    start.elapsed()
}
