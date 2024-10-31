use std::collections::{BTreeMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes};
use bittorrent_primitives::info_hash::InfoHash;
use rstest::{fixture, rstest};
use torrust_tracker_configuration::TrackerPolicy;
use torrust_tracker_primitives::pagination::Pagination;
use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;
use torrust_tracker_primitives::PersistentTorrents;
use torrust_tracker_torrent_repository::entry::Entry as _;
use torrust_tracker_torrent_repository::repository::dash_map_mutex_std::XacrimonDashMap;
use torrust_tracker_torrent_repository::repository::rw_lock_std::RwLockStd;
use torrust_tracker_torrent_repository::repository::rw_lock_tokio::RwLockTokio;
use torrust_tracker_torrent_repository::repository::skip_map_mutex_std::CrossbeamSkipList;
use torrust_tracker_torrent_repository::EntrySingle;

use crate::common::repo::Repo;
use crate::common::torrent_peer_builder::{a_completed_peer, a_started_peer};

#[fixture]
fn standard() -> Repo {
    Repo::RwLockStd(RwLockStd::default())
}

#[fixture]
fn standard_mutex() -> Repo {
    Repo::RwLockStdMutexStd(RwLockStd::default())
}

#[fixture]
fn standard_tokio() -> Repo {
    Repo::RwLockStdMutexTokio(RwLockStd::default())
}

#[fixture]
fn tokio_std() -> Repo {
    Repo::RwLockTokio(RwLockTokio::default())
}

#[fixture]
fn tokio_mutex() -> Repo {
    Repo::RwLockTokioMutexStd(RwLockTokio::default())
}

#[fixture]
fn tokio_tokio() -> Repo {
    Repo::RwLockTokioMutexTokio(RwLockTokio::default())
}

#[fixture]
fn skip_list_mutex_std() -> Repo {
    Repo::SkipMapMutexStd(CrossbeamSkipList::default())
}

#[fixture]
fn skip_list_mutex_parking_lot() -> Repo {
    Repo::SkipMapMutexParkingLot(CrossbeamSkipList::default())
}

#[fixture]
fn skip_list_rw_lock_parking_lot() -> Repo {
    Repo::SkipMapRwLockParkingLot(CrossbeamSkipList::default())
}

#[fixture]
fn dash_map_std() -> Repo {
    Repo::DashMapMutexStd(XacrimonDashMap::default())
}

type Entries = Vec<(InfoHash, EntrySingle)>;

#[fixture]
fn empty() -> Entries {
    vec![]
}

#[fixture]
fn default() -> Entries {
    vec![(InfoHash::default(), EntrySingle::default())]
}

#[fixture]
fn started() -> Entries {
    let mut torrent = EntrySingle::default();
    torrent.upsert_peer(&a_started_peer(1));
    vec![(InfoHash::default(), torrent)]
}

#[fixture]
fn completed() -> Entries {
    let mut torrent = EntrySingle::default();
    torrent.upsert_peer(&a_completed_peer(2));
    vec![(InfoHash::default(), torrent)]
}

#[fixture]
fn downloaded() -> Entries {
    let mut torrent = EntrySingle::default();
    let mut peer = a_started_peer(3);
    torrent.upsert_peer(&peer);
    peer.event = AnnounceEvent::Completed;
    peer.left = NumberOfBytes::new(0);
    torrent.upsert_peer(&peer);
    vec![(InfoHash::default(), torrent)]
}

#[fixture]
fn three() -> Entries {
    let mut started = EntrySingle::default();
    let started_h = &mut DefaultHasher::default();
    started.upsert_peer(&a_started_peer(1));
    started.hash(started_h);

    let mut completed = EntrySingle::default();
    let completed_h = &mut DefaultHasher::default();
    completed.upsert_peer(&a_completed_peer(2));
    completed.hash(completed_h);

    let mut downloaded = EntrySingle::default();
    let downloaded_h = &mut DefaultHasher::default();
    let mut downloaded_peer = a_started_peer(3);
    downloaded.upsert_peer(&downloaded_peer);
    downloaded_peer.event = AnnounceEvent::Completed;
    downloaded_peer.left = NumberOfBytes::new(0);
    downloaded.upsert_peer(&downloaded_peer);
    downloaded.hash(downloaded_h);

    vec![
        (InfoHash::from(&started_h.clone()), started),
        (InfoHash::from(&completed_h.clone()), completed),
        (InfoHash::from(&downloaded_h.clone()), downloaded),
    ]
}

#[fixture]
fn many_out_of_order() -> Entries {
    let mut entries: HashSet<(InfoHash, EntrySingle)> = HashSet::default();

    for i in 0..408 {
        let mut entry = EntrySingle::default();
        entry.upsert_peer(&a_started_peer(i));

        entries.insert((InfoHash::from(&i), entry));
    }

    // we keep the random order from the hashed set for the vector.
    entries.iter().map(|(i, e)| (*i, e.clone())).collect()
}

#[fixture]
fn many_hashed_in_order() -> Entries {
    let mut entries: BTreeMap<InfoHash, EntrySingle> = BTreeMap::default();

    for i in 0..408 {
        let mut entry = EntrySingle::default();
        entry.upsert_peer(&a_started_peer(i));

        let hash: &mut DefaultHasher = &mut DefaultHasher::default();
        hash.write_i32(i);

        entries.insert(InfoHash::from(&hash.clone()), entry);
    }

    // We return the entries in-order from from the b-tree map.
    entries.iter().map(|(i, e)| (*i, e.clone())).collect()
}

#[fixture]
fn persistent_empty() -> PersistentTorrents {
    PersistentTorrents::default()
}

#[fixture]
fn persistent_single() -> PersistentTorrents {
    let hash = &mut DefaultHasher::default();

    hash.write_u8(1);
    let t = [(InfoHash::from(&hash.clone()), 0_u32)];

    t.iter().copied().collect()
}

#[fixture]
fn persistent_three() -> PersistentTorrents {
    let hash = &mut DefaultHasher::default();

    hash.write_u8(1);
    let info_1 = InfoHash::from(&hash.clone());
    hash.write_u8(2);
    let info_2 = InfoHash::from(&hash.clone());
    hash.write_u8(3);
    let info_3 = InfoHash::from(&hash.clone());

    let t = [(info_1, 1_u32), (info_2, 2_u32), (info_3, 3_u32)];

    t.iter().copied().collect()
}

async fn make(repo: &Repo, entries: &Entries) {
    for (info_hash, entry) in entries {
        repo.insert(info_hash, entry.clone()).await;
    }
}

#[fixture]
fn paginated_limit_zero() -> Pagination {
    Pagination::new(0, 0)
}

#[fixture]
fn paginated_limit_one() -> Pagination {
    Pagination::new(0, 1)
}

#[fixture]
fn paginated_limit_one_offset_one() -> Pagination {
    Pagination::new(1, 1)
}

#[fixture]
fn policy_none() -> TrackerPolicy {
    TrackerPolicy::new(0, false, false)
}

#[fixture]
fn policy_persist() -> TrackerPolicy {
    TrackerPolicy::new(0, true, false)
}

#[fixture]
fn policy_remove() -> TrackerPolicy {
    TrackerPolicy::new(0, false, true)
}

#[fixture]
fn policy_remove_persist() -> TrackerPolicy {
    TrackerPolicy::new(0, true, true)
}

#[rstest]
#[case::empty(empty())]
#[case::default(default())]
#[case::started(started())]
#[case::completed(completed())]
#[case::downloaded(downloaded())]
#[case::three(three())]
#[case::out_of_order(many_out_of_order())]
#[case::in_order(many_hashed_in_order())]
#[tokio::test]
async fn it_should_get_a_torrent_entry(
    #[values(
        standard(),
        standard_mutex(),
        standard_tokio(),
        tokio_std(),
        tokio_mutex(),
        tokio_tokio(),
        skip_list_mutex_std(),
        skip_list_mutex_parking_lot(),
        skip_list_rw_lock_parking_lot(),
        dash_map_std()
    )]
    repo: Repo,
    #[case] entries: Entries,
) {
    make(&repo, &entries).await;

    if let Some((info_hash, torrent)) = entries.first() {
        assert_eq!(repo.get(info_hash).await, Some(torrent.clone()));
    } else {
        assert_eq!(repo.get(&InfoHash::default()).await, None);
    }
}

#[rstest]
#[case::empty(empty())]
#[case::default(default())]
#[case::started(started())]
#[case::completed(completed())]
#[case::downloaded(downloaded())]
#[case::three(three())]
#[case::out_of_order(many_out_of_order())]
#[case::in_order(many_hashed_in_order())]
#[tokio::test]
async fn it_should_get_paginated_entries_in_a_stable_or_sorted_order(
    #[values(
        standard(),
        standard_mutex(),
        standard_tokio(),
        tokio_std(),
        tokio_mutex(),
        tokio_tokio(),
        skip_list_mutex_std(),
        skip_list_mutex_parking_lot(),
        skip_list_rw_lock_parking_lot()
    )]
    repo: Repo,
    #[case] entries: Entries,
    many_out_of_order: Entries,
) {
    make(&repo, &entries).await;

    let entries_a = repo.get_paginated(None).await.iter().map(|(i, _)| *i).collect::<Vec<_>>();

    make(&repo, &many_out_of_order).await;

    let entries_b = repo.get_paginated(None).await.iter().map(|(i, _)| *i).collect::<Vec<_>>();

    let is_equal = entries_b.iter().take(entries_a.len()).copied().collect::<Vec<_>>() == entries_a;

    let is_sorted = entries_b.windows(2).all(|w| w[0] <= w[1]);

    assert!(
        is_equal || is_sorted,
        "The order is unstable: {is_equal}, or is sorted {is_sorted}."
    );
}

#[rstest]
#[case::empty(empty())]
#[case::default(default())]
#[case::started(started())]
#[case::completed(completed())]
#[case::downloaded(downloaded())]
#[case::three(three())]
#[case::out_of_order(many_out_of_order())]
#[case::in_order(many_hashed_in_order())]
#[tokio::test]
async fn it_should_get_paginated(
    #[values(
        standard(),
        standard_mutex(),
        standard_tokio(),
        tokio_std(),
        tokio_mutex(),
        tokio_tokio(),
        skip_list_mutex_std(),
        skip_list_mutex_parking_lot(),
        skip_list_rw_lock_parking_lot()
    )]
    repo: Repo,
    #[case] entries: Entries,
    #[values(paginated_limit_zero(), paginated_limit_one(), paginated_limit_one_offset_one())] paginated: Pagination,
) {
    make(&repo, &entries).await;

    let mut info_hashes = repo.get_paginated(None).await.iter().map(|(i, _)| *i).collect::<Vec<_>>();
    info_hashes.sort();

    match paginated {
        // it should return empty if limit is zero.
        Pagination { limit: 0, .. } => assert_eq!(repo.get_paginated(Some(&paginated)).await, vec![]),

        // it should return a single entry if the limit is one.
        Pagination { limit: 1, offset: 0 } => {
            if info_hashes.is_empty() {
                assert_eq!(repo.get_paginated(Some(&paginated)).await.len(), 0);
            } else {
                let page = repo.get_paginated(Some(&paginated)).await;
                assert_eq!(page.len(), 1);
                assert_eq!(page.first().map(|(i, _)| i), info_hashes.first());
            }
        }

        // it should return the only the second entry if both the limit and the offset are one.
        Pagination { limit: 1, offset: 1 } => {
            if info_hashes.len() > 1 {
                let page = repo.get_paginated(Some(&paginated)).await;
                assert_eq!(page.len(), 1);
                assert_eq!(page[0].0, info_hashes[1]);
            }
        }
        // the other cases are not yet tested.
        _ => {}
    }
}

#[rstest]
#[case::empty(empty())]
#[case::default(default())]
#[case::started(started())]
#[case::completed(completed())]
#[case::downloaded(downloaded())]
#[case::three(three())]
#[case::out_of_order(many_out_of_order())]
#[case::in_order(many_hashed_in_order())]
#[tokio::test]
async fn it_should_get_metrics(
    #[values(
        standard(),
        standard_mutex(),
        standard_tokio(),
        tokio_std(),
        tokio_mutex(),
        tokio_tokio(),
        skip_list_mutex_std(),
        skip_list_mutex_parking_lot(),
        skip_list_rw_lock_parking_lot(),
        dash_map_std()
    )]
    repo: Repo,
    #[case] entries: Entries,
) {
    use torrust_tracker_primitives::torrent_metrics::TorrentsMetrics;

    make(&repo, &entries).await;

    let mut metrics = TorrentsMetrics::default();

    for (_, torrent) in entries {
        let stats = torrent.get_swarm_metadata();

        metrics.torrents += 1;
        metrics.incomplete += u64::from(stats.incomplete);
        metrics.complete += u64::from(stats.complete);
        metrics.downloaded += u64::from(stats.downloaded);
    }

    assert_eq!(repo.get_metrics().await, metrics);
}

#[rstest]
#[case::empty(empty())]
#[case::default(default())]
#[case::started(started())]
#[case::completed(completed())]
#[case::downloaded(downloaded())]
#[case::three(three())]
#[case::out_of_order(many_out_of_order())]
#[case::in_order(many_hashed_in_order())]
#[tokio::test]
async fn it_should_import_persistent_torrents(
    #[values(
        standard(),
        standard_mutex(),
        standard_tokio(),
        tokio_std(),
        tokio_mutex(),
        tokio_tokio(),
        skip_list_mutex_std(),
        skip_list_mutex_parking_lot(),
        skip_list_rw_lock_parking_lot(),
        dash_map_std()
    )]
    repo: Repo,
    #[case] entries: Entries,
    #[values(persistent_empty(), persistent_single(), persistent_three())] persistent_torrents: PersistentTorrents,
) {
    make(&repo, &entries).await;

    let mut downloaded = repo.get_metrics().await.downloaded;
    persistent_torrents.iter().for_each(|(_, d)| downloaded += u64::from(*d));

    repo.import_persistent(&persistent_torrents).await;

    assert_eq!(repo.get_metrics().await.downloaded, downloaded);

    for (entry, _) in persistent_torrents {
        assert!(repo.get(&entry).await.is_some());
    }
}

#[rstest]
#[case::empty(empty())]
#[case::default(default())]
#[case::started(started())]
#[case::completed(completed())]
#[case::downloaded(downloaded())]
#[case::three(three())]
#[case::out_of_order(many_out_of_order())]
#[case::in_order(many_hashed_in_order())]
#[tokio::test]
async fn it_should_remove_an_entry(
    #[values(
        standard(),
        standard_mutex(),
        standard_tokio(),
        tokio_std(),
        tokio_mutex(),
        tokio_tokio(),
        skip_list_mutex_std(),
        skip_list_mutex_parking_lot(),
        skip_list_rw_lock_parking_lot(),
        dash_map_std()
    )]
    repo: Repo,
    #[case] entries: Entries,
) {
    make(&repo, &entries).await;

    for (info_hash, torrent) in entries {
        assert_eq!(repo.get(&info_hash).await, Some(torrent.clone()));
        assert_eq!(repo.remove(&info_hash).await, Some(torrent));

        assert_eq!(repo.get(&info_hash).await, None);
        assert_eq!(repo.remove(&info_hash).await, None);
    }

    assert_eq!(repo.get_metrics().await.torrents, 0);
}

#[rstest]
#[case::empty(empty())]
#[case::default(default())]
#[case::started(started())]
#[case::completed(completed())]
#[case::downloaded(downloaded())]
#[case::three(three())]
#[case::out_of_order(many_out_of_order())]
#[case::in_order(many_hashed_in_order())]
#[tokio::test]
async fn it_should_remove_inactive_peers(
    #[values(
        standard(),
        standard_mutex(),
        standard_tokio(),
        tokio_std(),
        tokio_mutex(),
        tokio_tokio(),
        skip_list_mutex_std(),
        skip_list_mutex_parking_lot(),
        skip_list_rw_lock_parking_lot(),
        dash_map_std()
    )]
    repo: Repo,
    #[case] entries: Entries,
) {
    use std::ops::Sub as _;
    use std::time::Duration;

    use torrust_tracker_clock::clock::stopped::Stopped as _;
    use torrust_tracker_clock::clock::{self, Time as _};
    use torrust_tracker_primitives::peer;

    use crate::CurrentClock;

    const TIMEOUT: Duration = Duration::from_secs(120);
    const EXPIRE: Duration = Duration::from_secs(121);

    make(&repo, &entries).await;

    let info_hash: InfoHash;
    let mut peer: peer::Peer;

    // Generate a new infohash and peer.
    {
        let hash = &mut DefaultHasher::default();
        hash.write_u8(255);
        info_hash = InfoHash::from(&hash.clone());
        peer = a_completed_peer(-1);
    }

    // Set the last updated time of the peer to be 121 seconds ago.
    {
        let now = clock::Working::now();
        clock::Stopped::local_set(&now);

        peer.updated = now.sub(EXPIRE);
    }

    // Insert the infohash and peer into the repository
    // and verify there is an extra torrent entry.
    {
        repo.upsert_peer(&info_hash, &peer).await;
        assert_eq!(repo.get_metrics().await.torrents, entries.len() as u64 + 1);
    }

    // Insert the infohash and peer into the repository
    // and verify the swarm metadata was updated.
    {
        repo.upsert_peer(&info_hash, &peer).await;
        let stats = repo.get_swarm_metadata(&info_hash).await;
        assert_eq!(
            stats,
            Some(SwarmMetadata {
                downloaded: 0,
                complete: 1,
                incomplete: 0
            })
        );
    }

    // Verify that this new peer was inserted into the repository.
    {
        let entry = repo.get(&info_hash).await.expect("it_should_get_some");
        assert!(entry.get_peers(None).contains(&peer.into()));
    }

    // Remove peers that have not been updated since the timeout (120 seconds ago).
    {
        repo.remove_inactive_peers(CurrentClock::now_sub(&TIMEOUT).expect("it should get a time passed"))
            .await;
    }

    // Verify that the this peer was removed from the repository.
    {
        let entry = repo.get(&info_hash).await.expect("it_should_get_some");
        assert!(!entry.get_peers(None).contains(&peer.into()));
    }
}

#[rstest]
#[case::empty(empty())]
#[case::default(default())]
#[case::started(started())]
#[case::completed(completed())]
#[case::downloaded(downloaded())]
#[case::three(three())]
#[case::out_of_order(many_out_of_order())]
#[case::in_order(many_hashed_in_order())]
#[tokio::test]
async fn it_should_remove_peerless_torrents(
    #[values(
        standard(),
        standard_mutex(),
        standard_tokio(),
        tokio_std(),
        tokio_mutex(),
        tokio_tokio(),
        skip_list_mutex_std(),
        skip_list_mutex_parking_lot(),
        skip_list_rw_lock_parking_lot(),
        dash_map_std()
    )]
    repo: Repo,
    #[case] entries: Entries,
    #[values(policy_none(), policy_persist(), policy_remove(), policy_remove_persist())] policy: TrackerPolicy,
) {
    make(&repo, &entries).await;

    repo.remove_peerless_torrents(&policy).await;

    let torrents = repo.get_paginated(None).await;

    for (_, entry) in torrents {
        assert!(entry.meets_retaining_policy(&policy));
    }
}
