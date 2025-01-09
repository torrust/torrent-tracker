use crate::core::statistics::event::{Event, UdpResponseKind};
use crate::core::statistics::repository::Repository;

pub async fn handle_event(event: Event, stats_repository: &Repository) {
    match event {
        // TCP4
        Event::Tcp4Announce => {
            stats_repository.increase_tcp4_announces().await;
            stats_repository.increase_tcp4_connections().await;
        }
        Event::Tcp4Scrape => {
            stats_repository.increase_tcp4_scrapes().await;
            stats_repository.increase_tcp4_connections().await;
        }

        // TCP6
        Event::Tcp6Announce => {
            stats_repository.increase_tcp6_announces().await;
            stats_repository.increase_tcp6_connections().await;
        }
        Event::Tcp6Scrape => {
            stats_repository.increase_tcp6_scrapes().await;
            stats_repository.increase_tcp6_connections().await;
        }

        // UDP
        Event::UdpRequestAborted => {
            stats_repository.increase_udp_requests_aborted().await;
        }
        Event::UdpRequestBanned => {
            stats_repository.increase_udp_requests_banned().await;
        }

        // UDP4
        Event::Udp4Request => {
            stats_repository.increase_udp4_requests().await;
        }
        Event::Udp4Connect => {
            stats_repository.increase_udp4_connections().await;
        }
        Event::Udp4Announce => {
            stats_repository.increase_udp4_announces().await;
        }
        Event::Udp4Scrape => {
            stats_repository.increase_udp4_scrapes().await;
        }
        Event::Udp4Response {
            kind,
            req_processing_time,
        } => {
            stats_repository.increase_udp4_responses().await;

            match kind {
                UdpResponseKind::Connect => {
                    stats_repository
                        .recalculate_udp_avg_connect_processing_time_ns(req_processing_time)
                        .await;
                }
                UdpResponseKind::Announce => {
                    stats_repository
                        .recalculate_udp_avg_announce_processing_time_ns(req_processing_time)
                        .await;
                }
                UdpResponseKind::Scrape => {
                    stats_repository
                        .recalculate_udp_avg_scrape_processing_time_ns(req_processing_time)
                        .await;
                }
                UdpResponseKind::Error => {}
            }
        }
        Event::Udp4Error => {
            stats_repository.increase_udp4_errors().await;
        }

        // UDP6
        Event::Udp6Request => {
            stats_repository.increase_udp6_requests().await;
        }
        Event::Udp6Connect => {
            stats_repository.increase_udp6_connections().await;
        }
        Event::Udp6Announce => {
            stats_repository.increase_udp6_announces().await;
        }
        Event::Udp6Scrape => {
            stats_repository.increase_udp6_scrapes().await;
        }
        Event::Udp6Response {
            kind: _,
            req_processing_time: _,
        } => {
            stats_repository.increase_udp6_responses().await;
        }
        Event::Udp6Error => {
            stats_repository.increase_udp6_errors().await;
        }
    }

    tracing::debug!("stats: {:?}", stats_repository.get_stats().await);
}

#[cfg(test)]
mod tests {
    use crate::core::statistics::event::handler::handle_event;
    use crate::core::statistics::event::Event;
    use crate::core::statistics::repository::Repository;

    #[tokio::test]
    async fn should_increase_the_tcp4_announces_counter_when_it_receives_a_tcp4_announce_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp4Announce, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.tcp4_announces_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp4_connections_counter_when_it_receives_a_tcp4_announce_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp4Announce, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.tcp4_connections_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp4_scrapes_counter_when_it_receives_a_tcp4_scrape_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp4Scrape, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.tcp4_scrapes_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp4_connections_counter_when_it_receives_a_tcp4_scrape_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp4Scrape, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.tcp4_connections_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp6_announces_counter_when_it_receives_a_tcp6_announce_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp6Announce, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.tcp6_announces_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp6_connections_counter_when_it_receives_a_tcp6_announce_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp6Announce, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.tcp6_connections_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp6_scrapes_counter_when_it_receives_a_tcp6_scrape_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp6Scrape, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.tcp6_scrapes_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp6_connections_counter_when_it_receives_a_tcp6_scrape_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp6Scrape, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.tcp6_connections_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_udp4_connections_counter_when_it_receives_a_udp4_connect_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Udp4Connect, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.udp4_connections_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_udp4_announces_counter_when_it_receives_a_udp4_announce_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Udp4Announce, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.udp4_announces_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_udp4_scrapes_counter_when_it_receives_a_udp4_scrape_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Udp4Scrape, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.udp4_scrapes_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_udp6_connections_counter_when_it_receives_a_udp6_connect_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Udp6Connect, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.udp6_connections_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_udp6_announces_counter_when_it_receives_a_udp6_announce_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Udp6Announce, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.udp6_announces_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_udp6_scrapes_counter_when_it_receives_a_udp6_scrape_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Udp6Scrape, &stats_repository).await;

        let stats = stats_repository.get_stats().await;

        assert_eq!(stats.udp6_scrapes_handled, 1);
    }
}
