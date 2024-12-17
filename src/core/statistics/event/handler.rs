use crate::core::statistics::event::Event;
use crate::core::statistics::repository::Repository;

pub async fn handle_event(event: Event, stats_repository: &Repository) {
    match event {
        // TCP4
        Event::Tcp4Announce => {
            stats_repository.increase_tcp4_announces();
            stats_repository.increase_tcp4_connections();
        }
        Event::Tcp4Scrape => {
            stats_repository.increase_tcp4_scrapes();
            stats_repository.increase_tcp4_connections();
        }

        // TCP6
        Event::Tcp6Announce => {
            stats_repository.increase_tcp6_announces();
            stats_repository.increase_tcp6_connections();
        }
        Event::Tcp6Scrape => {
            stats_repository.increase_tcp6_scrapes();
            stats_repository.increase_tcp6_connections();
        }

        // UDP
        Event::Udp4RequestAborted => {
            stats_repository.increase_udp_requests_aborted();
        }

        // UDP4
        Event::Udp4Request => {
            stats_repository.increase_udp4_requests();
        }
        Event::Udp4Connect => {
            stats_repository.increase_udp4_connections();
        }
        Event::Udp4Announce => {
            stats_repository.increase_udp4_announces();
        }
        Event::Udp4Scrape => {
            stats_repository.increase_udp4_scrapes();
        }
        Event::Udp4Response => {
            stats_repository.increase_udp4_responses();
        }
        Event::Udp4Error => {
            stats_repository.increase_udp4_errors();
        }

        // UDP6
        Event::Udp6Request => {
            stats_repository.increase_udp6_requests();
        }
        Event::Udp6Connect => {
            stats_repository.increase_udp6_connections();
        }
        Event::Udp6Announce => {
            stats_repository.increase_udp6_announces();
        }
        Event::Udp6Scrape => {
            stats_repository.increase_udp6_scrapes();
        }
        Event::Udp6Response => {
            stats_repository.increase_udp6_responses();
        }
        Event::Udp6Error => {
            stats_repository.increase_udp6_errors();
        }
    }

    tracing::debug!("stats: {:?}", stats_repository.get_stats());
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

        let stats = stats_repository.get_stats();

        assert_eq!(stats.tcp4_announces_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp4_connections_counter_when_it_receives_a_tcp4_announce_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp4Announce, &stats_repository).await;

        let stats = stats_repository.get_stats();

        assert_eq!(stats.tcp4_connections_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp4_scrapes_counter_when_it_receives_a_tcp4_scrape_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp4Scrape, &stats_repository).await;

        let stats = stats_repository.get_stats();

        assert_eq!(stats.tcp4_scrapes_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp4_connections_counter_when_it_receives_a_tcp4_scrape_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp4Scrape, &stats_repository).await;

        let stats = stats_repository.get_stats();

        assert_eq!(stats.tcp4_connections_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp6_announces_counter_when_it_receives_a_tcp6_announce_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp6Announce, &stats_repository).await;

        let stats = stats_repository.get_stats();

        assert_eq!(stats.tcp6_announces_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp6_connections_counter_when_it_receives_a_tcp6_announce_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp6Announce, &stats_repository).await;

        let stats = stats_repository.get_stats();

        assert_eq!(stats.tcp6_connections_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp6_scrapes_counter_when_it_receives_a_tcp6_scrape_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp6Scrape, &stats_repository).await;

        let stats = stats_repository.get_stats();

        assert_eq!(stats.tcp6_scrapes_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_tcp6_connections_counter_when_it_receives_a_tcp6_scrape_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Tcp6Scrape, &stats_repository).await;

        let stats = stats_repository.get_stats();

        assert_eq!(stats.tcp6_connections_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_udp4_connections_counter_when_it_receives_a_udp4_connect_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Udp4Connect, &stats_repository).await;

        let stats = stats_repository.get_stats();

        assert_eq!(stats.udp4_connections_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_udp4_announces_counter_when_it_receives_a_udp4_announce_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Udp4Announce, &stats_repository).await;

        let stats = stats_repository.get_stats();

        assert_eq!(stats.udp4_announces_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_udp4_scrapes_counter_when_it_receives_a_udp4_scrape_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Udp4Scrape, &stats_repository).await;

        let stats = stats_repository.get_stats();

        assert_eq!(stats.udp4_scrapes_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_udp6_connections_counter_when_it_receives_a_udp6_connect_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Udp6Connect, &stats_repository).await;

        let stats = stats_repository.get_stats();

        assert_eq!(stats.udp6_connections_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_udp6_announces_counter_when_it_receives_a_udp6_announce_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Udp6Announce, &stats_repository).await;

        let stats = stats_repository.get_stats();

        assert_eq!(stats.udp6_announces_handled, 1);
    }

    #[tokio::test]
    async fn should_increase_the_udp6_scrapes_counter_when_it_receives_a_udp6_scrape_event() {
        let stats_repository = Repository::new();

        handle_event(Event::Udp6Scrape, &stats_repository).await;

        let stats = stats_repository.get_stats();

        assert_eq!(stats.udp6_scrapes_handled, 1);
    }
}
