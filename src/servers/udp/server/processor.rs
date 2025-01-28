use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use aquatic_udp_protocol::Response;
use tokio::sync::RwLock;
use tokio::time::Instant;
use torrust_tracker_configuration::Core;
use tracing::{instrument, Level};

use super::banning::BanService;
use super::bound_socket::BoundSocket;
use crate::core::announce_handler::AnnounceHandler;
use crate::core::scrape_handler::ScrapeHandler;
use crate::core::statistics::event::sender::Sender;
use crate::core::statistics::event::UdpResponseKind;
use crate::core::{statistics, whitelist};
use crate::servers::udp::handlers::CookieTimeValues;
use crate::servers::udp::{handlers, RawRequest};

pub struct Processor {
    socket: Arc<BoundSocket>,
    core_config: Arc<Core>,
    announce_handler: Arc<AnnounceHandler>,
    scrape_handler: Arc<ScrapeHandler>,
    whitelist_authorization: Arc<whitelist::authorization::WhitelistAuthorization>,
    opt_stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    cookie_lifetime: f64,
}

impl Processor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket: Arc<BoundSocket>,
        core_config: Arc<Core>,
        announce_handler: Arc<AnnounceHandler>,
        scrape_handler: Arc<ScrapeHandler>,
        whitelist_authorization: Arc<whitelist::authorization::WhitelistAuthorization>,
        opt_stats_event_sender: Arc<Option<Box<dyn Sender>>>,
        cookie_lifetime: f64,
    ) -> Self {
        Self {
            socket,
            core_config,
            announce_handler,
            scrape_handler,
            whitelist_authorization,
            opt_stats_event_sender,
            cookie_lifetime,
        }
    }

    #[instrument(skip(self, request, ban_service))]
    pub async fn process_request(self, request: RawRequest, ban_service: Arc<RwLock<BanService>>) {
        let from = request.from;

        let start_time = Instant::now();

        let response = handlers::handle_packet(
            request,
            &self.core_config,
            &self.announce_handler,
            &self.scrape_handler,
            &self.whitelist_authorization,
            &self.opt_stats_event_sender,
            self.socket.address(),
            CookieTimeValues::new(self.cookie_lifetime),
            ban_service,
        )
        .await;

        let elapsed_time = start_time.elapsed();

        self.send_response(from, response, elapsed_time).await;
    }

    #[instrument(skip(self))]
    async fn send_response(self, target: SocketAddr, response: Response, req_processing_time: Duration) {
        tracing::debug!("send response");

        let response_type = match &response {
            Response::Connect(_) => "Connect".to_string(),
            Response::AnnounceIpv4(_) => "AnnounceIpv4".to_string(),
            Response::AnnounceIpv6(_) => "AnnounceIpv6".to_string(),
            Response::Scrape(_) => "Scrape".to_string(),
            Response::Error(e) => format!("Error: {e:?}"),
        };

        let response_kind = match &response {
            Response::Connect(_) => UdpResponseKind::Connect,
            Response::AnnounceIpv4(_) | Response::AnnounceIpv6(_) => UdpResponseKind::Announce,
            Response::Scrape(_) => UdpResponseKind::Scrape,
            Response::Error(_e) => UdpResponseKind::Error,
        };

        let mut writer = Cursor::new(Vec::with_capacity(200));

        match response.write_bytes(&mut writer) {
            Ok(()) => {
                let bytes_count = writer.get_ref().len();
                let payload = writer.get_ref();

                let () = match self.send_packet(&target, payload).await {
                    Ok(sent_bytes) => {
                        if tracing::event_enabled!(Level::TRACE) {
                            tracing::debug!(%bytes_count, %sent_bytes, ?payload, "sent {response_type}");
                        } else {
                            tracing::debug!(%bytes_count, %sent_bytes, "sent {response_type}");
                        }

                        if let Some(stats_event_sender) = self.opt_stats_event_sender.as_deref() {
                            match target.ip() {
                                IpAddr::V4(_) => {
                                    stats_event_sender
                                        .send_event(statistics::event::Event::Udp4Response {
                                            kind: response_kind,
                                            req_processing_time,
                                        })
                                        .await;
                                }
                                IpAddr::V6(_) => {
                                    stats_event_sender
                                        .send_event(statistics::event::Event::Udp6Response {
                                            kind: response_kind,
                                            req_processing_time,
                                        })
                                        .await;
                                }
                            }
                        }
                    }
                    Err(error) => tracing::warn!(%bytes_count, %error, ?payload, "failed to send"),
                };
            }
            Err(e) => {
                tracing::error!(%e, "error");
            }
        }
    }

    #[instrument(skip(self))]
    async fn send_packet(&self, target: &SocketAddr, payload: &[u8]) -> std::io::Result<usize> {
        tracing::trace!("send packet");

        // doesn't matter if it reaches or not
        self.socket.send_to(payload, target).await
    }
}
