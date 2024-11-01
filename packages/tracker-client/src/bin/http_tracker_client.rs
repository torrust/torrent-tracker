//! Program to make request to HTTP trackers.
use bittorrent_tracker_client::console::clients::http::app;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    app::run().await
}
