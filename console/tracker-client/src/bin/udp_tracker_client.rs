//! Program to make request to UDP trackers.
use torrust_tracker_client::console::clients::udp::app;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    app::run().await
}
