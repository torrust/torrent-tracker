use torrust_tracker_lib::{app, bootstrap};

#[tokio::main]
async fn main() {
    let (config, tracker, ban_service) = bootstrap::app::setup();

    let jobs = app::start(&config, tracker, ban_service).await;

    // handle the signals
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Torrust shutting down ...");

            // Await for all jobs to shutdown
            futures::future::join_all(jobs).await;
            tracing::info!("Torrust successfully shutdown.");
        }
    }
}
