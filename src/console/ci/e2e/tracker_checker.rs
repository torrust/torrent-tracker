use std::io;
use std::process::Command;

/// Runs the Tracker Checker.
///
/// # Errors
///
/// Will return an error if the Tracker Checker fails.
pub fn run(config_content: &str) -> io::Result<()> {
    tracing::info!(
        "Running Tracker Checker: TORRUST_CHECKER_CONFIG=[config] cargo run -p bittorrent-tracker-client --bin tracker_checker"
    );
    tracing::info!("Tracker Checker config:\n{config_content}");

    let status = Command::new("cargo")
        .env("TORRUST_CHECKER_CONFIG", config_content)
        .args(["run", "-p", "bittorrent-tracker-client", "--bin", "tracker_checker"])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "Failed to run Tracker Checker"))
    }
}
