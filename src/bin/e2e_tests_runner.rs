//! Program to run E2E tests.
use torrust_tracker_lib::console::ci::e2e;

fn main() -> anyhow::Result<()> {
    e2e::runner::run()
}
