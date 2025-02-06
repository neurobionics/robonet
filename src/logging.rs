use anyhow::{Context, Result};
use tracing_subscriber::EnvFilter;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

pub const LOG_DIR: &str = "/var/log/robonet";

pub fn setup_logging() -> Result<()> {
    // Create log directory if it doesn't exist
    std::fs::create_dir_all(LOG_DIR)
        .context("Failed to create log directory")?;

    // Main application log file
    let main_appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("main")
        .filename_suffix("log")
        .max_log_files(7)
        .build(LOG_DIR)
        .context("Failed to create main file appender")?;

    // Set up the subscriber with the appender
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive(tracing::Level::INFO.into())
            .add_directive(tracing::Level::DEBUG.into()))
        .with_writer(main_appender)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_target(false)
        .compact()
        .init();

    Ok(())
}
