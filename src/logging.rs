use anyhow::{Context, Result};
use tracing_subscriber::EnvFilter;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

pub const LOG_DIR_NAME: &str = "robonet/logs";

// Error code categories
pub const NETWORK_ERROR_BASE: u32 = 1000;
// pub const SERVICE_ERROR_BASE: u32 = 2000;
pub const EMAIL_ERROR_BASE: u32 = 3000;
pub const SYSTEM_ERROR_BASE: u32 = 4000;
pub const LOG_FILE_ERROR_BASE: u32 = 5000;
pub const ENV_VAR_ERROR_BASE: u32 = 6000;
// pub const GENERAL_ERROR_BASE: u32 = 9000;

#[derive(Debug)]
#[repr(u32)]
pub enum ErrorCode {
    // Network related (1000-1999)
    NetworkConfigInvalid = NETWORK_ERROR_BASE,
    DnsmasqConfigFailed = NETWORK_ERROR_BASE + 1,
    ConnectionFileFailed = NETWORK_ERROR_BASE + 2,
    
    // Service related (2000-2999)
    // ServiceConfigError = SERVICE_ERROR_BASE,
    
    // Email related (3000-3999)
    EmailConfigMissing = EMAIL_ERROR_BASE,
    EmailConfigInvalid = EMAIL_ERROR_BASE + 1,
    EmailSendFailed = EMAIL_ERROR_BASE + 2,
    EmailTemplateFailed = EMAIL_ERROR_BASE + 3,
    
    // System related (4000-4999)
    PermissionDenied = SYSTEM_ERROR_BASE,
    LoggingSetupFailed = SYSTEM_ERROR_BASE + 1,
    FileSystemError = SYSTEM_ERROR_BASE + 2,

    // Log file related (5000-5999)
    LogFileError = LOG_FILE_ERROR_BASE,
    LogFileTooLarge = LOG_FILE_ERROR_BASE + 1,
    LogFileInvalid = LOG_FILE_ERROR_BASE + 2,
    
    // Environment variable related (6000-6999)
    EnvVarError = ENV_VAR_ERROR_BASE,
    EnvVarInvalid = ENV_VAR_ERROR_BASE + 1,
    EnvVarEmpty = ENV_VAR_ERROR_BASE + 2,

    // General (9000-9999)
    // UnexpectedError = GENERAL_ERROR_BASE + 999,
}

pub fn error_code(code: ErrorCode) -> String {
    format!("[E{:04}]", code as u32)
}

pub fn setup_logging() -> Result<()> {
    // Get XDG data directory, fallback to ~/.local/share if not set
    let data_dir = std::env::var("XDG_DATA_HOME")
        .unwrap_or_else(|_| format!("{}/.local/share", std::env::var("HOME").unwrap_or_default()));
    
    let log_dir = format!("{}/{}", data_dir, LOG_DIR_NAME);

    // Create log directory if it doesn't exist
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("{} Failed to create log directory", 
            error_code(ErrorCode::LoggingSetupFailed)))?;

    // Main application log file
    let main_appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("main")
        .filename_suffix("log")
        .max_log_files(7)
        .build(&log_dir)
        .with_context(|| format!("{} Failed to create main file appender", 
            error_code(ErrorCode::LoggingSetupFailed)))?;

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
