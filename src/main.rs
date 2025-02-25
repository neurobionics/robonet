mod networking;
mod connectivity;
mod email;
mod logging;
mod service;
mod utils;

use clap::{Parser, Subcommand};
use anyhow::{Context, Result};
use networking::{NetworkMode, validate_args, generate_connection_file, write_connection_file, ensure_dnsmasq_config};
use log::{info, warn};
use email::{EmailConfig, send_login_ticket};
use service::install_service;
use utils::{check_root_privileges, set_environment_variable, get_env_var};
use logging::ErrorCode;
use regex::Regex;
use lazy_static::lazy_static;

const MAX_LOG_SIZE: u64 = 25 * 1024 * 1024; // 25MB
const NETWORK_TIMEOUT: u64 = 30; // 30 seconds

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).unwrap();
    static ref IP_REGEX: Regex = Regex::new(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ).unwrap();
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new network configuration
    AddNetwork {
        /// Network mode (AP, WPA, or WPAEAP)
        #[arg(short = 'm', long = "mode", value_enum)]
        mode: NetworkMode,

        /// Network name (SSID)
        #[arg(short = 'n', long = "name")]
        name: String,

        /// Network password
        #[arg(short = 'p', long = "password")]
        password: String,

        /// Priority for auto connect
        #[arg(short = 'r', long = "priority")]
        priority: String,

        /// IP address (required for AP mode)
        #[arg(short = 'i', long = "ip")]
        ip: Option<String>,

        /// User ID (required for WPAEAP mode)
        #[arg(short = 'd', long = "id")]
        user_id: Option<String>,
    },
    
    /// Run as a network event handler
    #[command(name = "run-service")]
    RunService {
        /// Interface name
        interface: String,
        
        /// Network event (CONNECTED/DISCONNECTED)
        #[arg(default_value = "")]
        event: String,
        
        /// Additional event data
        #[arg(default_value = "")]
        data: String,
    },

    /// Install systemd service and configure email settings
    #[command(name = "install")]
    Install {
        /// Email address for notifications (or set EMAIL_ADDRESS env var)
        #[arg(long)]
        email: Option<String>,
        
        /// SMTP server address (or set SMTP_SERVER env var)
        #[arg(long)]
        smtp_server: Option<String>,
        
        /// SMTP username (or set SMTP_USER env var)
        #[arg(long)]
        smtp_user: Option<String>,
        
        /// SMTP password (or set SMTP_PASSWORD env var)
        #[arg(long)]
        smtp_password: Option<String>,
        
    },

    /// Uninstall robonet package or its monitoring service
    Uninstall {
        /// What to uninstall: 'service' for monitoring service only, or empty for full package
        #[arg(short = 't', long = "target")]
        target: Option<String>,
    },

    /// Set system-wide environment variable
    SetEnv {
        /// Name of the environment variable
        #[arg(short = 'n', long = "name")]
        name: String,

        /// Value of the environment variable
        #[arg(short = 'v', long = "value")]
        value: String,
    },

    /// Send login ticket email using configured settings
    #[command(name = "send-login-ticket")]
    SendLoginTicket,

    /// View network manager log files
    ViewLog {
        /// Specific log file to view (optional)
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },

    /// Run network connection tests
    #[command(name = "test-connectivity")]
    TestConnectivity {
        /// Maximum number of test cycles to run
        #[arg(short = 'n', long = "max-trials", default_value = "50")]
        max_trials: u32,

        /// Restart interval in seconds
        #[arg(short = 'i', long = "interval", default_value = "15")]
        interval: u64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Set up logging first
    logging::setup_logging()?;
    
    // Only check root privileges for commands that actually need them
    match &cli.command {
        Commands::AddNetwork { .. } |  // Needs root to modify network configs
        Commands::Install { .. } |     // Needs root to install system service
        Commands::Uninstall { .. } |   // Needs root to remove system service
        Commands::SetEnv { .. } => {   // Needs root to set system-wide env vars
            check_root_privileges()
                .with_context(|| format!("{} Permission denied", 
                    logging::error_code(ErrorCode::PermissionDenied)))?;
        }
        _ => {}  // Other commands don't need root
    }

    info!("Robot Network Manager executing: {}", 
        match &cli.command {
            Commands::AddNetwork { .. } => "add-network",
            Commands::RunService { .. } => "run-service",
            Commands::Install { .. } => "install",
            Commands::Uninstall { .. } => "uninstall",
            Commands::SetEnv { .. } => "set-env",
            Commands::SendLoginTicket => "send-login-ticket",
            Commands::ViewLog { .. } => "view-log",
            Commands::TestConnectivity { .. } => "test-connectivity",
        }
    );

    match &cli.command {
        Commands::AddNetwork { mode, name, password, priority, ip, user_id } => {
            // Validate network name
            if name.is_empty() || name.len() > 32 {
                return Err(anyhow::anyhow!("{} Invalid network name length", 
                    logging::error_code(ErrorCode::NetworkConfigInvalid)));
            }

            // Validate IP if present
            if let Some(ip) = ip.as_ref() {
                if !IP_REGEX.is_match(ip) {
                    return Err(anyhow::anyhow!("{} Invalid IP address format", 
                        logging::error_code(ErrorCode::NetworkConfigInvalid)));
                }
            }

            // Validate mode-specific arguments
            mode.validate_mode_specific(ip, user_id)
                .with_context(|| format!("{} Invalid mode-specific configuration", 
                    logging::error_code(ErrorCode::NetworkConfigInvalid)))?;

            validate_args(mode, ip, user_id)
                .with_context(|| format!("{} Invalid network configuration", 
                    logging::error_code(ErrorCode::NetworkConfigInvalid)))?;

            // If AP mode, ensure dnsmasq is configured
            if matches!(mode, NetworkMode::AP) {
                ensure_dnsmasq_config()
                    .with_context(|| format!("{} Failed to configure dnsmasq for AP mode", 
                        logging::error_code(ErrorCode::DnsmasqConfigFailed)))?;
            }

            let content = generate_connection_file(mode, name, password, priority, ip, user_id)
                .with_context(|| format!("{} Failed to generate connection file", 
                    logging::error_code(ErrorCode::ConnectionFileFailed)))?;
            write_connection_file(name, &content)
                .with_context(|| format!("{} Failed to write connection file", 
                    logging::error_code(ErrorCode::ConnectionFileFailed)))?;

            match mode {
                NetworkMode::AP => {
                    println!("Added AP network: {}", name);
                    println!("IP: {}", ip.as_ref().unwrap());
                    println!("Priority: {}", priority);
                    println!("Note: NetworkManager configuration updated for AP mode");
                },
                NetworkMode::WPA => {
                    println!("Added WPA network: {}", name);
                    println!("Priority: {}", priority);
                },
                NetworkMode::WPAEAP => {
                    println!("Added WPAEAP network: {}", name);
                    println!("Priority: {}", priority);
                    println!("User ID: {}", user_id.as_ref().unwrap());
                },
            }
        }
        
        Commands::RunService { interface, event, data } => {
            info!("Network event: {} on {} ({})", event, interface, data);
            
            // Get relevant environment variables from NetworkManager
            let nm_action = std::env::var("NM_DISPATCHER_ACTION").unwrap_or_default();
            let ip_address = std::env::var("IP4_ADDRESS_0").unwrap_or_default();
            let connection_uuid = std::env::var("CONNECTION_UUID").unwrap_or_default();
            
            info!("NetworkManager details - Action: {}, IP: {}, UUID: {}", 
                nm_action, ip_address, connection_uuid);
            
            match event.as_str() {
                "CONNECTED" => {
                    // Skip processing for loopback interface
                    if interface == "lo" {
                        info!("Skipping loopback interface connection");
                        return Ok(());
                    }

                    // Skip processing for AP mode networks
                    let is_ap_mode = std::process::Command::new("iwconfig")
                        .arg(interface)
                        .output()
                        .map(|output| {
                            let output_str = String::from_utf8_lossy(&output.stdout);
                            output_str.contains("Mode:Master")
                        })
                        .unwrap_or(false);

                    if is_ap_mode {
                        info!("Skipping AP mode network connection (Mode:Master)");
                        return Ok(());
                    }

                    let mut retry_count = 0;
                    const MAX_RETRIES: u32 = 3;
                    
                    while retry_count < MAX_RETRIES {
                        // Verify we have a valid non-loopback IP address
                        if !ip_address.is_empty() && !ip_address.starts_with("127.") {
                            // Try to send login ticket email
                            match send_login_ticket(&EmailConfig::from_env()?) {
                                Ok(_) => {
                                    info!("Successfully sent login ticket email");
                                    break;
                                }
                                Err(e) => {
                                    warn!("Failed to send email (attempt {}): {}", retry_count + 1, e);
                                    retry_count += 1;
                                    std::thread::sleep(std::time::Duration::from_secs(5));
                                }
                            }
                        } else {
                            warn!("No valid IP address available yet, waiting...");
                            std::thread::sleep(std::time::Duration::from_secs(2));
                            retry_count += 1;
                        }
                    }

                    // If we exceeded max retries, try the next network
                    if retry_count >= MAX_RETRIES {
                        warn!("Max retries exceeded. Attempting to connect to AP network...");
                        // Try to connect to any available AP mode network
                        if let Err(e) = std::process::Command::new("nmcli")
                            .args(["connection", "show"])
                            .output() {
                            warn!("Failed to list network connections: {}", e);
                        } else {
                            // Find and connect to AP network
                            if let Err(e) = std::process::Command::new("nmcli")
                                .args(["connection", "up", "type", "wifi", "mode", "ap"])
                                .status() {
                                warn!("Failed to connect to AP network: {}", e);
                            }
                        }
                    }
                }
                "DISCONNECTED" => {
                    info!("Network disconnected - Connection: {}", data);
                }
                _ => {
                    info!("Unhandled network event: {}", event);
                }
            }
        }

        Commands::Install { 
            email, 
            smtp_server, 
            smtp_user, 
            smtp_password, 
        } => {

            // Validate email addresses if provided
            if let Some(email) = email.as_ref() {
                // Split email string by commas and validate each email
                for email_addr in email.split(',').map(str::trim) {
                    if !EMAIL_REGEX.is_match(email_addr) {
                        return Err(anyhow::anyhow!("{} Invalid email address format: {}", 
                            logging::error_code(ErrorCode::EmailConfigInvalid),
                            email_addr));
                    }
                }
            }

            install_service(
                email.as_deref(),
                smtp_server.as_deref(),
                smtp_user.as_deref(),
                smtp_password.as_deref(),
            )?;
        }

        Commands::Uninstall { target } => {
            match target.as_deref() {
                Some("service") => {
                    println!("Are you sure you want to uninstall the robonet-monitor.service? [y/N]");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    if input.trim().eq_ignore_ascii_case("y") {
                        service::uninstall_service()?;
                        println!("Service uninstalled successfully");
                    } else {
                        println!("Uninstall cancelled");
                    }
                }
                None => {
                    println!("Are you sure you want to uninstall the robonet dispatcher? [y/N]");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    if input.trim().eq_ignore_ascii_case("y") {
                        // First uninstall the service if it exists
                        let _ = service::uninstall_service();
                        // TODO: Add package uninstallation logic here
                        println!("To completely uninstall the robonet package, please use: `sudo dpkg -r robonet`");
                    } else {
                        println!("Uninstall cancelled");
                    }
                }
                Some(invalid) => {
                    return Err(anyhow::anyhow!("Invalid uninstall target: '{}'. Use 'service' or leave empty for full package uninstall", invalid));
                }
            }
        }

        Commands::SetEnv { name, value } => {
            // Validate environment variable name
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(anyhow::anyhow!("{} Invalid environment variable name: must contain only letters, numbers, and underscores", 
                    logging::error_code(ErrorCode::EnvVarInvalid)));
            }

            // Prevent empty values
            if value.trim().is_empty() {
                return Err(anyhow::anyhow!("{} Environment variable value cannot be empty", 
                    logging::error_code(ErrorCode::EnvVarEmpty)));
            }

            set_environment_variable(name, value)?;
        }

        Commands::SendLoginTicket => {
            let email = get_env_var("EMAIL_ADDRESS")
                .with_context(|| format!("{} EMAIL_ADDRESS not configured", 
                    logging::error_code(ErrorCode::EmailConfigMissing)))?;
            let smtp_server = get_env_var("SMTP_SERVER")
                .with_context(|| format!("{} SMTP_SERVER not configured", 
                    logging::error_code(ErrorCode::EmailConfigMissing)))?;
            let smtp_user = get_env_var("SMTP_USER")
                .with_context(|| format!("{} SMTP_USER not configured", 
                    logging::error_code(ErrorCode::EmailConfigMissing)))?;
            let smtp_password = get_env_var("SMTP_PASSWORD")
                .with_context(|| format!("{} SMTP_PASSWORD not configured", 
                    logging::error_code(ErrorCode::EmailConfigMissing)))?;

            // Split email addresses and create config
            let recipients: Vec<String> = email
                .split(',')
                .map(str::trim)
                .map(String::from)
                .collect();

            let recipient_count = recipients.len();
            let email_config = EmailConfig {
                smtp_server,
                smtp_user,
                smtp_password,
                recipients,
            };

            send_login_ticket(&email_config)
                .with_context(|| format!("{} Failed to send login ticket", 
                    logging::error_code(ErrorCode::EmailSendFailed)))?;
            
            println!("Login ticket email sent successfully to {} recipient(s)!", recipient_count);
        }

        Commands::ViewLog { file } => {
            let base_name = file.as_deref().unwrap_or("main");
            
            // Prevent path traversal
            if base_name.contains("..") || base_name.contains('/') || base_name.contains('\\') {
                return Err(anyhow::anyhow!("{} Invalid log file name", 
                    logging::error_code(ErrorCode::LogFileInvalid)));
            }
            
            // Get the log directory path
            let data_dir = std::env::var("XDG_DATA_HOME")
                .unwrap_or_else(|_| format!("{}/.local/share", std::env::var("HOME").unwrap_or_default()));
            let log_dir = format!("{}/{}", data_dir, logging::LOG_DIR_NAME);
            
            // List all files in the log directory
            let entries = std::fs::read_dir(&log_dir)
                .context("Failed to read log directory")?;
            
            // Find the most recent matching log file
            let latest_log = entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with(base_name)
                })
                .max_by_key(|e| e.metadata().unwrap().modified().unwrap());

            match latest_log {
                Some(log_entry) => {
                    let log_path = log_entry.path();
                    
                    // Check file size before reading
                    let metadata = std::fs::metadata(&log_path)
                        .with_context(|| format!("Failed to read log file metadata: {}", log_path.display()))?;
                    
                    if metadata.len() > MAX_LOG_SIZE {
                        return Err(anyhow::anyhow!("{} Log file too large (max {}MB)", 
                            logging::error_code(ErrorCode::LogFileTooLarge),
                            MAX_LOG_SIZE / 1024 / 1024));
                    }
                    
                    // Read and display the log file
                    let content = std::fs::read_to_string(&log_path)
                        .with_context(|| format!("Failed to read log file: {}", log_path.display()))?;
                    
                    println!("=== {} ===", log_path.display());
                    println!("{}", content);
                }
                None => {
                    println!("Available log files in {}:", log_dir);
                    if let Ok(entries) = std::fs::read_dir(&log_dir) {
                        for entry in entries {
                            if let Ok(entry) = entry {
                                println!("  {}", entry.file_name().to_string_lossy());
                            }
                        }
                    }
                    return Err(anyhow::anyhow!("{} No matching log file found for: {}", 
                        logging::error_code(ErrorCode::LogFileError),
                        base_name));
                }
            }
        }

        Commands::TestConnectivity { max_trials, interval} => {
            use std::{thread, time::Duration, fs::OpenOptions, io::Write};
            use chrono::Local;
            use connectivity::NetworkInfo;

            let timestamp = Local::now().format("%Y%m%d_%H%M%S");
            let filename = format!("test_connections_{}.csv", timestamp);
            
            println!("Starting network connection tests:");
            println!("Max trials: {}", max_trials);
            println!("Restart interval: {} seconds", interval);
            println!("Output file: {}", filename);

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .open(&filename)
                .with_context(|| format!("Failed to create output file: {}", filename))?;

            writeln!(file, "timestamp,trial,ssid,bssid,ip_address,signal_strength,channel,frequency,rate,mode,connection_time_ms,internet_connectivity")?;

            for trial in 1..=*max_trials {
                println!("\nTrial {} of {}", trial, max_trials);
                
                // Restart NetworkManager
                std::process::Command::new("systemctl")
                    .args(["restart", "NetworkManager"])
                    .status()
                    .with_context(|| "Failed to restart NetworkManager")?;

                let start_time = std::time::Instant::now();
                
                // Wait for connection with timeout
                let mut connected = false;
                let mut has_ip = false;
                let timeout = start_time + Duration::from_secs(NETWORK_TIMEOUT);
                
                while std::time::Instant::now() < timeout {
                    if let Ok(network_info) = NetworkInfo::get_current_connection() {
                        // Check if we have an IP address
                        if let Some(ip) = network_info.ip_address {
                            if !ip.is_empty() && ip != "0.0.0.0" {
                                connected = true;
                                has_ip = true;
                                // Add a small delay to ensure network is fully ready
                                thread::sleep(Duration::from_secs(2));
                                
                                // Check if this is an AP connection (should have a static IP)
                                let is_ap_mode = network_info.mode
                                    .as_ref()
                                    .map(|mode| mode == "AP")
                                    .unwrap_or(false);
                                
                                if is_ap_mode {
                                    println!("Connected in AP mode with IP: {}", ip);
                                    // For AP mode, we expect no internet connectivity
                                    connected = true;
                                    has_ip = true;
                                    break;
                                }
                                break;
                            }
                        }
                    }
                    thread::sleep(Duration::from_secs(1));
                }

                if connected && has_ip {
                    if let Ok(network_info) = NetworkInfo::get_current_connection() {
                        let connection_time = start_time.elapsed().as_millis();
                        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        
                        let is_ap_mode = network_info.mode
                            .as_ref()
                            .map(|mode| mode == "AP")
                            .unwrap_or(false);

                        // Only test internet connectivity if not in AP mode
                        let has_internet = if !is_ap_mode {
                            std::process::Command::new("ping")
                                .args(["-c", "1", "-W", "5", "8.8.8.8"])
                                .status()
                                .map(|status| status.success())
                                .unwrap_or(false)
                        } else {
                            false // AP mode should not have internet
                        };

                        writeln!(
                            file,
                            "{},{},{},{},{},{},{},{},{},{},{},{}",
                            timestamp,
                            trial,
                            network_info.ssid.unwrap_or_default(),
                            network_info.bssid.unwrap_or_default(),
                            network_info.ip_address.unwrap_or_default(),
                            network_info.signal_strength.unwrap_or_default(),
                            network_info.channel.unwrap_or_default(),
                            network_info.frequency.unwrap_or_default(),
                            network_info.rate.unwrap_or_default(),
                            network_info.mode.clone().unwrap_or_default(),
                            connection_time,
                            has_internet
                        )?;

                        println!("Mode: {}, Connection time: {}ms, Internet: {}", 
                            network_info.mode.clone().unwrap_or_default(),
                            connection_time, 
                            if has_internet { "Yes" } else { "No" });
                    }
                } else {
                    println!("Connection timeout after {}s", NETWORK_TIMEOUT);
                    writeln!(
                        file,
                        "{},{},CONNECTION_TIMEOUT,,,,,,,,,-1,false",
                        Local::now().format("%Y-%m-%d %H:%M:%S"),
                        trial
                    )?;
                }

                // Wait for the remainder of the interval
                let elapsed = start_time.elapsed().as_secs();
                if elapsed < *interval {
                    thread::sleep(Duration::from_secs(interval - elapsed));
                }
            }

            println!("\nTest completed. Results saved to: {}", filename);
        }

    }

    Ok(())
}
