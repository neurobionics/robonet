mod networking;
mod connectivity;
mod email;
mod logging;
mod service;
mod utils;

use clap::{Parser, Subcommand};
use anyhow::{Context, Result};
use networking::{NetworkMode, validate_args, generate_connection_file, write_connection_file, ensure_dnsmasq_config};
use log::{info, error, debug};
use email::{EmailConfig, send_login_ticket, LoginTicketReason};
use service::install_service;
use utils::{check_root_privileges, set_environment_variable, get_env_var};
use logging::ErrorCode;
use chrono::Local;
use connectivity::NetworkInfo;

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
    
    /// Run as a connectivity monitoring service
    #[command(name = "run-service")]
    RunService,

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
        
        /// Check interval in seconds (default: 300)
        #[arg(long, default_value = "180")]
        check_interval: u64,
        
        /// Maximum number of retries (default: 3)
        #[arg(long, default_value = "3")]
        max_retries: u32,
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
    #[command(name = "test-connections")]
    TestConnections {
        /// Maximum number of test cycles to run
        #[arg(short = 'n', long = "max-trials", default_value = "2")]
        max_trials: u32,

        /// Restart interval in seconds
        #[arg(short = 'i', long = "interval", default_value = "10")]
        interval: u64,
    },

    /// Map nearby WiFi networks
    #[command(name = "map-networks")]
    MapNetworks {
        /// Scan interval in seconds
        #[arg(short = 'i', long = "interval", default_value = "5")]
        interval: u64,

        /// Total duration to run in seconds
        #[arg(short = 't', long = "time", default_value = "300")]
        duration: u64,

        /// Maximum number of networks to log per scan (default: 10)
        #[arg(short = 'n', long = "networks", default_value = "10")]
        max_networks: usize,

        /// Filter by SSID (optional)
        #[arg(short = 's', long = "ssid")]
        ssid_filter: Option<String>,
    },
}

fn main() -> Result<()> {
    logging::setup_logging()?;
    
    let cli = Cli::parse();
    
    // Log which command is being executed (without error code since it's not an error)
    info!("Robot Network Manager executing: {}", 
        match &cli.command {
            Commands::AddNetwork { .. } => "add-network",
            Commands::RunService => "run-service",
            Commands::Install { .. } => "install",
            Commands::Uninstall { .. } => "uninstall",
            Commands::SetEnv { .. } => "set-env",
            Commands::SendLoginTicket => "send-login-ticket",
            Commands::ViewLog { .. } => "view-log",
            Commands::TestConnections { .. } => "test-connections",
            Commands::MapNetworks { .. } => "map-networks",
        }
    );

    // Only check root privileges for commands that need them
    match &cli.command {
        Commands::AddNetwork { .. } |
        Commands::Install { .. } |
        Commands::Uninstall { .. } |
        Commands::SetEnv { .. } => {
            debug!("Checking root privileges");  // Removed error code from debug message
            check_root_privileges()
                .with_context(|| format!("{} Permission denied", 
                    logging::error_code(ErrorCode::PermissionDenied)))?;  // Keep error code for actual errors
        }
        _ => {}  // Other commands don't need root
    }

    match &cli.command {
        Commands::AddNetwork { mode, name, password, priority, ip, user_id } => {
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
        
        Commands::RunService => {
            info!("{} Starting connectivity monitoring service", 
                logging::error_code(ErrorCode::UnexpectedError));
            
            let config = connectivity::NetworkConfig::from_env()
                .with_context(|| format!("{} Failed to load configuration", 
                    logging::error_code(ErrorCode::ServiceConfigError)))?;
            
            let mut manager = connectivity::ConnectivityManager::new(config);
            
            // Only log startup once for the service
            info!("Connectivity monitoring active");
            
            if let Err(e) = manager.run() {
                error!("Service error: {}", e);
                return Err(e);
            }
        }

        Commands::Install { 
            email, 
            smtp_server, 
            smtp_user, 
            smtp_password, 
            check_interval, 
            max_retries 
        } => {
            install_service(
                email.as_deref(),
                smtp_server.as_deref(),
                smtp_user.as_deref(),
                smtp_password.as_deref(),
                *check_interval,
                *max_retries,
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
                    println!("Are you sure you want to uninstall the entire robonet package? [y/N]");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    if input.trim().eq_ignore_ascii_case("y") {
                        // First uninstall the service if it exists
                        let _ = service::uninstall_service();
                        // TODO: Add package uninstallation logic here
                        println!("Package uninstallation not yet implemented");
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
            set_environment_variable(name, value)?;
        }

        Commands::SendLoginTicket => {
            // Try to load email configuration from environment variables
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

            let email_config = EmailConfig {
                smtp_server,
                smtp_user,
                smtp_password,
                recipient: email,
            };

            send_login_ticket(&email_config, LoginTicketReason::ManualCheck)
                .with_context(|| format!("{} Failed to send login ticket", 
                    logging::error_code(ErrorCode::EmailSendFailed)))?;
            
            println!("Login ticket email sent successfully!");
        }

        Commands::ViewLog { file } => {
            let base_name = file.as_deref().unwrap_or("main");
            
            // List all files in the log directory
            let entries = std::fs::read_dir(logging::LOG_DIR)
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
                    // Read and display the log file
                    let content = std::fs::read_to_string(&log_path)
                        .with_context(|| format!("Failed to read log file: {}", log_path.display()))?;
                    
                    println!("=== {} ===", log_path.display());
                    println!("{}", content);
                }
                None => {
                    println!("Available log files:");
                    if let Ok(entries) = std::fs::read_dir(logging::LOG_DIR) {
                        for entry in entries {
                            if let Ok(entry) = entry {
                                println!("  {}", entry.file_name().to_string_lossy());
                            }
                        }
                    }
                    return Err(anyhow::anyhow!("No matching log file found for: {}", base_name));
                }
            }
        }

        Commands::TestConnections { max_trials, interval} => {
            use std::{thread, time::Duration, fs::OpenOptions, io::Write};
            use chrono::Local;
            use connectivity::NetworkInfo;

            // Generate a timestamp-based filename
            let timestamp = Local::now().format("%Y%m%d_%H%M%S");
            let filename = format!("test_connections_{}.csv", timestamp);
            println!("Starting network connection tests:");
            println!("Max trials: {}", max_trials);
            println!("Restart interval: {} seconds", interval);
            println!("Output file: {}", filename);

            // Create new file with headers
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .open(&filename)
                .with_context(|| format!("Failed to create output file: {}", filename))?;

            // Write CSV headers
            writeln!(file, "timestamp,trial,ssid,bssid,ip_address,signal_strength,channel,frequency,rate,mode,connection_time_ms")?;

            for trial in 1..=*max_trials {
                println!("\nTrial {} of {}", trial, max_trials);
                
                // Restart NetworkManager
                std::process::Command::new("systemctl")
                    .args(["restart", "NetworkManager"])
                    .status()
                    .with_context(|| "Failed to restart NetworkManager")?;

                let start_time = std::time::Instant::now();
                
                // Wait for connection and collect network info
                thread::sleep(Duration::from_secs(10)); // Initial wait for service to start
                
                if let Ok(network_info) = NetworkInfo::get_current_connection() {
                    let connection_time = start_time.elapsed().as_millis();
                    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                    
                    // Write to CSV file
                    writeln!(
                        file,
                        "{},{},{},{},{},{},{},{},{},{},{}",
                        timestamp,
                        trial,
                        network_info.ssid.unwrap_or_default(),
                        network_info.bssid.unwrap_or_default(),
                        network_info.ip_address.unwrap_or_default(),
                        network_info.signal_strength.unwrap_or_default(),
                        network_info.channel.unwrap_or_default(),
                        network_info.frequency.unwrap_or_default(),
                        network_info.rate.unwrap_or_default(),
                        network_info.mode.unwrap_or_default(),
                        connection_time
                    )?;

                    println!("Connection time: {}ms", connection_time);
                } else {
                    println!("Failed to get network information");
                    writeln!(
                        file,
                        "{},{},NO_CONNECTION,,,,,,,,,-1",
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

        Commands::MapNetworks { interval, duration, max_networks, ssid_filter } => {
            let timestamp = Local::now().format("%Y%m%d_%H%M%S");
            let filename = format!("network_map_{}{}.csv", 
                ssid_filter.as_ref().map(|s| format!("_{}", s)).unwrap_or_default(),
                timestamp);
            
            println!("Starting network mapping:");
            println!("Scan interval: {} seconds", interval);
            println!("Total duration: {} seconds", duration);
            println!("Networks per scan: {}", max_networks);
            if let Some(ssid) = &ssid_filter {
                println!("Filtering for SSID: {}", ssid);
            }
            println!("Output file: {}", filename);

            NetworkInfo::map_networks(*interval, *duration, *max_networks, &filename, ssid_filter.as_deref())
                .with_context(|| format!("{} Network mapping failed", 
                    logging::error_code(ErrorCode::NetworkScanFailed)))?;

            println!("\nMapping completed. Results saved to: {}", filename);
        }
    }

    Ok(())
}
