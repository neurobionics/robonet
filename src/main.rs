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
use email::{EmailConfig, send_network_status_email};
use service::install_service;
use utils::{check_root_privileges, set_environment_variable, get_env_var};

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

    /// Install systemd service
    InstallService {
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
        #[arg(long, default_value = "300")]
        check_interval: u64,
        
        /// Maximum number of retries (default: 3)
        #[arg(long, default_value = "3")]
        max_retries: u32,
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

    /// Send network status email using configured settings
    SendStatusEmail,

    /// View network manager log files
    ViewLog {
        /// Specific log file to view (optional)
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
}

fn main() -> Result<()> {
    logging::setup_logging()?;
    
    let cli = Cli::parse();
    
    // Log which command is being executed
    info!("Robot Network Manager executing: {}", match &cli.command {
        Commands::AddNetwork { .. } => "add-network",
        Commands::RunService => "run-service",
        Commands::InstallService { .. } => "install-service",
        Commands::SetEnv { .. } => "set-env",
        Commands::SendStatusEmail => "send-status-email",
        Commands::ViewLog { .. } => "view-log",
    });

    // Only check root privileges for commands that need them
    match &cli.command {
        Commands::AddNetwork { .. } |
        Commands::InstallService { .. } |
        Commands::SetEnv { .. } => {
            debug!("Checking root privileges");
            check_root_privileges()?;
        }
        _ => {}  // Other commands don't need root
    }

    match &cli.command {
        Commands::AddNetwork { mode, name, password, priority, ip, user_id } => {
            validate_args(mode, ip, user_id)?;

            // If AP mode, ensure dnsmasq is configured
            if matches!(mode, NetworkMode::AP) {
                ensure_dnsmasq_config()
                    .with_context(|| "Failed to configure dnsmasq for AP mode")?;
            }

            let content = generate_connection_file(mode, name, password, priority, ip, user_id)?;
            write_connection_file(name, &content)?;

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
            info!("Starting connectivity monitoring service");
            
            let config = connectivity::NetworkConfig::from_env()
                .context("Failed to load configuration")?;
            
            let mut manager = connectivity::ConnectivityManager::new(config);
            
            // Only log startup once for the service
            info!("Connectivity monitoring active");
            
            if let Err(e) = manager.run() {
                error!("Service error: {}", e);
                return Err(e);
            }
        }

        Commands::InstallService { 
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

        Commands::SetEnv { name, value } => {
            set_environment_variable(name, value)?;
        }

        Commands::SendStatusEmail => {
            // Try to load email configuration from environment variables or /etc/environment
            let email = get_env_var("EMAIL_ADDRESS")?;
            let smtp_server = get_env_var("SMTP_SERVER")?;
            let smtp_user = get_env_var("SMTP_USER")?;
            let smtp_password = get_env_var("SMTP_PASSWORD")?;

            let email_config = EmailConfig {
                smtp_server,
                smtp_user,
                smtp_password,
                recipient: email,
            };

            send_network_status_email(&email_config, true)?;
            println!("Network status email sent successfully!");
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
    }

    Ok(())
}
