mod network_config;

use clap::{Parser, Subcommand};
use anyhow::{Context, Result, anyhow};
use network_config::{NetworkMode, validate_args, generate_connection_file, write_connection_file, ensure_dnsmasq_config};
use log::{info, error};
mod connectivity;
use std::collections::HashMap;
use std::process::Command;

// Add the template as a static string in the binary
const SERVICE_TEMPLATE: &str = include_str!("services/rpi-connectivity-manager.service");

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
    RunService,

    /// Install systemd service
    InstallService {
        /// Email address for notifications
        #[arg(long)]
        email: String,
        
        /// SMTP server address
        #[arg(long)]
        smtp_server: String,
        
        /// SMTP username
        #[arg(long)]
        smtp_user: String,
        
        /// SMTP password
        #[arg(long)]
        smtp_password: String,
        
        /// Check interval in seconds (default: 300)
        #[arg(long, default_value = "300")]
        check_interval: u64,
        
        /// Maximum number of retries (default: 3)
        #[arg(long, default_value = "3")]
        max_retries: u32,
    },
}

fn check_root_privileges() -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(anyhow!("This program must be run with root privileges (sudo)"));
    }
    Ok(())
}

fn install_service(
    email: &str,
    smtp_server: &str,
    smtp_user: &str,
    smtp_password: &str,
    check_interval: u64,
    max_retries: u32,
) -> Result<()> {
    let executable_path = std::env::current_exe()
        .context("Failed to get executable path")?;
    
    // Create a HashMap for template variables
    let mut vars = HashMap::new();
    vars.insert("EXECUTABLE_PATH", executable_path.display().to_string());
    vars.insert("NOTIFICATION_EMAIL", email.to_string());
    vars.insert("SMTP_SERVER", smtp_server.to_string());
    vars.insert("SMTP_USER", smtp_user.to_string());
    vars.insert("SMTP_PASSWORD", smtp_password.to_string());
    vars.insert("CHECK_INTERVAL_SECS", check_interval.to_string());
    vars.insert("MAX_RETRIES", max_retries.to_string());

    // Replace template variables
    let service_content = vars.iter().fold(SERVICE_TEMPLATE.to_string(), |content, (key, value)| {
        content.replace(&format!("${{{}}}", key), value)
    });

    // Write service file
    std::fs::write("/etc/systemd/system/raspberry-wifi-manager.service", service_content)
        .context("Failed to write service file")?;

    // Reload systemd daemon
    let status = Command::new("systemctl")
        .arg("daemon-reload")
        .status()
        .context("Failed to reload systemd daemon")?;

    if !status.success() {
        return Err(anyhow!("Failed to reload systemd daemon"));
    }

    // Enable service
    let status = Command::new("systemctl")
        .args(["enable", "raspberry-wifi-manager"])
        .status()
        .context("Failed to enable service")?;

    if !status.success() {
        return Err(anyhow!("Failed to enable service"));
    }

    // Start service
    let status = Command::new("systemctl")
        .args(["start", "raspberry-wifi-manager"])
        .status()
        .context("Failed to start service")?;

    if !status.success() {
        return Err(anyhow!("Failed to start service"));
    }

    println!("Service installed and started successfully!");
    println!("To check service status: sudo systemctl status raspberry-wifi-manager");
    println!("To view logs: sudo journalctl -u raspberry-wifi-manager -f");

    Ok(())
}

fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    check_root_privileges()?;
    let cli = Cli::parse();

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
            info!("Starting connectivity service");
            let config = connectivity::NetworkConfig::from_env()
                .context("Failed to load configuration")?;
            
            let mut manager = connectivity::ConnectivityManager::new(config);
            
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
                email,
                smtp_server,
                smtp_user,
                smtp_password,
                *check_interval,
                *max_retries,
            )?;
        }
    }

    Ok(())
}
