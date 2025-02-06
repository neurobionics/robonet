mod network_config;

use clap::{Parser, Subcommand};
use anyhow::{Context, Result, anyhow};
use network_config::{NetworkMode, validate_args, generate_connection_file, write_connection_file, ensure_dnsmasq_config};
use log::{info, error};
mod connectivity;
use std::collections::HashMap;
use std::process::Command;
mod email;
use email::{EmailConfig, send_network_status_email};

// Add the template as a static string in the binary
const SERVICE_TEMPLATE: &str = include_str!("services/robot-network-manager.service");

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
}

fn check_root_privileges() -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(anyhow!("This program must be run with root privileges (sudo)"));
    }
    Ok(())
}

fn install_service(
    email: Option<&str>,
    smtp_server: Option<&str>,
    smtp_user: Option<&str>,
    smtp_password: Option<&str>,
    check_interval: u64,
    max_retries: u32,
) -> Result<()> {
    let email = email
        .map(String::from)
        .or_else(|| get_env_var("EMAIL_ADDRESS").ok())
        .context("Email address not provided. Set EMAIL_ADDRESS environment variable or use --email flag")?;
    
    let smtp_server = smtp_server
        .map(String::from)
        .or_else(|| get_env_var("SMTP_SERVER").ok())
        .context("SMTP server not provided. Set SMTP_SERVER environment variable or use --smtp-server flag")?;
    
    let smtp_user = smtp_user
        .map(String::from)
        .or_else(|| get_env_var("SMTP_USER").ok())
        .context("SMTP username not provided. Set SMTP_USER environment variable or use --smtp-user flag")?;
    
    let smtp_password = smtp_password
        .map(String::from)
        .or_else(|| get_env_var("SMTP_PASSWORD").ok())
        .context("SMTP password not provided. Set SMTP_PASSWORD environment variable or use --smtp-password flag")?;

    // Test email configuration before installing service
    let email_config = EmailConfig {
        smtp_server: smtp_server.clone(),
        smtp_user: smtp_user.clone(),
        smtp_password: smtp_password.clone(),
        recipient: email.clone(),
    };

    // Test email configuration
    send_network_status_email(&email_config, false)?;

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
    std::fs::write("/etc/systemd/system/robot-network-manager.service", service_content)
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
        .args(["enable", "robot-network-manager"])
        .status()
        .context("Failed to enable service")?;

    if !status.success() {
        return Err(anyhow!("Failed to enable service"));
    }

    // Start service
    let status = Command::new("systemctl")
        .args(["start", "robot-network-manager"])
        .status()
        .context("Failed to start service")?;

    if !status.success() {
        return Err(anyhow!("Failed to start service"));
    }

    println!("Service installed and started successfully!");
    println!("To check service status: sudo systemctl status robot-network-manager");
    println!("To view logs: sudo journalctl -u robot-network-manager -f");

    Ok(())
}

fn set_environment_variable(name: &str, value: &str) -> Result<()> {
    let env_file = "/etc/environment";
    
    // Read existing content
    let content = std::fs::read_to_string(env_file)
        .context("Failed to read /etc/environment")?;
    
    // Parse existing variables
    let mut lines: Vec<String> = content.lines()
        .filter(|line| !line.starts_with(&format!("{}=", name)))
        .map(String::from)
        .collect();
    
    // Add new variable
    lines.push(format!("{}={}", name, value));
    
    // Write back to file
    std::fs::write(env_file, lines.join("\n") + "\n")
        .context("Failed to write to /etc/environment")?;
    
    println!("Environment variable '{}' set to '{}' successfully!", name, value);
    println!("Note: You may need to log out and back in or reboot for changes to take effect.");
    
    Ok(())
}

fn get_env_var(name: &str) -> Result<String> {
    // First try standard env var
    if let Ok(value) = std::env::var(name) {
        return Ok(value);
    }

    // If not found, try reading from /etc/environment
    let content = std::fs::read_to_string("/etc/environment")
        .context("Failed to read /etc/environment")?;
    
    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == name {
                return Ok(value.trim().to_string());
            }
        }
    }

    Err(anyhow!("{} not found in environment or /etc/environment. Please run 'install-service' first to configure email settings", name))
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
    }

    Ok(())
}
