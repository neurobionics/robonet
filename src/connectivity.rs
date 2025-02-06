use anyhow::{Context, Result, anyhow};
use log::{info, error, warn};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use crate::email::{EmailConfig, send_network_status_email};

pub struct NetworkConfig {
    pub notification_email: String,
    pub smtp_server: String,
    pub smtp_user: String,
    pub smtp_password: String,
    pub check_interval: Duration,
    pub max_retries: u32,
}

impl NetworkConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            notification_email: std::env::var("NOTIFICATION_EMAIL")
                .context("NOTIFICATION_EMAIL environment variable not set")?,
            smtp_server: std::env::var("SMTP_SERVER")
                .context("SMTP_SERVER environment variable not set")?,
            smtp_user: std::env::var("SMTP_USER")
                .context("SMTP_USER environment variable not set")?,
            smtp_password: std::env::var("SMTP_PASSWORD")
                .context("SMTP_PASSWORD environment variable not set")?,
            check_interval: Duration::from_secs(
                std::env::var("CHECK_INTERVAL_SECS")
                    .unwrap_or_else(|_| "300".to_string())
                    .parse()
                    .unwrap_or(300)
            ),
            max_retries: std::env::var("MAX_RETRIES")
                .unwrap_or_else(|_| "3".to_string())
                .parse()
                .unwrap_or(3),
        })
    }
}

#[derive(Debug)]
struct NetworkConnection {
    name: String,
    priority: i32,
}

pub struct ConnectivityManager {
    config: NetworkConfig,
    last_ip: Option<String>,
    consecutive_failures: u32,
}

impl ConnectivityManager {
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config,
            last_ip: None,
            consecutive_failures: 0,
        }
    }

    pub fn run(&mut self) -> Result<()> {
        info!("Starting connectivity manager service");
        
        loop {
            match self.check_and_manage_connectivity() {
                Ok(()) => {
                    self.consecutive_failures = 0;
                    thread::sleep(self.config.check_interval);
                }
                Err(e) => {
                    error!("Connectivity check failed: {}", e);
                    self.consecutive_failures += 1;
                    
                    if self.consecutive_failures >= self.config.max_retries {
                        error!("Maximum retry attempts reached");
                        return Err(anyhow!("Maximum retry attempts reached"));
                    }
                    
                    // Exponential backoff
                    let backoff = Duration::from_secs(2u64.pow(self.consecutive_failures));
                    thread::sleep(backoff);
                }
            }
        }
    }

    fn check_and_manage_connectivity(&mut self) -> Result<()> {
        if !self.check_internet_connectivity() {
            info!("No internet connectivity, attempting to reconnect");
            self.try_connect_networks()?;
        }

        let current_ip = self.get_current_ip()?;
        
        // Send email if IP has changed or this is the first successful connection
        if self.last_ip.as_ref() != Some(&current_ip) {
            info!("IP address changed or initial connection");
            self.last_ip = Some(current_ip);
            self.send_ip_email()?;
        }

        Ok(())
    }

    fn check_internet_connectivity(&self) -> bool {
        let output = Command::new("ping")
            .args(["-c", "1", "-W", "5", "8.8.8.8"])
            .output();

        match output {
            Ok(output) => output.status.success(),
            Err(e) => {
                warn!("Ping command failed: {}", e);
                false
            }
        }
    }

    fn get_current_ip(&self) -> Result<String> {
        let output = Command::new("hostname")
            .args(["-I"])
            .output()
            .context("Failed to get IP address")?;
        
        let ip = String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow!("No IP address found"))?
            .to_string();
        
        Ok(ip)
    }

    fn try_connect_networks(&self) -> Result<()> {
        let networks = self.get_available_networks()?;
        
        for network in networks {
            info!("Attempting to connect to network: {}", network.name);
            
            match self.connect_to_network(&network) {
                Ok(()) => {
                    thread::sleep(Duration::from_secs(10));
                    if self.check_internet_connectivity() {
                        info!("Successfully connected to network: {}", network.name);
                        return Ok(());
                    }
                }
                Err(e) => {
                    warn!("Failed to connect to network {}: {}", network.name, e);
                    continue;
                }
            }
        }

        Err(anyhow!("Failed to connect to any available network"))
    }

    fn get_available_networks(&self) -> Result<Vec<NetworkConnection>> {
        let networks_dir = std::path::Path::new("/etc/NetworkManager/system-connections");
        let mut networks = Vec::new();

        for entry in std::fs::read_dir(networks_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                // Read priority from connection file
                let priority = self.get_network_priority(&path).unwrap_or(0);
                
                networks.push(NetworkConnection {
                    name: name.to_string(),
                    priority,
                });
            }
        }

        // Sort networks by priority (highest first)
        networks.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        Ok(networks)
    }

    fn get_network_priority(&self, path: &PathBuf) -> Result<i32> {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            if line.starts_with("priority=") {
                return Ok(line.split('=').nth(1)
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0));
            }
        }
        Ok(0)
    }

    fn connect_to_network(&self, network: &NetworkConnection) -> Result<()> {
        let output = Command::new("nmcli")
            .args(["connection", "up", &network.name])
            .output()
            .context("Failed to execute nmcli command")?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to connect to network: {}", error));
        }

        Ok(())
    }

    fn send_ip_email(&self) -> Result<()> {
        let email_config = EmailConfig {
            smtp_server: self.config.smtp_server.clone(),
            smtp_user: self.config.smtp_user.clone(),
            smtp_password: self.config.smtp_password.clone(),
            recipient: self.config.notification_email.clone(),
        };

        let ip_changed = self.last_ip.is_some();
        send_network_status_email(&email_config, ip_changed)
    }
}
