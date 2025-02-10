use anyhow::{Context, Result, anyhow};
use log::{info, warn, debug, error};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use crate::email::{EmailConfig, send_login_ticket, LoginTicketReason};
use crate::logging;
use crate::logging::ErrorCode;

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
}

impl ConnectivityManager {
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config,
            last_ip: None,
        }
    }

    pub fn run(&mut self) -> Result<()> {
        info!("Initializing connectivity monitoring");
        let mut consecutive_failures = 0;
        let mut first_run = true;

        loop {
            if first_run {
                debug!("Performing initial connectivity check");
                first_run = false;
            }

            match self.check_connectivity() {
                Ok(_) => {
                    if consecutive_failures > 0 {
                        info!("Connectivity restored after {} failures", consecutive_failures);
                    }
                    consecutive_failures = 0;
                    debug!("Connectivity check successful, sleeping for {} seconds", 
                          self.config.check_interval.as_secs());
                    std::thread::sleep(self.config.check_interval);
                }
                Err(e) => {
                    warn!("Connectivity check failed: {}", e);
                    consecutive_failures += 1;

                    if consecutive_failures >= self.config.max_retries {
                        warn!("Maximum consecutive failures ({}) reached. Entering recovery mode...", 
                              self.config.max_retries);
                        // Wait for a longer period (e.g., 500 seconds) before retrying
                        std::thread::sleep(Duration::from_secs(500));
                        // Reset the counter to allow for new attempts
                        consecutive_failures = 0;
                    } else {
                        debug!("Retry {}/{} in 30 seconds", 
                               consecutive_failures, self.config.max_retries);
                        std::thread::sleep(Duration::from_secs(30));
                    }
                }
            }
        }
    }

    fn check_connectivity(&mut self) -> Result<()> {
        if !self.check_internet_connectivity() {
            error!("{} Internet connectivity check failed", 
                logging::error_code(ErrorCode::NetworkConnectFailed));
            self.try_connect_networks()?;
        }

        match self.get_current_ip() {
            Ok(current_ip) => {
                // Only log and send email if IP has changed
                if self.last_ip.as_ref() != Some(&current_ip) {
                    info!("IP address changed from {} to {}", 
                          self.last_ip.as_deref().unwrap_or("none"), 
                          current_ip);
                    self.last_ip = Some(current_ip.clone());
                    
                    debug!("Sending IP change notification email");
                    if let Err(e) = self.send_ip_email() {
                        warn!("Failed to send IP notification email: {}", e);
                        return Err(e);
                    }
                    info!("Successfully sent IP notification email");
                }
                Ok(())
            }
            Err(e) => {
                warn!("Failed to get current IP: {}", e);
                Err(e)
            }
        }
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
                    error!("{} Failed to establish internet connectivity on network: {}", 
                        logging::error_code(ErrorCode::NetworkConnectFailed), network.name);
                }
                Err(e) => {
                    error!("{} Failed to connect to network {}: {}", 
                        logging::error_code(ErrorCode::NetworkConnectFailed), network.name, e);
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
        send_login_ticket(&email_config, if ip_changed {
            LoginTicketReason::IpChanged
        } else {
            LoginTicketReason::InitialLogin
        })
    }
}

#[derive(Debug)]
pub struct NetworkInfo {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub signal_strength: Option<String>,
    pub ip_address: Option<String>,
    pub channel: Option<String>,
    pub frequency: Option<String>,
    pub rate: Option<String>,
    pub mode: Option<String>,
}

impl NetworkInfo {
    pub fn get_current_connection() -> Result<Self> {
        // Get wifi connection details with a single command
        let wifi_output = std::process::Command::new("nmcli")
            .args(["-f", "IN-USE,SSID,BSSID,SIGNAL,CHAN,FREQ,RATE,MODE", "device", "wifi"])
            .output()?;
        
        let wifi_info = String::from_utf8_lossy(&wifi_output.stdout);
        let connection_info = wifi_info.lines()
            .skip(1)  // Skip the header line
            .find(|line| line.starts_with("*"))  // Find the line with * indicating active connection
            .map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                
                // Extract numeric values from frequency and rate
                let freq = parts.iter()
                    .position(|&x| x == "MHz")
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| parts.get(i))
                    .map(|&s| s.to_string());
                
                let rate = parts.iter()
                    .position(|&x| x == "Mbit/s")
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| parts.get(i))
                    .map(|&s| s.to_string());
                
                let mode_index = parts.iter()
                    .position(|&x| x == "Mbit/s")
                    .map(|i| i + 1)
                    .and_then(|i| parts.get(i))
                    .map(|&s| s.to_string());

                (
                    parts.get(1).map(|&s| s.to_string()),     // SSID
                    parts.get(2).map(|&s| s.to_string()),     // BSSID
                    parts.get(3).map(|&s| s.to_string()),     // Signal
                    parts.get(4).map(|&s| s.to_string()),     // Channel
                    freq,                                      // Frequency (numeric only)
                    rate,                                      // Rate (numeric only)
                    mode_index,                                // Mode
                )
            });

        // Get IP address (keeping this part as it's working)
        let ip_output = std::process::Command::new("ip")
            .args(["addr", "show", "wlan0"])
            .output()?;
        
        let ip_info = String::from_utf8_lossy(&ip_output.stdout);
        let ip_address = ip_info.lines()
            .find(|line| line.contains("inet ") && !line.contains("inet6"))
            .and_then(|line| {
                line.split_whitespace()
                    .nth(1)
                    .map(|s| s.split('/').next().unwrap_or("").to_string())
            });

        if let Some((ssid, bssid, signal, chan, freq, rate, mode)) = connection_info {
            Ok(NetworkInfo {
                ssid,
                bssid,
                signal_strength: signal,
                ip_address,
                channel: chan,
                frequency: freq,
                rate,
                mode,
            })
        } else {
            Ok(NetworkInfo {
                ssid: None,
                bssid: None,
                signal_strength: None,
                ip_address,
                channel: None,
                frequency: None,
                rate: None,
                mode: None,
            })
        }
    }

    pub fn scan_networks() -> Result<Vec<NetworkInfo>> {
        let output = Command::new("nmcli")
            .args(["-f", "SSID,BSSID,SIGNAL,CHAN,FREQ,RATE,MODE", "device", "wifi", "list"])
            .output()
            .context("Failed to execute nmcli command")?;

        let wifi_info = String::from_utf8_lossy(&output.stdout);
        let mut networks = Vec::new();

        // Skip the header line
        for line in wifi_info.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 7 {
                networks.push(NetworkInfo {
                    ssid: Some(parts[0].to_string()),
                    bssid: Some(parts[1].to_string()),
                    signal_strength: Some(parts[2].to_string()),
                    channel: Some(parts[3].to_string()),
                    frequency: Some(parts[4].to_string()),
                    rate: Some(parts[5].to_string()),
                    mode: Some(parts[6].to_string()),
                    ip_address: None, // Not relevant for network scanning
                });
            }
        }

        Ok(networks)
    }

    pub fn map_networks(
        interval: u64,
        duration: u64,
        max_networks: usize,
        output_file: &str,
        ssid_filter: Option<&str>,
    ) -> Result<()> {
        use std::{thread, time::Duration, fs::OpenOptions, io::Write};
        use chrono::Local;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(output_file)
            .context("Failed to create output file")?;

        // Write CSV headers
        writeln!(file, "timestamp,ssid,bssid,signal_strength,channel,frequency,rate,mode")?;

        let start_time = std::time::Instant::now();
        
        while start_time.elapsed().as_secs() < duration {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            
            match Self::scan_networks() {
                Ok(networks) => {
                    // Filter networks if SSID filter is provided
                    let filtered_networks: Vec<_> = if let Some(ssid) = ssid_filter {
                        networks.into_iter()
                            .filter(|n| n.ssid.as_ref().map(|s| s == ssid).unwrap_or(false))
                            .collect()
                    } else {
                        networks
                    };

                    // Sort by signal strength
                    let mut networks = filtered_networks;
                    networks.sort_by(|a, b| {
                        let a_signal = a.signal_strength.as_ref()
                            .and_then(|s| s.parse::<i32>().ok())
                            .unwrap_or(-100);
                        let b_signal = b.signal_strength.as_ref()
                            .and_then(|s| s.parse::<i32>().ok())
                            .unwrap_or(-100);
                        b_signal.cmp(&a_signal)
                    });

                    // Log top networks
                    for network in networks.iter().take(max_networks) {
                        writeln!(
                            file,
                            "{},{},{},{},{},{},{},{}",
                            timestamp,
                            network.ssid.as_deref().unwrap_or(""),
                            network.bssid.as_deref().unwrap_or(""),
                            network.signal_strength.as_deref().unwrap_or(""),
                            network.channel.as_deref().unwrap_or(""),
                            network.frequency.as_deref().unwrap_or(""),
                            network.rate.as_deref().unwrap_or(""),
                            network.mode.as_deref().unwrap_or("")
                        )?;
                    }

                    info!("Scan completed at {}: {} networks found{}", 
                        timestamp, 
                        networks.len().min(max_networks),
                        ssid_filter.map(|s| format!(" for SSID '{}'", s))
                            .unwrap_or_default());
                }
                Err(e) => {
                    warn!("Failed to scan networks at {}: {}", timestamp, e);
                }
            }

            thread::sleep(Duration::from_secs(interval));
        }

        Ok(())
    }
}
