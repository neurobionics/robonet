use anyhow::{Context, Result, anyhow};
use log::{info, warn, debug, error};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use crate::email::{EmailConfig, send_login_ticket, LoginTicketReason};
use crate::logging;
use crate::logging::ErrorCode;
use std::collections::HashMap;
use metrics::{counter, gauge};

pub struct NetworkConfig {
    pub notification_email: String,
    pub smtp_server: String,
    pub smtp_user: String,
    pub smtp_password: String,
    pub check_interval: Duration,
    pub max_retries: u32,
    pub connection_retry_delay: Duration,
    pub stale_connection_threshold: Duration,
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
            connection_retry_delay: Duration::from_secs(
                std::env::var("CONNECTION_RETRY_DELAY_SECS")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()
                    .unwrap_or(5)
            ),
            stale_connection_threshold: Duration::from_secs(
                std::env::var("STALE_CONNECTION_THRESHOLD_SECS")
                    .unwrap_or_else(|_| "3600".to_string())
                    .parse()
                    .unwrap_or(3600)
            ),
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
    metrics: NetworkMetrics,
}

impl ConnectivityManager {
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config,
            last_ip: None,
            metrics: NetworkMetrics::default(),
        }
    }

    pub fn run(&mut self) -> Result<()> {
        info!("Initializing connectivity monitoring");
        let mut consecutive_failures = 0;
        
        // Force immediate IP check and notification on startup
        info!("Performing initial connectivity check on startup");
        self.force_ip_notification()?;

        loop {
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
        // Add multiple DNS servers for redundancy
        if !self.check_internet_connectivity() {
            error!("{} Internet connectivity check failed", 
                logging::error_code(ErrorCode::NetworkConnectFailed));
            
            // Add retry with different DNS servers before trying to reconnect
            for dns in ["8.8.8.8", "1.1.1.1", "8.8.4.4"].iter() {
                if self.check_internet_connectivity_with_dns(dns) {
                    debug!("Connectivity restored using DNS server {}", dns);
                    return Ok(());
                }
            }
            
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
        self.check_internet_connectivity_with_dns("8.8.8.8")
    }

    fn check_internet_connectivity_with_dns(&self, dns: &str) -> bool {
        // Add timeout and multiple attempts
        for _ in 0..3 {
            let output = Command::new("ping")
                .args(["-c", "1", "-W", "3", dns])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    return true;
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
        false
    }

    fn get_current_ip(&self) -> Result<String> {
        // Try multiple methods to get IP address
        if let Ok(ip) = self.get_ip_from_hostname() {
            return Ok(ip);
        }

        if let Ok(ip) = self.get_ip_from_ip_addr() {
            return Ok(ip);
        }

        Err(anyhow!("Failed to get IP address using all available methods"))
    }

    fn get_ip_from_hostname(&self) -> Result<String> {
        let output = Command::new("hostname")
            .args(["-I"])
            .output()
            .context("Failed to get IP address from hostname")?;
        
        let ip = String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow!("No IP address found in hostname output"))?
            .to_string();
        
        // Validate IP address format
        if !ip.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return Err(anyhow!("Invalid IP address format"));
        }
        
        Ok(ip)
    }

    fn get_ip_from_ip_addr(&self) -> Result<String> {
        let output = Command::new("ip")
            .args(["addr", "show"])
            .output()
            .context("Failed to get IP address from ip addr")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("inet ") && !line.contains("inet6") && !line.contains("127.0.0.1") {
                if let Some(ip) = line.split_whitespace()
                    .nth(1)
                    .and_then(|s| s.split('/').next()) {
                    return Ok(ip.to_string());
                }
            }
        }
        
        Err(anyhow!("No valid IP address found in ip addr output"))
    }

    fn try_connect_networks(&mut self) -> Result<()> {
        self.cleanup_stale_connections()?;
        let networks = self.get_available_networks()?;  // Networks are already sorted by priority
        
        for network in networks {
            info!("Attempting to connect to network: {} (priority: {})", network.name, network.priority);
            
            let attempts = self.metrics.connection_attempts
                .entry(network.name.clone())
                .or_insert(0);
            *attempts += 1;
            counter!("network.connection_attempts", 1);

            let connect_result = std::panic::catch_unwind(|| {
                self.connect_to_network(&network)
            });

            match connect_result {
                Ok(Ok(())) => {
                    // Check if connection is stable
                    for i in 1..=3 {
                        thread::sleep(self.config.connection_retry_delay);
                        if self.check_internet_connectivity() {
                            // Measure quality for monitoring purposes only
                            let quality = self.measure_connection_quality(&network.name);
                            info!("Successfully connected to network: {} (priority: {}, quality: {:.2})", 
                                network.name, network.priority, quality);
                            
                            // Update metrics
                            self.metrics.last_connection_time
                                .insert(network.name.clone(), Instant::now());
                            self.metrics.connection_quality
                                .insert(network.name.clone(), quality);
                            counter!("network.successful_connections", 1);
                            gauge!("network.connection_quality", quality);
                            
                            // Return success regardless of quality - we respect priority
                            return Ok(());
                        }
                        debug!("Connection stability check {}/3...", i);
                    }
                    error!("{} Failed to establish stable connection on network: {}", 
                        logging::error_code(ErrorCode::NetworkConnectFailed), network.name);
                    counter!("network.failed_connections", 1);
                }
                Ok(Err(e)) => {
                    error!("{} Failed to connect to network {} (priority: {}): {}", 
                        logging::error_code(ErrorCode::NetworkConnectFailed), 
                        network.name, 
                        network.priority,
                        e);
                    counter!("network.connection_errors", 1);
                }
                Err(_) => {
                    error!("{} Connection attempt panicked for network {} (priority: {})", 
                        logging::error_code(ErrorCode::NetworkConnectFailed), 
                        network.name,
                        network.priority);
                    counter!("network.connection_panics", 1);
                }
            }
        }

        // If we get here, we've tried all networks and failed
        // The last network should be the AP mode, so we should have an IP even without internet
        if let Ok(current_ip) = self.get_current_ip() {
            info!("No internet connectivity available. Operating in AP mode with IP: {}", current_ip);
            self.last_ip = Some(current_ip);
            return Ok(());  // No need to attempt email notification in AP mode
        }

        Err(anyhow!("Failed to connect to any available network"))
    }

    fn get_available_networks(&self) -> Result<Vec<NetworkConnection>> {
        let networks_dir = std::path::Path::new("/etc/NetworkManager/system-connections");
        let mut networks = Vec::new();

        for entry in std::fs::read_dir(networks_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if let Some(name) = path.file_stem()
                .and_then(|n| n.to_str()) 
            {
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
            if line.starts_with("autoconnect-priority=") {
                return Ok(line.split('=').nth(1)
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0));
            }
        }
        Ok(0)
    }

    fn connect_to_network(&self, network: &NetworkConnection) -> Result<()> {
        info!("Attempting to connect to network '{}'", network.name);
        
        let output = Command::new("nmcli")
            .args(["connection", "up", &network.name])
            .output()
            .with_context(|| format!("Failed to execute nmcli command for network {}", network.name))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to connect to network: {}", error));
        }

        Ok(())
    }

    fn send_ip_email(&mut self) -> Result<()> {
        let email_config = EmailConfig {
            smtp_server: self.config.smtp_server.clone(),
            smtp_user: self.config.smtp_user.clone(),
            smtp_password: self.config.smtp_password.clone(),
            recipients: vec![self.config.notification_email.clone()],
        };

        // Change reason based on whether this is initial boot or IP change
        let reason = if self.last_ip.is_none() {
            LoginTicketReason::InitialLogin
        } else {
            LoginTicketReason::IpChanged
        };

        send_login_ticket(&email_config, reason)?;
        counter!("network.email_notifications_sent", 1);
        Ok(())
    }

    fn cleanup_stale_connections(&mut self) -> Result<()> {
        let now = Instant::now();
        let stale_networks: Vec<String> = self.metrics.last_connection_time
            .iter()
            .filter(|(_, &last_time)| {
                now.duration_since(last_time) > self.config.stale_connection_threshold
            })
            .map(|(name, _)| name.clone())
            .collect();

        for network in stale_networks {
            debug!("Cleaning up stale connection: {}", network);
            Command::new("nmcli")
                .args(["connection", "down", &network])
                .output()
                .with_context(|| format!("Failed to disconnect stale network: {}", network))?;

            self.metrics.connection_attempts.remove(&network);
            self.metrics.last_connection_time.remove(&network);
            self.metrics.connection_quality.remove(&network);

            counter!("network.stale_connections_cleaned", 1);
        }

        Ok(())
    }

    fn measure_connection_quality(&mut self, network_name: &str) -> f64 {
        let mut total_latency = 0.0;
        let mut successful_pings = 0;
        
        for dns in ["8.8.8.8", "1.1.1.1"].iter() {
            for _ in 0..3 {
                let start = Instant::now();
                if self.check_internet_connectivity_with_dns(dns) {
                    total_latency += start.elapsed().as_millis() as f64;
                    successful_pings += 1;
                }
            }
        }

        let quality = if successful_pings > 0 {
            let avg_latency = total_latency / successful_pings as f64;
            let success_rate = successful_pings as f64 / 6.0;
            success_rate * (1000.0 / (avg_latency + 100.0))
        } else {
            0.0
        };

        // Store quality metric but don't use it for decision making
        self.metrics.connection_quality.insert(network_name.to_string(), quality);
        quality
    }

    // Add new method to force IP notification
    fn force_ip_notification(&mut self) -> Result<()> {
        info!("Waiting for initial network connectivity...");
        
        // Add initial delay to allow network manager to stabilize
        std::thread::sleep(Duration::from_secs(5));
        
        // Try for up to 2 minutes to get connectivity
        let timeout = std::time::Duration::from_secs(120);
        let start_time = std::time::Instant::now();
        
        while start_time.elapsed() < timeout {
            // First check if we already have internet connectivity
            if self.check_internet_connectivity() {
                // If we have connectivity, get the IP and proceed
                if let Ok(current_ip) = self.get_current_ip() {
                    info!("Initial IP address: {}", current_ip);
                    self.last_ip = Some(current_ip.clone());
                    
                    debug!("Sending initial IP notification email");
                    if let Err(e) = self.send_ip_email() {
                        warn!("Failed to send initial IP notification email: {}", e);
                        return Err(e);
                    }
                    info!("Successfully sent initial IP notification email");
                    return Ok(());
                }
            }
            
            // No connectivity, try to connect to available networks
            debug!("No internet connectivity, trying to connect to available networks...");
            if let Err(e) = self.try_connect_networks() {
                debug!("Failed to connect to any network: {}", e);
            }
            
            // Get current IP and check if we're in AP mode
            match self.get_current_ip() {
                Ok(current_ip) => {
                    // Check if this is an AP connection
                    let networks = self.get_available_networks()?;
                    let current_network = networks.last()  // AP should be last (lowest priority)
                        .filter(|n| n.name == current_ip);  // Match by IP since we know AP's IP
                    
                    if current_network.is_some() {
                        info!("Operating in AP mode with static IP: {}", current_ip);
                        self.last_ip = Some(current_ip);
                        return Ok(());  // No need to send email in AP mode
                    }
                }
                Err(e) => {
                    debug!("Failed to get IP address, retrying: {}", e);
                }
            }
            
            debug!("Waiting for network connectivity... ({} seconds elapsed)", 
                start_time.elapsed().as_secs());
            std::thread::sleep(Duration::from_secs(2));
        }
        
        Err(anyhow!("Timeout waiting for initial network connectivity"))
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

#[derive(Default)]
struct NetworkMetrics {
    connection_attempts: HashMap<String, u32>,
    last_connection_time: HashMap<String, Instant>,
    connection_quality: HashMap<String, f64>,
}
