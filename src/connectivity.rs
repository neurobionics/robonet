use anyhow::Result;
use std::process::Command;

// Keep NetworkInfo struct and implementation for CLI functionality
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
        // Get IP address
        let ip_output = Command::new("hostname")
            .arg("-I")
            .output()?;
        
        let ip = String::from_utf8(ip_output.stdout)?
            .trim()
            .split_whitespace()
            .next()
            .map(String::from);

        // Get wifi connection details
        let wifi_output = Command::new("iwconfig")
            .output()?;
        
        let wifi_info = String::from_utf8_lossy(&wifi_output.stdout);
        
        // Parse iwconfig output
        let ssid = wifi_info.lines()
            .find(|line| line.contains("ESSID"))
            .and_then(|line| {
                line.split("ESSID:\"")
                    .nth(1)
                    .map(|s| s.trim_end_matches('"').to_string())
            });

        Ok(NetworkInfo {
            ssid,
            bssid: None,
            ip_address: ip,
            signal_strength: None,
            channel: None,
            frequency: None,
            rate: None,
            mode: None,
        })
    }
}

