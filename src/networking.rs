use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use std::fs;
use std::path::Path;
use std::collections::HashMap;
use std::io::Read;
use std::process::Command;
use std::thread;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use regex::Regex;
use lazy_static::lazy_static;
use std::path::PathBuf;

pub const SYSTEM_CONNECTIONS_PATH: &str = "/etc/NetworkManager/system-connections/";
const NETWORK_MANAGER_CONFIG_PATH: &str = "/etc/NetworkManager/NetworkManager.conf";

lazy_static! {
    static ref VALID_NAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
}

const TEMPLATE_DIR: &str = "src/templates/connections";
const MAX_SSID_LENGTH: usize = 32;
const MIN_PASSWORD_LENGTH: usize = 8;
const MAX_PASSWORD_LENGTH: usize = 63;

#[derive(Clone, ValueEnum, Debug)]
pub enum NetworkMode {
    /// Access Point mode
    AP,
    /// WPA Personal mode
    WPA,
    /// WPA Enterprise mode
    WPAEAP,
}

impl NetworkMode {
    pub fn required_args(&self) -> Vec<&'static str> {
        match self {
            NetworkMode::AP => vec!["name", "password", "ip"],
            NetworkMode::WPA => vec!["name", "password"],
            NetworkMode::WPAEAP => vec!["name", "password", "id"],
        }
    }

    pub fn validate_mode_specific(&self, ip: &Option<String>, user_id: &Option<String>) -> Result<()> {
        match self {
            NetworkMode::AP => {
                if let Some(ip) = ip {
                    if !ip.split('.').all(|octet| {
                        octet.parse::<u8>().is_ok()
                    }) {
                        return Err(anyhow!("Invalid IP address format"));
                    }
                }
            },
            NetworkMode::WPAEAP => {
                if let Some(id) = user_id {
                    if id.is_empty() || id.len() > 64 {
                        return Err(anyhow!("User ID must be between 1 and 64 characters"));
                    }
                }
            },
            _ => {}
        }
        Ok(())
    }
}

pub fn validate_args(mode: &NetworkMode, ip: &Option<String>, user_id: &Option<String>) -> Result<()> {
    let required = mode.required_args();
    
    if required.contains(&"ip") && ip.is_none() {
        return Err(anyhow!("IP address is required for AP mode"));
    }
    
    if required.contains(&"id") && user_id.is_none() {
        return Err(anyhow!("User ID is required for WPAEAP mode"));
    }

    Ok(())
}

pub fn generate_connection_file(mode: &NetworkMode, name: &str, password: &str, priority: &str, ip: &Option<String>, user_id: &Option<String>) -> Result<String> {
    // Validate inputs
    if name.len() > MAX_SSID_LENGTH || name.is_empty() {
        return Err(anyhow!("SSID must be between 1 and {} characters", MAX_SSID_LENGTH));
    }

    if password.len() < MIN_PASSWORD_LENGTH || password.len() > MAX_PASSWORD_LENGTH {
        return Err(anyhow!("Password must be between {} and {} characters", 
            MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH));
    }

    // Validate priority is a number
    if let Err(_) = priority.parse::<u32>() {
        return Err(anyhow!("Priority must be a valid number"));
    }

    // Construct template path safely
    let template_name = match mode {
        NetworkMode::AP => "ap.nmconnection",
        NetworkMode::WPA => "wpa.nmconnection",
        NetworkMode::WPAEAP => "wpaeap.nmconnection",
    };

    let template_path = PathBuf::from(TEMPLATE_DIR).join(template_name);
    
    // Verify template exists and is a file
    if !template_path.is_file() {
        return Err(anyhow!("Template file not found: {}", template_path.display()));
    }

    let template = fs::read_to_string(&template_path)
        .with_context(|| format!("Failed to read template file: {}", template_path.display()))?;

    let mut replacements = HashMap::new();
    match mode {
        NetworkMode::AP => {
            replacements.insert("{AP_SSID}", name);
            replacements.insert("{AP_PSK}", password);
            replacements.insert("{AP_PRIORITY}", priority);
            replacements.insert("{AP_IP_ADDRESS}", ip.as_ref().unwrap());
        },
        NetworkMode::WPA => {
            replacements.insert("{NETWORK_SSID}", name);
            replacements.insert("{NETWORK_PSK}", password);
            replacements.insert("{NETWORK_PRIORITY}", priority);
        },
        NetworkMode::WPAEAP => {
            replacements.insert("{NETWORK_SSID}", name);
            replacements.insert("{NETWORK_PASSWORD}", password);
            replacements.insert("{NETWORK_PRIORITY}", priority);            
            replacements.insert("{NETWORK_IDENTITY}", user_id.as_ref().unwrap());
        },
    }

    let mut content = template;
    for (key, value) in replacements {
        content = content.replace(key, value);
    }

    Ok(content)
}

pub fn write_connection_file(name: &str, content: &str) -> Result<()> {
    // Validate connection name
    if !VALID_NAME_REGEX.is_match(name) {
        return Err(anyhow!("Invalid connection name. Use only letters, numbers, underscores, and hyphens"));
    }

    let filename = format!("{}{}.nmconnection", SYSTEM_CONNECTIONS_PATH, name);
    let path = Path::new(&filename);

    // Check if parent directory exists and has correct permissions
    if !Path::new(SYSTEM_CONNECTIONS_PATH).exists() {
        return Err(anyhow!("NetworkManager connections directory does not exist"));
    }

    // Create file with correct permissions from the start
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("Failed to create connection file: {}", filename))?;

    // Write content
    std::io::Write::write_all(&mut file, content.as_bytes())
        .with_context(|| format!("Failed to write connection file: {}", filename))?;

    // Ensure all data is written to disk
    file.sync_all()
        .with_context(|| format!("Failed to sync connection file: {}", filename))?;

    // Reload all connections in NetworkManager
    Command::new("nmcli")
        .args(["connection", "reload"])
        .output()
        .with_context(|| "Failed to reload NetworkManager connections")?;

    // Small delay to ensure NetworkManager processes the new connection
    thread::sleep(std::time::Duration::from_secs(1));

    Ok(())
}

pub fn ensure_dnsmasq_config() -> Result<()> {
    let path = Path::new(NETWORK_MANAGER_CONFIG_PATH);
    
    // Ensure the file exists
    if !path.exists() {
        return Err(anyhow!("NetworkManager configuration file does not exist"));
    }

    // Create backup before modification
    let backup_path = path.with_extension("conf.backup");
    fs::copy(path, &backup_path)
        .with_context(|| "Failed to create backup of NetworkManager.conf")?;

    // Read existing config with size limit
    const MAX_CONFIG_SIZE: u64 = 1024 * 1024; // 1MB limit
    let metadata = fs::metadata(path)
        .with_context(|| "Failed to read NetworkManager.conf metadata")?;
    
    if metadata.len() > MAX_CONFIG_SIZE {
        return Err(anyhow!("NetworkManager.conf is too large"));
    }

    let mut content = String::new();
    fs::File::open(path)
        .with_context(|| format!("Failed to open {}", NETWORK_MANAGER_CONFIG_PATH))?
        .read_to_string(&mut content)?;

    // Check if dns=dnsmasq is already present under [main]
    if content.contains("[main]") && content.contains("dns=dnsmasq") {
        return Ok(());
    }

    // Modify the content
    let new_content = if content.contains("[main]") {
        // Add dns=dnsmasq under existing [main] section
        let re = Regex::new(r"(?m)^\[main\]$").unwrap();
        re.replace(&content, "[main]\ndns=dnsmasq").into_owned()
    } else {
        // Create [main] section with dns=dnsmasq
        format!("{}\n[main]\ndns=dnsmasq\n", content)
    };

    // Write to temporary file first
    let mut temp_path = path.to_path_buf();
    temp_path.set_extension("tmp");
    
    fs::write(&temp_path, &new_content)
        .with_context(|| "Failed to write temporary config file")?;

    // Set correct permissions
    let mut perms = fs::metadata(&temp_path)?.permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&temp_path, perms)?;

    // Atomic rename
    fs::rename(&temp_path, path)
        .with_context(|| "Failed to update NetworkManager.conf")?;

    Ok(())
} 