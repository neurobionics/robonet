use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use std::fs;
use std::path::Path;
use std::collections::HashMap;
use std::io::Read;
use std::process::Command;
use std::thread;

pub const SYSTEM_CONNECTIONS_PATH: &str = "/etc/NetworkManager/system-connections/";
const NETWORK_MANAGER_CONFIG_PATH: &str = "/etc/NetworkManager/NetworkManager.conf";

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
    let template_path = match mode {
        NetworkMode::AP => "src/templates/connections/ap.nmconnection",
        NetworkMode::WPA => "src/templates/connections/wpa.nmconnection",
        NetworkMode::WPAEAP => "src/templates/connections/wpaeap.nmconnection",
    };

    let template = fs::read_to_string(template_path)
        .with_context(|| format!("Failed to read template file: {}", template_path))?;

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
    let filename = format!("{}{}.nmconnection", SYSTEM_CONNECTIONS_PATH, name);
    fs::write(&filename, content)
        .with_context(|| format!("Failed to write connection file: {}", filename))?;
    
    // Set appropriate permissions (600) for NetworkManager
    use std::os::unix::fs::PermissionsExt;
    let path = Path::new(&filename);
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;

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
    
    // Read existing config
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
        content.replace("[main]", "[main]\ndns=dnsmasq")
    } else {
        // Create [main] section with dns=dnsmasq
        format!("{}\n[main]\ndns=dnsmasq\n", content)
    };

    // Write the modified content back
    let mut temp_path = path.to_path_buf();
    temp_path.set_extension("tmp");
    
    fs::write(&temp_path, &new_content)
        .with_context(|| "Failed to write temporary config file")?;
    
    fs::rename(&temp_path, path)
        .with_context(|| "Failed to update NetworkManager.conf")?;

    Ok(())
} 