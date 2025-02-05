use clap::{Parser, Subcommand, ValueEnum};
use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::Path;
use std::collections::HashMap;
use std::io::Read;

const SYSTEM_CONNECTIONS_PATH: &str = "/etc/NetworkManager/system-connections/";
const NETWORK_MANAGER_CONFIG_PATH: &str = "/etc/NetworkManager/NetworkManager.conf";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, ValueEnum, Debug)]
enum NetworkMode {
    /// Access Point mode
    AP,
    /// WPA Personal mode
    WPA,
    /// WPA Enterprise mode
    WPAEAP,
}

impl NetworkMode {
    fn required_args(&self) -> Vec<&'static str> {
        match self {
            NetworkMode::AP => vec!["name", "password", "ip"],
            NetworkMode::WPA => vec!["name", "password"],
            NetworkMode::WPAEAP => vec!["name", "password", "id"],
        }
    }
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

        /// IP address (required for AP mode)
        #[arg(short = 'i', long = "ip")]
        ip: Option<String>,

        /// User ID (required for WPAEAP mode)
        #[arg(short = 'd', long = "id")]
        user_id: Option<String>,
    },
}

fn validate_args(mode: &NetworkMode, ip: &Option<String>, user_id: &Option<String>) -> Result<()> {
    let required = mode.required_args();
    
    if required.contains(&"ip") && ip.is_none() {
        return Err(anyhow!("IP address is required for AP mode"));
    }
    
    if required.contains(&"id") && user_id.is_none() {
        return Err(anyhow!("User ID is required for WPAEAP mode"));
    }

    Ok(())
}

fn generate_connection_file(mode: &NetworkMode, name: &str, password: &str, ip: &Option<String>, user_id: &Option<String>) -> Result<String> {
    let template_path = match mode {
        NetworkMode::AP => "src/connections/ap.nmconnection",
        NetworkMode::WPA => "src/connections/wpa.nmconnection",
        NetworkMode::WPAEAP => "src/connections/wpaeap.nmconnection",
    };

    let template = fs::read_to_string(template_path)
        .with_context(|| format!("Failed to read template file: {}", template_path))?;

    let mut replacements = HashMap::new();
    match mode {
        NetworkMode::AP => {
            replacements.insert("{AP_SSID}", name);
            replacements.insert("{AP_PSK}", password);
            replacements.insert("{AP_IP_ADDRESS}", ip.as_ref().unwrap());
        },
        NetworkMode::WPA => {
            replacements.insert("{NETWORK_SSID}", name);
            replacements.insert("{NETWORK_PSK}", password);
        },
        NetworkMode::WPAEAP => {
            replacements.insert("{NETWORK_SSID}", name);
            replacements.insert("{NETWORK_PASSWORD}", password);
            replacements.insert("{NETWORK_IDENTITY}", user_id.as_ref().unwrap());
        },
    }

    let mut content = template;
    for (key, value) in replacements {
        content = content.replace(key, value);
    }

    Ok(content)
}

fn write_connection_file(name: &str, content: &str) -> Result<()> {
    let filename = format!("{}{}.nmconnection", SYSTEM_CONNECTIONS_PATH, name);
    fs::write(&filename, content)
        .with_context(|| format!("Failed to write connection file: {}", filename))?;
    
    // Set appropriate permissions (600) for NetworkManager
    use std::os::unix::fs::PermissionsExt;
    let path = Path::new(&filename);
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;

    Ok(())
}

fn ensure_dnsmasq_config() -> Result<()> {
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

fn check_root_privileges() -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(anyhow!("This program must be run with root privileges (sudo)"));
    }
    Ok(())
}

fn main() -> Result<()> {
    check_root_privileges()?;
    
    let cli = Cli::parse();

    match &cli.command {
        Commands::AddNetwork { mode, name, password, ip, user_id } => {
            validate_args(mode, ip, user_id)?;

            // If AP mode, ensure dnsmasq is configured
            if matches!(mode, NetworkMode::AP) {
                ensure_dnsmasq_config()
                    .with_context(|| "Failed to configure dnsmasq for AP mode")?;
            }

            let content = generate_connection_file(mode, name, password, ip, user_id)?;
            write_connection_file(name, &content)?;

            match mode {
                NetworkMode::AP => {
                    println!("Added AP network: {}", name);
                    println!("IP: {}", ip.as_ref().unwrap());
                    println!("Note: NetworkManager configuration updated for AP mode");
                },
                NetworkMode::WPA => {
                    println!("Added WPA network: {}", name);
                },
                NetworkMode::WPAEAP => {
                    println!("Added WPAEAP network: {}", name);
                    println!("User ID: {}", user_id.as_ref().unwrap());
                },
            }
        }
    }

    Ok(())
}
