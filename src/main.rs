mod network_config;

use clap::{Parser, Subcommand};
use anyhow::{Context, Result, anyhow};
use network_config::{NetworkMode, validate_args, generate_connection_file, write_connection_file, ensure_dnsmasq_config};

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

        /// IP address (required for AP mode)
        #[arg(short = 'i', long = "ip")]
        ip: Option<String>,

        /// User ID (required for WPAEAP mode)
        #[arg(short = 'd', long = "id")]
        user_id: Option<String>,
    },
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
