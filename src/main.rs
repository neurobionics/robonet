use clap::Parser;
use anyhow::{Context, Result};

const SYSTEM_CONNECTIONS_PATH: &str = "/etc/NetworkManager/system-connections/";
const NETWORK_MANAGER_CONFIG_PATH: &str = "/etc/NetworkManager/NetworkManager.conf";

#[derive(Parser)]
struct Cli {
    pattern: String,
    path: std::path::PathBuf,
}

fn main() -> Result<()> {
    let args: Cli = Cli::parse();
    println!("Runnnig with pattern: {:?}, path: {:?}", args.pattern, args.path);

    let content = std::fs::read_to_string(&args.path)
        .with_context(|| format!("Could not read file {:?}", args.path.display()))?;

    for line in content.lines() {
        if line.contains(&args.pattern) {
            println!("Pattern found:{}", line);
        }
    }

    Ok(())
}
