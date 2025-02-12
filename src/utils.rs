use anyhow::{Context, Result, anyhow};
use nix;
use log::{error, debug};
use crate::logging;
use crate::logging::ErrorCode;
use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::{Write, BufReader, BufRead};
use std::os::unix::fs::OpenOptionsExt;

const ENV_FILE: &str = "/etc/environment";

pub fn check_root_privileges() -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        error!("{} Root privileges required",
            logging::error_code(ErrorCode::PermissionDenied));
        return Err(anyhow!("This program must be run with root privileges (sudo)"));
    }
    Ok(())
}

pub fn set_environment_variable(name: &str, value: &str) -> Result<()> {
    debug!("Setting environment variable {}={}", name, value);

    let env_path = Path::new(ENV_FILE);
    
    // Create backup
    let backup_path = format!("{}.bak", ENV_FILE);
    if env_path.exists() {
        fs::copy(env_path, &backup_path)
            .with_context(|| format!("{} Failed to create backup of environment file",
                logging::error_code(ErrorCode::EnvVarError)))?;
    }

    // Read existing content
    let content = fs::read_to_string(env_path)
        .unwrap_or_default();
    
    // Parse existing variables
    let mut lines: Vec<String> = content.lines()
        .filter(|line| !line.trim().is_empty())
        .filter(|line| !line.starts_with(&format!("{}=", name)))
        .map(String::from)
        .collect();
    
    // Add new variable
    lines.push(format!("{}={}", name, value));
    lines.sort(); // Keep file organized

    // Write to temporary file first
    let temp_path = format!("{}.tmp", ENV_FILE);
    {
        let mut temp_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&temp_path)
            .with_context(|| format!("{} Failed to create temporary environment file",
                logging::error_code(ErrorCode::EnvVarError)))?;

        writeln!(temp_file, "{}", lines.join("\n"))
            .with_context(|| format!("{} Failed to write to temporary environment file",
                logging::error_code(ErrorCode::EnvVarError)))?;
        
        temp_file.sync_all()
            .with_context(|| format!("{} Failed to sync temporary environment file",
                logging::error_code(ErrorCode::EnvVarError)))?;
    }

    // Atomically rename temporary file to actual file
    fs::rename(&temp_path, env_path)
        .with_context(|| format!("{} Failed to update environment file",
            logging::error_code(ErrorCode::EnvVarError)))?;

    debug!("Successfully set environment variable {}", name);
    println!("Environment variable '{}' set to '{}' successfully!", name, value);
    println!("Note: You may need to log out and back in or reboot for changes to take effect.");
    
    Ok(())
}

pub fn get_env_var(name: &str) -> Result<String> {
    // First try standard env var
    if let Ok(value) = std::env::var(name) {
        debug!("Found {} in environment variables", name);
        return Ok(value);
    }

    debug!("Looking for {} in {}", name, ENV_FILE);

    // If not found, try reading from /etc/environment
    let file = File::open(ENV_FILE)
        .with_context(|| format!("{} Failed to read {}",
            logging::error_code(ErrorCode::EnvVarError),
            ENV_FILE))?;

    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.context("Failed to read line from environment file")?;
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == name {
                return Ok(value.trim().to_string());
            }
        }
    }

    Err(anyhow!("{} not found in environment or {}. Please run 'install-service' first to configure email settings", 
        name, ENV_FILE))
} 