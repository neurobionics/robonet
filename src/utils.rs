use anyhow::{Context, Result, anyhow};
use nix;
use log::error;
use crate::logging;
use crate::logging::ErrorCode;

pub fn check_root_privileges() -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        error!("{} Root privileges required",
            logging::error_code(ErrorCode::PermissionDenied));
        return Err(anyhow!("This program must be run with root privileges (sudo)"));
    }
    Ok(())
}

pub fn set_environment_variable(name: &str, value: &str) -> Result<()> {
    let env_file = "/etc/environment";
    
    // Read existing content
    let content = std::fs::read_to_string(env_file)
        .with_context(|| format!("{} Failed to read environment file",
            logging::error_code(ErrorCode::EnvVarError)))?;
    
    // Parse existing variables
    let mut lines: Vec<String> = content.lines()
        .filter(|line| !line.starts_with(&format!("{}=", name)))
        .map(String::from)
        .collect();
    
    // Add new variable
    lines.push(format!("{}={}", name, value));
    
    // Write back to file
    std::fs::write(env_file, lines.join("\n") + "\n")
        .with_context(|| format!("{} Failed to write environment file",
            logging::error_code(ErrorCode::EnvVarError)))?;
    
    println!("Environment variable '{}' set to '{}' successfully!", name, value);
    println!("Note: You may need to log out and back in or reboot for changes to take effect.");
    
    Ok(())}

pub fn get_env_var(name: &str) -> Result<String> {
    // First try standard env var
    if let Ok(value) = std::env::var(name) {
        return Ok(value);
    }

    // If not found, try reading from /etc/environment
    let content = std::fs::read_to_string("/etc/environment")
        .context("Failed to read /etc/environment")?;

    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == name {
                return Ok(value.trim().to_string());
            }
        }
    }

    Err(anyhow!("{} not found in environment or /etc/environment. Please run 'install-service' first to configure email settings", name))

} 