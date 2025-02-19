use anyhow::{Context, Result};
use log::info;
use std::path::Path;
use std::os::unix::fs::PermissionsExt;
use crate::utils::check_root_privileges;
use crate::utils::set_environment_variable;
use std::fs;

const DISPATCHER_DIR: &str = "/etc/NetworkManager/dispatcher.d";
const DISPATCHER_SCRIPT_NAME: &str = "90-robonet-notify";
const DISPATCHER_TEMPLATE: &str = include_str!("templates/dispatchers/90-robonet-notify");

pub fn install_service(
    email: Option<&str>,
    smtp_server: Option<&str>,
    smtp_user: Option<&str>,
    smtp_password: Option<&str>,
) -> Result<()> {
    check_root_privileges()?;
    info!("Installing NetworkManager dispatcher script");

    // First, ensure environment variables are set system-wide
    if let Some(email) = email {
        set_environment_variable("EMAIL_ADDRESS", email)?;
    }
    if let Some(server) = smtp_server {
        set_environment_variable("SMTP_SERVER", server)?;
    }
    if let Some(user) = smtp_user {
        set_environment_variable("SMTP_USER", user)?;
    }
    if let Some(pass) = smtp_password {
        set_environment_variable("SMTP_PASSWORD", pass)?;
    }

    // Get executable path
    let executable_path = std::env::current_exe()
        .context("Failed to get executable path")?;
    
    // Create dispatcher script content from template
    let script_content = DISPATCHER_TEMPLATE.replace("{executable}", &executable_path.display().to_string());

    // Ensure dispatcher directory exists
    fs::create_dir_all(DISPATCHER_DIR)
        .context("Failed to create dispatcher directory")?;

    // Write dispatcher script
    let script_path = Path::new(DISPATCHER_DIR).join(DISPATCHER_SCRIPT_NAME);
    fs::write(&script_path, script_content)
        .context("Failed to write dispatcher script")?;

    // Set executable permissions (755)
    fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
        .context("Failed to set dispatcher script permissions")?;

    println!("NetworkManager dispatcher script installed successfully!");
    println!("Script location: {}", script_path.display());

    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    check_root_privileges()?;
    info!("Removing NetworkManager dispatcher script");

    // Remove the dispatcher script
    let script_path = Path::new(DISPATCHER_DIR).join(DISPATCHER_SCRIPT_NAME);
    if script_path.exists() {
        fs::remove_file(&script_path)
            .context("Failed to remove dispatcher script")?;
    }

    println!("NetworkManager dispatcher script has been removed");
    Ok(())
} 