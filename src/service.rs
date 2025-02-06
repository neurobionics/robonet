use anyhow::{Context, Result, anyhow};
use log::{info, debug, error};
use std::collections::HashMap;
use std::process::Command;
use crate::email::{EmailConfig, send_login_ticket, LoginTicketReason};
use crate::utils::get_env_var;
use crate::logging;
use crate::logging::ErrorCode;

pub const SERVICE_TEMPLATE: &str = include_str!("templates/services/robonet-monitor.service");

pub fn install_service(
    email: Option<&str>,
    smtp_server: Option<&str>,
    smtp_user: Option<&str>,
    smtp_password: Option<&str>,
    check_interval: u64,
    max_retries: u32,
) -> Result<()> {

    info!("Installing network manager service");
    debug!("Email: {:?}, SMTP Server: {:?}", email, smtp_server); // Use {:?} for Option types
    
    let email = email
        .map(String::from)
        .or_else(|| get_env_var("EMAIL_ADDRESS").ok())
        .context("Email address not provided. Set EMAIL_ADDRESS environment variable or use --email flag")?;
    
    let smtp_server = smtp_server
        .map(String::from)
        .or_else(|| get_env_var("SMTP_SERVER").ok())
        .context("SMTP server not provided. Set SMTP_SERVER environment variable or use --smtp-server flag")?;
    
    let smtp_user = smtp_user
        .map(String::from)
        .or_else(|| get_env_var("SMTP_USER").ok())
        .context("SMTP username not provided. Set SMTP_USER environment variable or use --smtp-user flag")?;
    
    let smtp_password = smtp_password
        .map(String::from)
        .or_else(|| get_env_var("SMTP_PASSWORD").ok())
        .context("SMTP password not provided. Set SMTP_PASSWORD environment variable or use --smtp-password flag")?;

    // Test email configuration before installing service
    let email_config = EmailConfig {
        smtp_server: smtp_server.clone(),
        smtp_user: smtp_user.clone(),
        smtp_password: smtp_password.clone(),
        recipient: email.clone(),
    };

    info!("Testing email configuration");
    send_login_ticket(&email_config, LoginTicketReason::InitialLogin)?;

    let executable_path = std::env::current_exe()
        .context("Failed to get executable path")?;
    
    // Create a HashMap for template variables
    let mut vars = HashMap::new();
    vars.insert("EXECUTABLE_PATH", executable_path.display().to_string());
    vars.insert("NOTIFICATION_EMAIL", email.to_string());
    vars.insert("SMTP_SERVER", smtp_server.to_string());
    vars.insert("SMTP_USER", smtp_user.to_string());
    vars.insert("SMTP_PASSWORD", smtp_password.to_string());
    vars.insert("CHECK_INTERVAL_SECS", check_interval.to_string());
    vars.insert("MAX_RETRIES", max_retries.to_string());

    // Replace template variables
    let service_content = vars.iter().fold(SERVICE_TEMPLATE.to_string(), |content, (key, value)| {
        content.replace(&format!("${{{}}}", key), value)
    });

    debug!("Writing service file to /etc/systemd/system/robonet-monitor.service");
    std::fs::write("/etc/systemd/system/robonet-monitor.service", service_content)
        .context("Failed to write service file")?;

    // Reload systemd daemon
    let status = Command::new("systemctl")
        .arg("daemon-reload")
        .status()
        .with_context(|| format!("{} Failed to reload systemd daemon",
            logging::error_code(ErrorCode::ServiceInstallFailed)))?;

    if !status.success() {
        error!("{} Failed to reload systemd daemon",
            logging::error_code(ErrorCode::ServiceInstallFailed));
        return Err(anyhow!("Failed to reload systemd daemon"));
    }

    // Enable service
    let status = Command::new("systemctl")
        .args(["enable", "robonet-monitor"])
        .status()
        .context("Failed to enable service")?;

    if !status.success() {
        return Err(anyhow!("Failed to enable service"));
    }

    // Start service
    let status = Command::new("systemctl")
        .args(["start", "robonet-monitor"])
        .status()
        .context("Failed to start service")?;

    if !status.success() {
        return Err(anyhow!("Failed to start service"));
    }

    println!("Service installed and started successfully!");
    println!("To check service status: sudo systemctl status robonet-monitor");
    println!("To view logs: sudo journalctl -u robonet-monitor -f");

    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    use std::process::Command;
    use anyhow::Context;
    use log::info;

    info!("Uninstalling network manager service");

    // Stop the service if it's running
    let _ = Command::new("systemctl")
        .args(["stop", "robonet-monitor.service"])
        .output()
        .context("Failed to stop service")?;

    // Disable the service
    Command::new("systemctl")
        .args(["disable", "robonet-monitor.service"])
        .output()
        .with_context(|| format!("{} Failed to disable service",
            logging::error_code(ErrorCode::ServiceUninstallFailed)))?;

    // Remove the service file
    let service_path = "/etc/systemd/system/robonet-monitor.service";
    if std::path::Path::new(service_path).exists() {
        std::fs::remove_file(service_path)
            .context("Failed to remove service file")?;
    }

    // Reload systemd daemon
    Command::new("systemctl")
        .arg("daemon-reload")
        .output()
        .context("Failed to reload systemd daemon")?;

    info!("Network manager service uninstalled successfully");
    println!("Network manager service has been uninstalled");

    Ok(())
} 