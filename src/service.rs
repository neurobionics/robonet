use anyhow::{Context, Result, anyhow};
use log::{info, debug, error, warn};
use std::collections::HashMap;
use std::process::{Command, Output};
use std::path::Path;
use std::os::unix::fs::PermissionsExt;
use crate::email::{EmailConfig, send_login_ticket, LoginTicketReason};
use crate::utils::{get_env_var, check_root_privileges};
use crate::logging;
use crate::logging::ErrorCode;

pub const SERVICE_TEMPLATE: &str = include_str!("templates/services/robonet-monitor.service");

fn run_systemctl_command(args: &[&str]) -> Result<Output> {
    Command::new("systemctl")
        .args(args)
        .output()
        .with_context(|| format!("{} Failed to execute systemctl command: {:?}",
            logging::error_code(ErrorCode::ServiceInstallFailed),
            args))
}

pub fn install_service(
    email: Option<&str>,
    smtp_server: Option<&str>,
    smtp_user: Option<&str>,
    smtp_password: Option<&str>,
    check_interval: u64,
    max_retries: u32,
) -> Result<()> {
    check_root_privileges()?;
    info!("Installing network manager service");
    debug!("Email: {:?}, SMTP Server: {:?}", email, smtp_server);
    
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

    // Validate executable path
    if !executable_path.exists() {
        return Err(anyhow!("Executable not found at: {}", executable_path.display()));
    }

    // Create service file path
    let service_path = Path::new("/etc/systemd/system/robonet-monitor.service");

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

    debug!("Writing service file to {}", service_path.display());
    
    // Write service file with proper permissions (644)
    std::fs::write(service_path, service_content.as_bytes())
        .context("Failed to write service file")?;
    
    std::fs::set_permissions(service_path, std::fs::Permissions::from_mode(0o644))
        .context("Failed to set service file permissions")?;

    // Reload systemd daemon
    let output = run_systemctl_command(&["daemon-reload"])?;
    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        error!("{} Failed to reload systemd daemon: {}", 
            logging::error_code(ErrorCode::ServiceInstallFailed),
            error_msg);
        return Err(anyhow!("Failed to reload systemd daemon: {}", error_msg));
    }

    // Enable service
    let output = run_systemctl_command(&["enable", "robonet-monitor"])?;
    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        error!("Failed to enable service: {}", error_msg);
        // Cleanup on failure
        let _ = std::fs::remove_file(service_path);
        return Err(anyhow!("Failed to enable service: {}", error_msg));
    }

    // Start service
    let output = run_systemctl_command(&["start", "robonet-monitor"])?;
    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        error!("Failed to start service: {}", error_msg);
        // Cleanup on failure
        let _ = run_systemctl_command(&["disable", "robonet-monitor"]);
        let _ = std::fs::remove_file(service_path);
        return Err(anyhow!("Failed to start service: {}", error_msg));
    }

    // Verify service is running
    let output = run_systemctl_command(&["is-active", "robonet-monitor"])?;
    if !output.status.success() {
        warn!("Service installed but may not be running properly. Please check status manually.");
    }

    info!("Service installed and started successfully!");
    println!("Service installed and started successfully!");
    println!("To check service status: sudo systemctl status robonet-monitor");
    println!("To view logs: sudo journalctl -u robonet-monitor -f");

    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    check_root_privileges()?;
    info!("Uninstalling network manager service");

    // Stop the service if it's running
    let output = run_systemctl_command(&["stop", "robonet-monitor"])?;
    if !output.status.success() {
        warn!("Failed to stop service, it might not be running");
    }

    // Disable the service
    let output = run_systemctl_command(&["disable", "robonet-monitor"])?;
    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        error!("{} Failed to disable service: {}", 
            logging::error_code(ErrorCode::ServiceUninstallFailed),
            error_msg);
    }

    // Remove the service file
    let service_path = Path::new("/etc/systemd/system/robonet-monitor.service");
    if service_path.exists() {
        std::fs::remove_file(service_path)
            .context("Failed to remove service file")?;
    }

    // Reload systemd daemon
    let output = run_systemctl_command(&["daemon-reload"])?;
    if !output.status.success() {
        warn!("Failed to reload systemd daemon after uninstall");
    }

    info!("Network manager service uninstalled successfully");
    println!("Network manager service has been uninstalled");

    Ok(())
} 