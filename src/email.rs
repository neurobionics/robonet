use anyhow::{Context, Result};
use lettre::{
    message::{header::ContentType, Mailbox, MultiPart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use std::process::Command;
use uuid::Uuid;
use crate::logging;
use crate::utils::get_env_var;

pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_user: String,
    pub smtp_password: String,
    pub recipients: Vec<String>,
}

impl EmailConfig {
    pub fn from_env() -> Result<Self> {
        // Get and split email addresses
        let email_addresses = get_env_var("EMAIL_ADDRESS")
            .context("EMAIL_ADDRESS not configured")?;
        
        let recipients: Vec<String> = email_addresses
            .split(',')
            .map(str::trim)
            .map(String::from)
            .collect();

        Ok(EmailConfig {
            smtp_server: get_env_var("SMTP_SERVER")
                .context("SMTP_SERVER not configured")?,
            smtp_user: get_env_var("SMTP_USER")
                .context("SMTP_USER not configured")?,
            smtp_password: get_env_var("SMTP_PASSWORD")
                .context("SMTP_PASSWORD not configured")?,
            recipients,
        })
    }
}

pub struct SystemInfo {
    hostname: String,
    ip_address: String,
    mac_address: String,
    ssid: String,
    session_id: String,
    timestamp: String,
}

impl SystemInfo {
    pub fn collect() -> Result<Self> {
        let hostname = hostname::get()
            .with_context(|| format!("{} Failed to get hostname",
                logging::error_code(logging::ErrorCode::FileSystemError)))?
            .to_string_lossy()
            .to_string();

        // Get IP address (wlan0 only)
        let ip_address = Command::new("ip")
            .args(["addr", "show", "wlan0"])
            .output()
            .ok()
            .and_then(|output| {
                let output = String::from_utf8_lossy(&output.stdout);
                output
                    .lines()
                    .find(|line| line.contains("inet "))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .map(|ip| ip.split('/').next().unwrap_or("").to_string())
            })
            .filter(|ip| !ip.is_empty())
            .unwrap_or_else(|| "No IP address found".to_string());

        // Get MAC address for wlan0 only
        let mac_address = std::fs::read_to_string("/sys/class/net/wlan0/address")
            .map(|mac| mac.trim().to_string())
            .unwrap_or_else(|_| "No MAC address found".to_string());

        // Get SSID if connected to WiFi
        let ssid = Command::new("iwgetid")
            .arg("-r")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|_| "Not connected to WiFi".to_string());

        // Generate session ID
        let session_id = Uuid::new_v4().to_string();

        // Get timestamp
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string();

        Ok(Self {
            hostname,
            ip_address,
            mac_address,
            ssid,
            session_id,
            timestamp,
        })
    }
}

pub fn send_login_ticket(config: &EmailConfig) -> Result<()> {
    let system_info = SystemInfo::collect()
        .with_context(|| format!("{} Failed to collect system information",
            logging::error_code(logging::ErrorCode::EmailTemplateFailed)))?;
    
    // Read the template file from the compiled output directory
    let template = include_str!(concat!(env!("OUT_DIR"), "/templates/emails/login_ticket.html"));

    let html_content = template
        .replace("{STATUS_TYPE}", "New Login Ticket")
        .replace("{HOSTNAME}", &system_info.hostname)
        .replace("{IP_ADDRESS}", &system_info.ip_address)
        .replace("{MAC_ADDRESS}", &system_info.mac_address)
        .replace("{SSID}", &system_info.ssid)
        .replace("{SESSION_ID}", &system_info.session_id)
        .replace("{TIMESTAMP}", &system_info.timestamp);

    let mut builder = Message::builder()
        .from(format!("{} <raspberry.pi@localhost>", system_info.hostname).parse()?);

    // Add all recipients
    for recipient in &config.recipients {
        builder = builder.to(recipient.parse::<Mailbox>()?);
    }

    let email = builder
        .subject(format!(
            "Login Ticket for {} - {}", 
            system_info.hostname,
            system_info.timestamp.split_whitespace().next().unwrap_or("")
        ))
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    lettre::message::SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(html_content),
                ),
        )?;

    let creds = Credentials::new(
        config.smtp_user.clone(),
        config.smtp_password.clone(),
    );

    let mailer = SmtpTransport::relay(&config.smtp_server)?
        .credentials(creds)
        .build();

    mailer.send(&email)
        .with_context(|| format!("{} Failed to send email",
            logging::error_code(logging::ErrorCode::EmailSendFailed)))?;

    Ok(())
} 