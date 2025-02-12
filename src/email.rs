use anyhow::{Context, Result};
use lettre::{
    message::{header::ContentType, Mailbox, MultiPart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use std::process::Command;
use uuid::Uuid;
use crate::logging;

pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_user: String,
    pub smtp_password: String,
    pub recipient: String,
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

        // Get IP address (improved to handle errors)
        let ip_address = Command::new("ip")
            .args(["addr", "show", "wlan0"])
            .output()
            .with_context(|| "Failed to execute ip command")?
            .stdout;
        let ip_address = String::from_utf8_lossy(&ip_address)
            .lines()
            .find(|line| line.contains("inet "))
            .and_then(|line| line.split_whitespace().nth(1))
            .map(|ip| ip.split('/').next().unwrap_or("").to_string())
            .unwrap_or_else(|| "No IP address found".to_string());

        // Get MAC address with proper error handling
        let mac_address = std::fs::read_to_string("/sys/class/net/wlan0/address")
            .with_context(|| "Failed to read MAC address")?
            .trim()
            .to_string();

        // Get SSID with proper error handling
        let ssid = Command::new("iwgetid")
            .arg("-r")
            .output()
            .with_context(|| "Failed to get SSID")?;
        let ssid = String::from_utf8_lossy(&ssid.stdout)
            .trim()
            .to_string();

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

#[derive(Debug)]
pub enum LoginTicketReason {
    InitialLogin,
    IpChanged,
    ManualCheck,
}

pub fn send_login_ticket(config: &EmailConfig, reason: LoginTicketReason) -> Result<()> {
    let system_info = SystemInfo::collect()
        .with_context(|| format!("{} Failed to collect system information",
            logging::error_code(logging::ErrorCode::EmailTemplateFailed)))?;
    
    let status_type = match reason {
        LoginTicketReason::InitialLogin => "New Login",
        LoginTicketReason::IpChanged => "IP Address Change Alert",
        LoginTicketReason::ManualCheck => "Manual Execution",
    };

    // Read the template file from the compiled output directory
    let template = include_str!(concat!(env!("OUT_DIR"), "/templates/emails/login_ticket.html"));

    let html_content = template
        .replace("{STATUS_TYPE}", status_type)
        .replace("{HOSTNAME}", &system_info.hostname)
        .replace("{IP_ADDRESS}", &system_info.ip_address)
        .replace("{MAC_ADDRESS}", &system_info.mac_address)
        .replace("{SSID}", &system_info.ssid)
        .replace("{SESSION_ID}", &system_info.session_id)
        .replace("{TIMESTAMP}", &system_info.timestamp);

    let email = Message::builder()
        .from(format!("Raspberry Pi <{}>", config.smtp_user).parse()?)
        .to(config.recipient.parse::<Mailbox>()?)
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
        .tls(lettre::transport::smtp::client::Tls::Required(
            lettre::transport::smtp::client::TlsParameters::new(config.smtp_server.clone())?
        ))
        .build();

    mailer.send(&email)
        .with_context(|| format!("{} Failed to send email",
            logging::error_code(logging::ErrorCode::EmailSendFailed)))?;

    Ok(())
} 