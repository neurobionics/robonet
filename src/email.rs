use anyhow::{Context, Result};
use lettre::{
    message::{header::ContentType, Mailbox, MultiPart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use std::process::Command;
use uuid::Uuid;

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
            .context("Failed to get hostname")?
            .to_string_lossy()
            .to_string();

        // Get IP address (both wlan0 and eth0)
        let mut ip_addresses = Vec::new();
        
        // Try wlan0
        if let Ok(output) = Command::new("ip")
            .args(["addr", "show", "wlan0"])
            .output() {
            let output = String::from_utf8_lossy(&output.stdout);
            if let Some(ip) = output
                .lines()
                .find(|line| line.contains("inet "))
                .and_then(|line| line.split_whitespace().nth(1))
                .map(|ip| ip.split('/').next().unwrap_or("").to_string()) {
                if !ip.is_empty() {
                    ip_addresses.push(format!("WiFi (wlan0): {}", ip));
                }
            }
        }
        
        // Try eth0
        if let Ok(output) = Command::new("ip")
            .args(["addr", "show", "eth0"])
            .output() {
            let output = String::from_utf8_lossy(&output.stdout);
            if let Some(ip) = output
                .lines()
                .find(|line| line.contains("inet "))
                .and_then(|line| line.split_whitespace().nth(1))
                .map(|ip| ip.split('/').next().unwrap_or("").to_string()) {
                if !ip.is_empty() {
                    ip_addresses.push(format!("Ethernet (eth0): {}", ip));
                }
            }
        }

        let ip_address = if ip_addresses.is_empty() {
            "No IP addresses found".to_string()
        } else {
            ip_addresses.join("\n")
        };

        // Get MAC address for both interfaces
        let mut mac_addresses = Vec::new();
        
        for interface in &["wlan0", "eth0"] {
            if let Ok(mac) = std::fs::read_to_string(format!("/sys/class/net/{}/address", interface)) {
                let mac = mac.trim();
                if !mac.is_empty() {
                    mac_addresses.push(format!("{}: {}", interface, mac));
                }
            }
        }

        let mac_address = if mac_addresses.is_empty() {
            "No MAC addresses found".to_string()
        } else {
            mac_addresses.join("\n")
        };

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

pub fn send_network_status_email(config: &EmailConfig, ip_changed: bool) -> Result<()> {
    let system_info = SystemInfo::collect()?;
    
    let status_type = if ip_changed {
        "IP Address Change Report"
    } else {
        "Initial Connection Report"
    };
    
    let html_content = format!(
        r#"<!DOCTYPE html>
        <html dir="ltr" lang="en">
            <head>
                <meta content="text/html; charset=UTF-8" http-equiv="Content-Type" />
            </head>
            <body style="background-color:rgb(0,0,0);margin:auto;font-family:system-ui;padding:1rem">
                <table align="center" width="100%" style="max-width:700px;border:1px solid rgb(82,82,91);border-radius:0.375rem;margin:40px auto;padding:20px">
                    <tbody>
                        <tr style="width:100%">
                            <td>
                                <h1 style="font-weight:400;text-align:center;border-radius:0.375rem;padding:1rem;margin:0 0 12px;border:1px solid rgb(82,82,91)">
                                    <p style="font-size:14px;line-height:28px;margin:16px 0;color:rgb(205,205,205);text-align:center;margin-bottom:12px">
                                        <strong style="color:rgb(255,255,255);font-size:32px">Raspberry Pi Network Status</strong><br />
                                        {}</p>
                                </h1>
                                <table align="center" width="100%" style="border-radius:0.375rem;padding:1rem;margin:auto;border:1px solid rgb(82,82,91)">
                                    <tbody style="color:rgb(255,255,255)">
                                        <tr>
                                            <td style="padding:10px">Hostname:</td>
                                            <td style="padding:10px">{}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding:10px">IP Addresses:</td>
                                            <td style="padding:10px;color:rgb(165,243,252);white-space:pre-line">{}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding:10px">MAC Addresses:</td>
                                            <td style="padding:10px;white-space:pre-line">{}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding:10px">WiFi Network:</td>
                                            <td style="padding:10px">{}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding:10px">Session ID:</td>
                                            <td style="padding:10px">{}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding:10px">Timestamp:</td>
                                            <td style="padding:10px">{}</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </body>
        </html>"#,
        status_type,
        system_info.hostname,
        system_info.ip_address,
        system_info.mac_address,
        system_info.ssid,
        system_info.session_id,
        system_info.timestamp,
    );

    let email = Message::builder()
        .from("Raspberry Pi <raspberry.pi@localhost>".parse()?)
        .to(config.recipient.parse::<Mailbox>()?)
        .subject(format!("Raspberry Pi Network Status - {}", system_info.hostname))
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
        .context("Failed to send email")?;

    Ok(())
} 