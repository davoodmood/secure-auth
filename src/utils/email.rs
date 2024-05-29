use log::{error, info};
use std::env;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::{
    authentication::{Credentials, Mechanism},
    client::{
        Tls,
        TlsParameters
    }
};

pub async fn send_reset_email(email: &str, token: &str) -> Result<(), lettre::error::Error> {
    // Fetch SMTP server endpoint, username, and password from environment variables

    let smtp_server = env::var("SMTP_SERVER").expect("SMTP_SERVER environment variable not set");
    let smtp_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME environment variable not set");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD environment variable not set");
    let server_domain = env::var("SERVER_DOMAIN").expect("SERVER_DOMAIN environment variable not set");
    
    // Set the email body & message
    let from_address = format!("no-reply@{}", server_domain);
    let email_body = format!("Please use the following link to reset your password: https://{}/reset_password?token={}", server_domain, token);
    let email = Message::builder()
        .from(from_address.parse().unwrap())
        .to(email.parse().unwrap())
        .subject("Password Reset Request")
        .body(email_body)
        .unwrap();

    // Set the TLS-Required Parameters
    let tls_parameters = TlsParameters::builder(smtp_server.clone())
        .build()
        .unwrap();

    // Setup the SMTP Transport with Aha-Send SMTP-Server Relayer
    let mailer = SmtpTransport::relay(&smtp_server)
    .unwrap()
    .port(587)
    .credentials(Credentials::new(smtp_username, smtp_password))
    .tls(Tls::Required(tls_parameters))
    .authentication(vec![Mechanism::Plain]) // Set the authentication method to PLAIN
    .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => {
            info!("Email sent successfully");
            Ok(())
        }
        Err(e) => {
            error!("Failed to send email: {:?}", e);
            Ok(())
        }
    }
}
