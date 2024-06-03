use actix_web::http::header::ContentType;
use log::{error, info};
use std::env;
use std::error::Error;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::{
    authentication::{Credentials, Mechanism},
    client::{
        Tls,
        TlsParameters
    }
};

struct SmtpConfig {
    smtp_server: String,
    smtp_username: String,
    smtp_password: String,
    server_domain: String,
}

fn get_smtp_config() -> Result<SmtpConfig, Box<dyn Error>> {
    Ok(SmtpConfig {
        smtp_server: env::var("SMTP_SERVER")?,
        smtp_username: env::var("SMTP_USERNAME")?,
        smtp_password: env::var("SMTP_PASSWORD")?,
        server_domain: env::var("SERVER_DOMAIN")?,
    })
}

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


// Function to notify the user of the successful password reset
pub async fn notify_password_reset(email: &str) -> Result<(), Box<dyn Error>> {
    let config = get_smtp_config()?;

    // Set the email body & message
    let from_address = format!("no-reply@{}", config.server_domain);
    let email_body = "Your password has been reset successfully.".to_string();
    let email = Message::builder()
        .from(from_address.parse()?)
        .to(email.parse()?)
        .subject("Password Reset Confirmation")
        .body(email_body)?;

    // Set the TLS-Required Parameters
    let tls_parameters = TlsParameters::builder(config.smtp_server.clone())
        .build()?;

    // Setup the SMTP Transport with TLS
    let mailer = SmtpTransport::relay(&config.smtp_server)?
        .port(587)
        .credentials(Credentials::new(config.smtp_username, config.smtp_password))
        .tls(Tls::Required(tls_parameters))
        .authentication(vec![Mechanism::Plain]) // Set the authentication method to PLAIN
        .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => {
            info!("Password reset confirmation email sent successfully");
            Ok(())
        }
        Err(e) => {
            error!("Failed to send password reset confirmation email: {:?}", e);
            Err(Box::new(e))
        }
    }
}

pub async fn send_verification_email(email: &str, token: &str) -> Result<(), Box<dyn Error>> {
    let config = get_smtp_config().expect("Failed to get SMTP config");

    let from_address = format!("no-reply@{}", config.server_domain);
    let email_body = format!("Please verify your email by clicking on the following link: https://{}/verify_email?token={}", config.server_domain, token);
    let email = Message::builder()
        .from(from_address.parse().unwrap())
        .to(email.parse().unwrap())
        .subject("Email Verification")
        .body(email_body)
        .unwrap();

    let tls_parameters = TlsParameters::builder(config.smtp_server.clone())
        .build()
        .unwrap();

    let mailer = SmtpTransport::relay(&config.smtp_server)
        .unwrap()
        .port(587)
        .credentials(Credentials::new(config.smtp_username.clone(), config.smtp_password.clone()))
        .tls(Tls::Required(tls_parameters))
        .authentication(vec![Mechanism::Plain])
        .build();

    match mailer.send(&email) {
        Ok(_) => {
            info!("Verification email sent successfully");
            Ok(())
        }
        Err(e) => {
            error!("Failed to send verification email: {:?}", e);
            Err(Box::new(e))
        }
    }
}

// pub async fn send_verification_email(email: &str, otp_code: &str) -> Result<(), Box<dyn Error>> {
//     let config = get_smtp_config().expect("Failed to get SMTP config");

//     let from_address = format!("no-reply@{}", config.server_domain);
//     let email_body = format!("Please verify your email by clicking on the following link: https://{}/verify_email?token={}", config.server_domain, token);
//     let email = Message::builder()
//         .from(from_address.parse().unwrap())
//         .to(email.parse().unwrap())
//         .subject("Email Verification")
//         .body(email_body)
//         .unwrap();

//     let tls_parameters = TlsParameters::builder(config.smtp_server.clone())
//         .build()
//         .unwrap();

//     let mailer = SmtpTransport::relay(&config.smtp_server)
//         .unwrap()
//         .port(587)
//         .credentials(Credentials::new(config.smtp_username.clone(), config.smtp_password.clone()))
//         .tls(Tls::Required(tls_parameters))
//         .authentication(vec![Mechanism::Plain])
//         .build();

//     match mailer.send(&email) {
//         Ok(_) => {
//             info!("Verification email sent successfully");
//             Ok(())
//         }
//         Err(e) => {
//             error!("Failed to send verification email: {:?}", e);
//             Err(Box::new(e))
//         }
//     }
// }


pub async fn send_otp(email: &str, otp_code: &str) -> Result<(), Box<dyn Error>> {
    let config = get_smtp_config().expect("Failed to get SMTP config");

    let from_address = format!("no-reply@{}", config.server_domain);
    let email_body = format!("Your OTP code is: {}", otp_code);
    let email = Message::builder()
        .from(from_address.parse().unwrap())
        .to(email.parse().unwrap())
        .subject("Your OTP code")
        .body(email_body)
        .unwrap();

    let tls_parameters = TlsParameters::builder(config.smtp_server.clone())
        .build()?;

    let mailer = SmtpTransport::relay(&config.smtp_server)?
        .port(587)
        .credentials(Credentials::new(config.smtp_username.clone(), config.smtp_password.clone()))
        .tls(Tls::Required(tls_parameters))
        .authentication(vec![Mechanism::Plain])
        .build();

    match mailer.send(&email) {
        Ok(_) => {
            info!("OTP email sent successfully");
            Ok(())
        }
        Err(e) => {
            error!("Failed to send OTP email: {:?}", e);
            Err(Box::new(e))
        }
    }
}


