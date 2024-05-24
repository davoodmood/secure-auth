use lettre::{Message, SmtpTransport, Transport};

pub fn send_reset_email(email: &str, token: &str) -> Result<(), lettre::error::Error> {
    let email_body = format!("Please use the following link to reset your password: https://yourdomain.com/reset_password?token={}", token);
    let email = Message::builder()
        .from("no-reply@yourdomain.com".parse().unwrap())
        .to(email.parse().unwrap())
        .subject("Password Reset Request")
        .body(email_body)
        .unwrap();

    let mailer = SmtpTransport::relay("smtp.yourprovider.com").unwrap().build();
    mailer.send(&email);

    Ok(())
}
