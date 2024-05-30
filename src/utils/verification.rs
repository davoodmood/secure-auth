use rand::Rng;
use rand::distributions::Alphanumeric;

// @notice: generate a 32-character alphanumeric verification token
pub fn generate_email_verification_token() -> String {
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect()
}

// @notice: generate a 8-character alphanumeric verification token
pub fn generate_text_verification_token() -> String {
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect()
}
