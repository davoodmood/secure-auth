use rand::{distributions::Alphanumeric, thread_rng, Rng};

pub fn generate_recovery_codes() -> Vec<String> {
    (0..5) // Generate 5 recovery codes
        .map(|_| {
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10) // Each code has 10 characters
                .map(|c| c as char) // Convert u8 to char
                .collect::<String>()
        })
        .collect()
}

// @dev: TODO Store these codes securely using the crypto utils, and mark them as used once a user redeems one.
pub fn generate_totp_secret() -> String {
    let secret: String = thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();
    secret
}