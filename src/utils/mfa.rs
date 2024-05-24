pub fn generate_recovery_codes() -> Vec<String> {
    (0..5) // Generate 5 recovery codes
        .map(|_| {
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10) // Each code has 10 characters
                .collect()
        })
        .collect()
}

// @dev: Store these codes securely, and mark them as used once a user redeems one.
