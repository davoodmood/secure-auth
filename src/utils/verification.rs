use chrono::{Duration, Utc};
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use mongodb::Database;
use rand::Rng;
use rand::distributions::Alphanumeric;

use crate::models::user::User;

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

pub fn generate_otp() -> String {
    // Generate a random 6-digit OTP code
    let mut rng = rand::thread_rng();
    (0..6)
        .map(|_| rng.gen_range(0..10).to_string())
        .collect::<Vec<String>>()
        .join("")
}


async fn store_otp(db: &Database, user_id: &ObjectId, otp_code: &str) {
    let collection = db.collection::<User>("users");
    let filter = doc! { "_id": user_id };
    let update = doc! { "$set": { "otp_code": otp_code, "otp_expires_at": (Utc::now() + Duration::minutes(10)).timestamp() }};
    collection.update_one(filter, update, None).await.unwrap();
}

