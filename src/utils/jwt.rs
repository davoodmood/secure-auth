use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use mongodb::{bson::doc, Database};
use serde::{Serialize, Deserialize};
use std::env;
use std::error::Error;

use crate::models::user::User;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    exp: usize,
}

pub fn create_token(username: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: username.to_owned(),
        exp: expiration as usize,
    };

    let secret: String = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
}


pub async fn create_reset_token(email: &str, db: &Database) -> Result<String, Box<dyn Error>> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(15))  // Shorter expiration time for reset tokens
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: email.to_owned(),
        exp: expiration as usize,
    };

    let secret = env::var("JWT_RESET_SECRET")?.into_bytes();  // Separate secret for reset tokens
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(&secret))?;

    // Set the created token in the user account's database
    let collection: mongodb::Collection<User> = db.collection("users");

    let filter = doc! { "email": email };
    let update = doc! { "$set": { "password_reset_token": &token } };

    match collection.update_one(filter, update, None).await {
        Ok(_) => Ok(token),
        Err(err) => Err(Box::new(err)),
    }
}

