// use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use mongodb::bson::oid::ObjectId;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub username: String,
    pub password: String, // This will store the hashed password
    pub email: String,
    pub onboarding: bool,
    pub phone: Option<String>,
    pub tel: Option<String>,
    pub email_verified: Option<bool>,
    pub phone_verified: Option<bool>,
    pub email_verification_token: Option<String>,
    pub phone_verification_token: Option<String>,
    pub password_reset_token: Option<String>,
    pub mfa_enabled: Option<bool>,
    pub mfa_secret: Option<String>,  // This will store the TOTP secret, empty if MFA is not enabled
    pub mfa_recovery_codes: Option<Vec<String>>,
    // pub opted_out_marketing_emails: Option<String>,
    // pub failed_login_attempts: Option<i32>,
    // pub lockout_until: Option<DateTime<Utc>>,
    // Add other fields as necessary
}
