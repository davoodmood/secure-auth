use std::collections::HashMap;

// use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use mongodb::bson::oid::ObjectId;

use super::communication::CommunicationPreferences;

#[derive(Debug, Serialize, Deserialize, Clone)]
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
    pub is_mfa_required: bool,
    pub mfa_enabled: Option<bool>,
    pub mfa_secret: Option<String>,  // This will store the TOTP secret, empty if MFA is not enabled
    pub mfa_recovery_codes: Option<Vec<String>>,
    pub communication_preferences: CommunicationPreferences, // Reference to CommunicationPreferences
    pub created: i64, // Unix time for creation timestamp
    pub updated: i64, // Unix time for update timestamp
    pub last_logged_in: Option<i64>, // Unix time for last login timestamp
    // pub data_privacy_settings_id: Option<ObjectId>, // Reference to DataPrivacySettings
    // pub failed_login_attempts: Option<i32>,
    // pub lockout_until: Option<DateTime<Utc>>,
    // pub gdpr_consent: Option<bool>, // EU GDPR consent
    // pub ccpa_opt_out: Option<bool>, // California CCPA opt-out
    // Add other fields as necessary
}
