/*
    TODO: @dev add user groups, with roles, permissions & access control.
*/

// use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use mongodb::bson::oid::ObjectId;

use super::communication::CommunicationPreferences;


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoginAttempt {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub user_id: ObjectId,
    pub ip_address: String,
    pub timestamp: i64,
    pub geographic_location: String,
    pub device_info: String,
}

pub struct ProfilePreferences {
    pub language: String, // Language preference, e.g., "en-US", "es-ES", etc.
    pub language_variant: String, // Language variant or dialect preference
    pub theme_color: String, // Theme color preference, e.g., "dark", "light"
    pub font_size: u8, // Font size preference
    pub email_preferences: EmailPreferences, // Email notification preferences
    pub privacy_settings: PrivacySettings, // Privacy settings
    pub content_filtering: ContentFilteringSettings, // Content filtering preferences
    pub location_settings: LocationSettings, // Location-based services settings
    pub syncing_preferences: SyncingPreferences, // Data syncing preferences
    pub backup_settings: BackupSettings, // Data backup preferences
    pub usage_statistics: UsageStatistics, // Usage statistics preferences
}

pub struct EmailPreferences {
    pub frequency: String, // Email frequency preference, e.g., "daily", "weekly", etc.
    pub types: Vec<String>, // Types of emails to receive, e.g., newsletters, promotions, etc.
}

pub struct PrivacySettings {
    pub sharing_level: String, // Privacy sharing level, e.g., "public", "private", etc.
}

pub struct ContentFilteringSettings {
    pub filter_types: Vec<String>, // Types of content to filter or block
}

pub struct LocationSettings {
    pub permissions: Vec<String>, // Location-based service permissions
}

pub struct SyncingPreferences {
    pub platforms: Vec<String>, // Platforms to sync data with
}

pub struct BackupSettings {
    pub frequency: String, // Data backup frequency preference, e.g., "daily", "weekly", etc.
    pub method: String, // Backup method preference, e.g., "cloud", "local", etc.
}

pub struct UsageStatistics {
    pub enabled: bool, // Whether usage statistics sharing is enabled
}



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
    // pub profile_preferences: ProfilePreferences,
    pub communication_preferences: CommunicationPreferences, // Reference to CommunicationPreferences
    pub failed_login_attempts: u32,
    pub lockout_until: Option<i64>, // Unix time
    pub permissions: i32,
    pub created: i64, // Unix time for creation timestamp
    pub updated: i64, // Unix time for update timestamp
    pub last_logged_in: Option<i64>, // Unix time for last login timestamp
    pub login_history: Option<Vec<ObjectId>>, // Stores login history as vector of ObjectId
    pub otp_code: Option<String>,
    pub otp_expires_at: Option<i64>,
    // pub data_privacy_settings_id: Option<ObjectId>, // Reference to DataPrivacySettings
    // pub failed_login_attempts: Option<i32>,
    // pub lockout_until: Option<DateTime<Utc>>,
    // pub gdpr_consent: Option<bool>, // EU GDPR consent
    // pub ccpa_opt_out: Option<bool>, // California CCPA opt-out
    // Add other fields as necessary
}
