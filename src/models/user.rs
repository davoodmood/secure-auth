use serde::{Serialize, Deserialize};
use mongodb::bson::oid::ObjectId;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub username: String,
    pub password: String, // This will store the hashed password
    pub email: String,
    // pub mfa_enabled: bool,
    // pub mfa_secret: Option<String>,  // This will store the TOTP secret, empty if MFA is not enabled

    // Add other fields as necessary
}
