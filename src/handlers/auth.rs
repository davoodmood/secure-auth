use std::{collections::HashMap, env};

use actix_web::{http::header, web, HttpResponse, Responder};
use chrono::Utc;
use mongodb::{
    bson::{doc, oid::ObjectId, Bson}, Database
};
use regex::Regex;
use bcrypt::{hash, DEFAULT_COST, verify};
use jsonwebtoken::{encode, Header, EncodingKey};
use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use otpauth::TOTP;
use qrcode::{QrCode, render::svg};
use std::time::{SystemTime, UNIX_EPOCH};


use crate::{models::{communication::CommunicationPreferences, user::User}, utils::{crypto::{decrypt, encrypt}, mfa::{generate_recovery_codes, generate_totp_secret}}};
use crate::utils::{
    verification::{
        generate_email_verification_token,
        generate_text_verification_token
    },
    jwt::{
        Claims, 
        create_token, 
        create_reset_token
    }, 
    email::{
        send_reset_email, 
        notify_password_reset,
        send_verification_email
    },
    txt::send_verification_text,
};

struct Username(String);

impl Username {
    fn new(username: &str) -> Result<Self, &'static str> {
        if username.len() < 3 {
            Err("Username must be at least 3 characters long")
        } else {
            Ok(Self(username.to_string()))
        }
    }
}

#[derive(Debug)]
struct Email(String);

impl Email {
    pub fn new(email: &str) -> Result<Self, &'static str> {
        let email_regex = Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").unwrap();
        if email_regex.is_match(email) {
            Ok(Self(email.to_string()))
        } else {
            Err("Invalid email format")
        }
    }
}

#[derive(Debug)]
struct Password(String);

impl Password {
    pub fn new(password: &str) -> Result<Self, &'static str> {
        if password.len() < 8 {
            Err("Password must be at least 8 characters long")
        } else {
            Ok(Self(password.to_string()))
        }
    }
}


#[derive(Clone)]
struct PhoneNumber(String);

impl PhoneNumber {
    pub fn new(phone: &str) -> Result<Self, &'static str> {
        if validate_phone_number(phone) {
            Ok(Self(phone.to_string()))
        } else {
            Err("Invalid phone number format")
        }
    }
}

impl From<&PhoneNumber> for Bson {
    fn from(phone: &PhoneNumber) -> Bson {
        Bson::String(phone.0.clone())
    }
}

fn validate_phone_number(phone: &str) -> bool {
    let mut chars = phone.chars();
    let valid_chars: Vec<char> = "0123456789+".chars().collect();
    let has_plus = chars.next() == Some('+');

    if has_plus && chars.all(|c| valid_chars.contains(&c)) {
        true
    } else if !has_plus && chars.all(|c| valid_chars.contains(&c)) {
        true
    } else {
        false
    }
}



#[derive(Deserialize)]
pub struct UserRequest {
    username: String,
    email: String,
    password: String,
    phone: Option<String>,
    receive_promotions: Option<bool>,
}

#[derive(Serialize)]
struct UserResponse {
    id: String,
    username: String,
    email: String,
    onboarding: bool,
    phone: Option<String>,
    tel: Option<String>,
    email_verified: Option<bool>,
    phone_verified: Option<bool>,
    communication_preferences: CommunicationPreferences,
    created: i64,
    last_logged_in: Option<i64>,
    // message: String,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id.map(|id| id.to_hex()).unwrap_or("".to_string()), // Convert ObjectId to String
            username: user.username,
            email: user.email,
            onboarding: user.onboarding,
            phone: user.phone,
            tel: user.tel,
            email_verified: user.email_verified,
            phone_verified: user.phone_verified,
            communication_preferences: user.communication_preferences,
            created: user.created,
            last_logged_in: user.last_logged_in,
            // message: "User data fetched successfully".to_string(),
        }
    }
}

pub async fn register_user(
    user_req: web::Json<UserRequest>,
    db: web::Data<Database>,
) -> impl Responder {

    let username = match Username::new(&user_req.username) {
        Ok(username) => username,
        Err(err) => return HttpResponse::BadRequest().body(err),
    };

    let email = match Email::new(&user_req.email) {
        Ok(email) => email,
        Err(err) => return HttpResponse::BadRequest().body(err),
    };

    let password = match Password::new(&user_req.password) {
        Ok(password) => password,
        Err(err) => return HttpResponse::BadRequest().body(err),
    };

    let phone = match &user_req.phone {
        Some(phone) => {
            if !validate_phone_number(phone) {
                return HttpResponse::BadRequest().body("Invalid phone number");
            }
            Some(PhoneNumber::new(phone).unwrap())
        }
        None => None,
    };


    // Check if username or email already exist in the database
    let mut existing_user_filter = doc! {
        "$or": [
            {"username": &username.0},
            {"email": &email.0},
        ]
    };
    
    // If phone number is provided, include it in the filter
    if let Some(phone) = &phone {
        if let Ok(or_array) = existing_user_filter.get_array_mut("$or") {
            or_array.push(doc! {"phone": phone}.into());
        }
    }

    let existing_user = db
        .collection::<User>("users")
        .find_one(existing_user_filter, None)
        .await;

    match existing_user {
        Ok(Some(_)) => {
            // An existing user with the provided email, username, or phone already exists
            return HttpResponse::BadRequest().body("User with provided email, username, or phone already exists");
        }
        Err(_) => {
            // Error occurred while querying the database
            return HttpResponse::InternalServerError().finish();
        }
        _ => {
            // No existing user found, continue with user creation
        }
    };


    // Hash the user's password
    let hashed_password = match hash(&password.0, DEFAULT_COST) {
        Ok(hp) => hp,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let email_verification_token = generate_email_verification_token();
    let phone_verification_token = user_req.phone.as_ref().map(|_| generate_text_verification_token());

    let now = Utc::now().timestamp();

    let mut new_user = User {
        id: None,
        username: username.0.clone(),
        email: email.0.clone(),
        password: hashed_password,
        onboarding: false,
        phone: None, // Initialize as None
        email_verified: None,
        phone_verified: None,
        email_verification_token: Some(email_verification_token.clone()),
        phone_verification_token: phone_verification_token.clone(),
        tel: None,
        password_reset_token: None,
        mfa_enabled: Some(false),
        mfa_secret: None,
        mfa_recovery_codes: None,
        communication_preferences: CommunicationPreferences {
            receive_promotions_email: Some(user_req.receive_promotions.unwrap_or(false)),
            receive_promotions_sms: Some(user_req.receive_promotions.unwrap_or(false)),
        },
        created: now,
        updated: now,
        last_logged_in: None,    
    };

    if let Some(phone) = &phone {
        new_user.phone = Some(phone.0.clone());
    }


    // Insert the new user into the database
    match db
        .collection("users")
        .insert_one(new_user.clone(), None)
        .await
    {
        Ok(_insert_result) => {
            // let id = _insert_result.inserted_id.as_object_id().unwrap().to_hex();

            // Send verification email
            match send_verification_email(&email.0, &email_verification_token).await {
                Ok(_) => (),
                Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to send verification email: {}", err)),
            }

            // Send verification text if phone is provided
            if let Some(phone) = &phone {
                if let Some(phone_verification_token) = &phone_verification_token {
                    match send_verification_text(&phone.0, &phone_verification_token).await {
                        Ok(_) => (),
                        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to send verification text: {}", err)),
                    }
                } else {
                    return HttpResponse::InternalServerError().body("Phone verification token should exist");
                }
            }    
            // Create a response struct, excluding the password
            let user_response: UserResponse = new_user.into();
            HttpResponse::Ok().json(user_response)
        }
        Err(_) => HttpResponse::InternalServerError().finish(),
    }


    // HttpResponse::Ok().json(new_user) // Respond with the created user (excluding password)
}

/*
  LOGIN HANDLER
*/

#[derive(Deserialize)]
pub struct UserLogin {
    identifier: String,  // Can be either username or email
    password: String,
}


#[derive(Serialize)]
struct TokenResponse {
    token: String,
    user: UserResponse,
}

#[derive(Debug, Error)]
enum LoginError {
    #[error("Internal server error")]
    InternalServerError,
    #[error("Unauthorized")]
    Unauthorized,
}

impl From<mongodb::error::Error> for LoginError {
    fn from(_: mongodb::error::Error) -> Self {
        LoginError::InternalServerError
    }
}

impl From<bcrypt::BcryptError> for LoginError {
    fn from(_: bcrypt::BcryptError) -> Self {
        LoginError::InternalServerError
    }
}

impl From<jsonwebtoken::errors::Error> for LoginError {
    fn from(_: jsonwebtoken::errors::Error) -> Self {
        LoginError::InternalServerError
    }
}

pub async fn login_user(db: web::Data<Database>, form: web::Json<UserLogin>) -> HttpResponse {
    let collection = db.collection::<User>("users");

    // Try to find the user by username or email
    let filter = doc! {
        "$or": [
            { "username": &form.identifier },
            { "email": &form.identifier }
        ]
    };
    let user = match collection.find_one(filter, None).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            println!("User not found");
            return HttpResponse::Unauthorized().finish();
        }
        Err(err) => {
            println!("Error querying database: {:?}", err);
            return HttpResponse::InternalServerError().finish();
        }
    };

    if user.email_verified != Some(true) && user.phone_verified != Some(true) {
        return HttpResponse::Unauthorized().json(json!({"message": "Please verify your email or phone to access the services"}));
    }

    if let Ok(valid) = verify(&form.password, &user.password) {
        if valid {
            if user.mfa_enabled.unwrap_or(false) {
                // @dev: add some signal field to db that the user has authenticated password 
                //       and awaits mfa authentication, so a user cannot call the mfa_verified directly. 
                return HttpResponse::Ok().json(json!({"message": "MFA required", "mfa_required": true}));
            } else {
                match create_token(&user.username) {
                    Ok(token) => {
                        let timestamp = Utc::now().timestamp(); // Update last_logged_in field
                        // Update the user in the database
                        let filter = doc! { "_id": user.id.clone() };
                        let update = doc! { "$set": { "last_logged_in": timestamp } };
        
                        if let Err(_) = collection.update_one(filter, update, None).await {
                            return HttpResponse::InternalServerError().finish();
                        }
                        let user_response: UserResponse = user.into();
                        return HttpResponse::Ok().json(TokenResponse { token, user: user_response });
                    },
                    Err(_) => return HttpResponse::InternalServerError().finish(),
                }
            }
        }
    }

    HttpResponse::Unauthorized().finish()
}

/*
  FORGOT PASSWORD HANDLER
*/

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Error)]
enum ForgotPasswordError {
    #[error("Internal server error")]
    InternalServerError,
}

impl From<mongodb::error::Error> for ForgotPasswordError {
    fn from(_: mongodb::error::Error) -> Self {
        ForgotPasswordError::InternalServerError
    }
}

pub async fn forgot_password(db: web::Data<Database>, form: web::Json<ForgotPasswordRequest>) -> HttpResponse {
    let collection = db.collection::<User>("users");

    // Try to find the user by email
    let filter = doc! { "email": &form.email };
    let user = match collection.find_one(filter, None).await {
        Ok(Some(user)) => user,
        Ok(None) => return HttpResponse::Ok().json(json!({
            "message": "If your email is registered with us, you will receive a password reset link."
        })),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    
    // Create reset token
    let reset_token = match create_reset_token(&user.email, &db).await {
        Ok(token) => token,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    
    // Send reset email
    match send_reset_email(&user.email, &reset_token).await {
        Ok(_) => HttpResponse::Ok().json(json!({
            "message": "If your email is registered with us, you will receive a password reset link."
        })),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

/*
  RESET PASSWORD HANDLER
*/

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub email: String,
    pub new_password: String,
    pub reset_token: String,
}

#[derive(Debug, Error)]
enum ResetPasswordError {
    #[error("Internal server error")]
    InternalServerError,
    #[error("Invalid reset token")]
    InvalidResetToken,
}

impl From<mongodb::error::Error> for ResetPasswordError {
    fn from(_: mongodb::error::Error) -> Self {
        ResetPasswordError::InternalServerError
    }
}

async fn find_user_by_email(collection: &mongodb::Collection<User>, email: &str) -> Result<Option<User>, ResetPasswordError> {
    let filter = doc! { "email": email };
    collection.find_one(filter, None).await.map_err(|_| ResetPasswordError::InternalServerError)
}

async fn update_password(collection: &mongodb::Collection<User>, user_id: ObjectId, new_password: &str) -> Result<(), ResetPasswordError> {
    let filter = doc! { "_id": user_id };
    let hashed_password = hash(new_password, DEFAULT_COST).map_err(|_| ResetPasswordError::InternalServerError)?;
    let update = doc! { "$set": { "password": hashed_password } };
    collection.update_one(filter, update, None).await.map_err(|_| ResetPasswordError::InternalServerError)?;
    Ok(())
}

// Function to invalidate the password reset token
async fn invalidate_reset_token(collection: &mongodb::Collection<User>, user_id: ObjectId) -> Result<(), Box<dyn std::error::Error>> {
    let filter = doc! { "_id": user_id };
    let update = doc! { "$set": { "password_reset_token": Bson::Null } };
    collection.update_one(filter, update, None).await?;
    Ok(())
}

pub async fn reset_password(db: web::Data<Database>, form: web::Json<ResetPasswordRequest>) -> HttpResponse {
    let collection = db.collection::<User>("users");

    // Validate the reset token and extract the email
    let user = match find_user_by_email(&collection, &form.email).await {
        Ok(Some(user)) => user,
        Ok(None) => return HttpResponse::Ok().json(json!({"message": "Invalid reset token"})),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    match (user.password_reset_token, &form.reset_token) {
        (Some(user_token), form_token) if user_token == *form_token => {
            // Tokens match, proceed with password reset
            let user_id = match user.id.clone() {
                Some(id) => id,
                None => {
                    return HttpResponse::InternalServerError().finish();
                }
            };
            
            // Hash the new password and update the user's password in the database
            if let Err(_) = update_password(&collection, user_id , &form.new_password).await {
                return HttpResponse::InternalServerError().finish();
            }

            // @dev: TODO: Invalidate the token after usage.
            // Invalidate the token after usage
            if let Err(_) = invalidate_reset_token(&collection, user_id.clone()).await {
                return HttpResponse::InternalServerError().finish();
            }

            // @dev: TODO: Notify the user of the successful password reset
            // Notify the user of the successful password reset
            if let Err(_) = notify_password_reset(&user.email).await {
                return HttpResponse::InternalServerError().finish();
            }
        
            HttpResponse::Ok().json(json!({"message": "Password reset successfully"}))
        }
        _ => {
            // Tokens don't match or one of them is None
            return HttpResponse::Ok().json(json!({"message": "Invalid reset token"}));
        }
    }
}


/*
  USER VERIFICATION HANDLER
*/

#[derive(Deserialize)]
pub struct VerifyRequest {
    token: String,
}

/* EMAIL */
pub async fn verify_email(db: web::Data<Database>, token: web::Query<HashMap<String, String>>) -> HttpResponse {
    let token_value = match token.get("token") {
        Some(value) => value,
        None => return HttpResponse::BadRequest().json(json!({"message": "Token parameter is missing"})),
    };
    
    let collection = db.collection::<User>("users");

    let filter = doc! { "email_verification_token": token_value  };
    let update = doc! { "$set": { "email_verified": true }, "$unset": { "email_verification_token": "" } };
    let server_domain = env::var("SERVER_DOMAIN").expect("SERVER_DOMAIN environment variable not set");
    match collection.update_one(filter, update, None).await {
        // Ok(result) if result.matched_count > 0 => HttpResponse::Ok().json(json!({"message": "Email verified successfully"})),
        Ok(result) if result.matched_count > 0 => {
            // Redirect to a specific page after successful verification
            HttpResponse::Found()
                .append_header((header::LOCATION, format!("https://{}/verification-success", server_domain)))
                .finish()
        },
        _ => HttpResponse::BadRequest().json(json!({"message": "Invalid verification token"})),
    }
}


/* PHONE */
pub async fn verify_phone(db: web::Data<Database>, form: web::Json<VerifyRequest>) -> HttpResponse {
    let collection = db.collection::<User>("users");

    let filter = doc! { "phone_verification_token": &form.token };
    let update = doc! { "$set": { "phone_verified": true }, "$unset": { "phone_verification_token": "" } };
    let server_domain = env::var("SERVER_DOMAIN").expect("SERVER_DOMAIN environment variable not set");
    match collection.update_one(filter, update, None).await {
        // Ok(result) if result.matched_count > 0 => HttpResponse::Ok().json(json!({"message": "Phone verified successfully"})),
        Ok(result) if result.matched_count > 0 => {
            // Redirect to a specific page after successful verification
            HttpResponse::Found()
                .append_header((header::LOCATION, format!("https://{}/verification-success", server_domain)))
                .finish()
        },
        _ => HttpResponse::BadRequest().json(json!({"message": "Invalid verification token"})),
    }
}


/*
  MFA SETUP HANDLER
*/
//@dev alternative libs: https://github.com/constantoine/totp-rs

pub async fn setup_mfa(db: web::Data<Database>, user_id: web::Path<String>) -> HttpResponse {

    println!("user_id is: {}", user_id);
    // Fetch the user from the database
    let collection = db.collection::<User>("users");
    let object_id = match ObjectId::parse_str(user_id.as_ref()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(json!({"message": "Invalid user ID"})),
    };    
    let filter = doc! { "_id": object_id };
    
    let user = match collection.find_one(filter.clone(), None).await {
        Ok(Some(user)) => user,
        Ok(None) => return HttpResponse::NotFound().json(json!({"message": "User not found"})),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    // Check if MFA is already enabled for the user
    if let Some(true) = user.mfa_enabled {
        return HttpResponse::BadRequest().json(json!({"message": "MFA is already enabled for this user"}));
    }

    // Generate a new TOTP secret 
    let secret = generate_totp_secret();

    let totp = TOTP::new(secret.clone());
    // Use the user's email and ID as the label for the TOTP URI
    let uri = totp.to_uri(user.email, "MyApp".to_string());

    // Generate a QR code for the secret
    let code = match QrCode::new(&uri) {
        Ok(code) => code,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let image = code.render::<svg::Color>().build();
    let base64_image = general_purpose::STANDARD.encode(&image);
    
    // Generate recovery codes
    // @dev: check if we can securely send a pdf for download from user request!? 
    let recovery_codes = generate_recovery_codes();

    // Retrieve the key and iv from environment variables
    let encryption_key = match env::var("ENCRYPTION_KEY") {
        Ok(val) => match general_purpose::STANDARD.decode(&val) {
            Ok(decoded) => decoded,
            Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Invalid ENCRYPTION_KEY"})),
        },
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "ENCRYPTION_KEY not set"})),
    };

    let encryption_iv = match env::var("ENCRYPTION_IV") {
        Ok(val) => match general_purpose::STANDARD.decode(&val) {
            Ok(decoded) => decoded,
            Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Invalid ENCRYPTION_IV"})),
        },
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "ENCRYPTION_IV not set"})),
    };

    let encrypted_secret = encrypt(secret.as_bytes(), &encryption_key, &encryption_iv);
    let encrypted_recovery_codes: Vec<String> = recovery_codes.clone()
        .into_iter()
        .map(|code| general_purpose::STANDARD.encode(&encrypt(code.as_bytes(), &encryption_key, &encryption_iv)))
        .collect();

    // Save the encrypted secret and recovery codes in the user's profile
    let update = doc! { 
        "$set": { 
            "mfa_enabled": true,
            "mfa_secret": general_purpose::STANDARD.encode(&encrypted_secret),
            "mfa_recovery_codes": encrypted_recovery_codes
        } 
    };
    
    if let Err(_) = collection.update_one(filter, update, None).await {
        return HttpResponse::InternalServerError().finish();
    }

    // Respond with the QR code image and recovery codes
    let response = json!({
        "type": "totp",
        "object": "authentication_factor",
        "id": format!("auth_factor_{}", user_id),
        "totp": {
            "qr_code": format!("data:image/svg+xml;base64,{}", base64_image),
            "secret": secret,
            "uri": uri
        },
        "recovery_codes": recovery_codes,
    });

    HttpResponse::Ok().json(response)
}
/*
  MFA SETUP HANDLER
*/

#[derive(Deserialize)]
pub struct MfaVerificationRequest {
    totp_code: String,
}

pub async fn verify_mfa(db: web::Data<Database>, user_id: web::Path<String>, form: web::Json<MfaVerificationRequest>) -> HttpResponse {
    // Retrieve the user's MFA secret from the database
    let collection = db.collection::<User>("users");
    let object_id = match ObjectId::parse_str(user_id.as_ref()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(json!({"message": "Invalid user ID"})),
    };    
    let filter = doc! { "_id": object_id };

    let user = match collection.find_one(filter.clone(), None).await {
        Ok(Some(user)) => user,
        Ok(None) => return HttpResponse::NotFound().json(json!({"message": "User not found"})),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    // Check if MFA secret is available
    let encrypted_secret = match user.clone().mfa_secret {
        Some(secret) => secret,
        None => return HttpResponse::BadRequest().json(json!({"message": "MFA not set up for this user"})),
    };

    // Retrieve the key and iv from environment variables
    let encryption_key = match env::var("ENCRYPTION_KEY") {
        Ok(val) => match general_purpose::STANDARD.decode(&val) {
            Ok(decoded) => decoded,
            Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Invalid ENCRYPTION_KEY"})),
        },
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "ENCRYPTION_KEY not set"})),
    };

    let encryption_iv = match env::var("ENCRYPTION_IV") {
        Ok(val) => match general_purpose::STANDARD.decode(&val) {
            Ok(decoded) => decoded,
            Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Invalid ENCRYPTION_IV"})),
        },
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "ENCRYPTION_IV not set"})),
    };

    // Decrypt the secret
    let encrypted_secret_bytes = match general_purpose::STANDARD.decode(&encrypted_secret) {
        Ok(bytes) => bytes,
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Failed to decode encrypted secret"})),
    };
    let decrypted_secret_bytes = decrypt(&encrypted_secret_bytes, &encryption_key, &encryption_iv);
    let decrypted_secret = match String::from_utf8(decrypted_secret_bytes) {
        Ok(secret) => secret,
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Invalid UTF-8 sequence in decrypted secret"})),
    };


    // Use the otpauth crate to verify the TOTP
    let totp = TOTP::new(decrypted_secret);

    let code = match form.totp_code.parse::<u32>() {
        Ok(code) => code,
        Err(_) => return HttpResponse::BadRequest().json(json!({"message": "Invalid TOTP code"})),
    };
    let period = 30;
    let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "System time error"})),
    };


    let verified = totp.verify(code, period, timestamp);

    if verified {
        match create_token(&user.username) {
            Ok(token) => {
                let timestamp = Utc::now().timestamp(); // Update last_logged_in field
                // Update the user in the database
                // let filter = doc! { "_id": user.id.clone() };
                let update = doc! { "$set": { "last_logged_in": timestamp } };

                if let Err(_) = collection.update_one(filter, update, None).await {
                    return HttpResponse::InternalServerError().finish();
                }
                let user_response: UserResponse = user.into();
                return HttpResponse::Ok().json(TokenResponse { token, user: user_response });
            },
            Err(_) => return HttpResponse::InternalServerError().finish(),
        }
    } else {
        HttpResponse::Unauthorized().json(json!({"message": "MFA verification failed"}))
    }
}
