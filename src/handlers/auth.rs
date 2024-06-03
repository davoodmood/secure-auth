use std::{collections::HashMap, env};
use actix_session::Session;
use actix_web::{http::header, web, HttpRequest, HttpResponse, Responder, ResponseError};
use chrono::{Duration, Utc};
use mongodb::{
    bson::{self, doc, oid::ObjectId, Bson}, Database
};
use oauth2::{AuthorizationCode, CsrfToken, StandardTokenResponse, TokenResponse as OAuth2TokenResponse};
use regex::Regex;
use bcrypt::{hash, DEFAULT_COST, verify};
use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use otpauth::TOTP;
use qrcode::{QrCode, render::svg};
use std::time::{SystemTime, UNIX_EPOCH};
use reqwest::Client as ReqwestClient; // Correct import for reqwest Client
use crate::{models::{communication::CommunicationPreferences, user::{LoginAttempt, User}}, services::auth::roles::ROLE_USER, utils::{crypto::{decrypt, encrypt}, email::send_otp, mfa::{generate_recovery_codes, generate_totp_secret}, oauth::{discord_client, facebook_client, google_client}, risk_assessment::{assess_login_risk, login_attempt_to_bson, RiskLevel}, verification::generate_otp}};
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

const MAX_FAILED_ATTEMPTS: u32 = 5;
const LOCKOUT_DURATION_MINUTES: i64 = 15;


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
    /// @notice: Password Policy Enforcement
    // Added checks for the presence of uppercase, lowercase, digits, and special characters, 
    // @returns  appropriate error messages if conditions are not met
    pub fn new(password: &str) -> Result<Self, String> {
        let min_length = 8;
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digits = password.chars().any(|c| c.is_digit(10));
        let has_special_chars = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:'\",.<>/?".contains(c));

        if password.len() < min_length {
            return Err(format!("Password must be at least {} characters long.", min_length));
        }
        
        if !has_uppercase {
            return Err("Password must contain at least one uppercase letter.".to_string());
        }
        
        if !has_lowercase {
            return Err("Password must contain at least one lowercase letter.".to_string());
        }
        
        if !has_digits {
            return Err("Password must contain at least one digit.".to_string());
        }
        
        if !has_special_chars {
            return Err("Password must contain at least one special character.".to_string());
        }

        Ok(Self(password.to_string()))
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
    mfa_enabled: Option<bool>,
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
            mfa_enabled: user.mfa_enabled,
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
        is_mfa_required: false,
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
        failed_login_attempts: 0,
        lockout_until: None,
        permissions: ROLE_USER,
        login_history: None,
        otp_code: None,
        otp_expires_at: None,
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

pub async fn login_user(db: web::Data<Database>, form: web::Json<UserLogin>, req: HttpRequest) -> HttpResponse {
    // Extract the IP address from the request
    let ip_address = req
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Extract the User-Agent header from the request
    let device_info = req
        .headers()
        .get("User-Agent")
        .and_then(|ua| ua.to_str().ok())
        .unwrap_or_else(|| "unknown")
        .to_string();

    // @dev TODO: Placeholder for geographic location
    let geographic_location = "unknown".to_string(); // use a service to get this
    
    let collection = db.collection::<User>("users");

    // Try to find the user by username or email
    let filter = doc! {
        "$or": [
            { "username": &form.identifier },
            { "email": &form.identifier }
        ]
    };
    let user = match collection.find_one(filter.clone(), None).await {
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

    // Check if account is locked
    if let Some(lockout_until) = user.lockout_until {
        if Utc::now().timestamp() < lockout_until {
            return HttpResponse::Forbidden().json(json!({"message": "Account is temporarily locked."}));
        }
    }

    // Assess the Request's Risk
    // Create a new login attempt
    let user_id = match user.id {
        Some(id) => id,
        None => {
            return HttpResponse::InternalServerError()
                .body("User ID is None")
                .into();
        }
    };
    
    let timestamp = Utc::now().timestamp(); // Update last_logged_in field
    let login_attempt = LoginAttempt {
        id: None,
        ip_address,
        timestamp,
        geographic_location,
        device_info,
        user_id: user_id.clone(),
    };

    let risk_level = assess_login_risk(&db, &user_id.to_hex(), &login_attempt).await;

    match risk_level {
        RiskLevel::High => {
            let otp = generate_otp();
            let otp_expires_at = Utc::now().timestamp() + 300; // OTP valid for 5 minutes
            let update = doc! { "$set": { "otp_code": &otp, "otp_expires_at": otp_expires_at }};
            let collection = db.collection::<User>("users");
            if let Err(_) = collection.update_one(doc! { "_id": user_id.clone() }, update, None).await {
                return HttpResponse::InternalServerError().json(json!({"message": "Failed to update user"}));
            }
            if let Err(e) = send_otp(&user.email, &otp).await {
                return HttpResponse::InternalServerError().json(json!({"message": format!("Failed to send OTP: {}", e)}));
            }        
            // Send OTP to user via email/SMS (implementation needed)
            return HttpResponse::BadRequest()
                .json(json!({"message": "Additional verification required. Check your email for the OTP"}));
        },
        RiskLevel::Medium => {
            // @dev TODO:
            // Trigger additional verification, like request frontend for Capcha check after access!
            // return HttpResponse::BadRequest()
            //     .body("Additional verification required, contact developer to handle this ;)")
            //     .into();
        },
        _ => {
            // Proceed with standard login process
        }
    }

    if let Ok(valid) = verify(&form.password, &user.password) {
        if valid {
            if user.mfa_enabled.unwrap_or(false) {
                // @dev: add some signal field to db that the user has authenticated password 
                //       and awaits mfa authentication, so a user cannot call the mfa_verified directly. 
                // Update user record to disable MFA
                let update = doc! {
                    "$set": {
                        "is_mfa_required": true,
                    }
                };

                match collection.update_one(filter, update, None).await {
                    Ok(_) => return HttpResponse::Ok().json(json!({"message": "Proceed to MFA stage", "mfa_required": true})),
                    Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Failed to initiate MFA process"})),
                }
            } else {
                match create_token(&user.username, user.permissions) {
                    Ok(token) => {                       
                        
                        // Convert LoginAttempt to BSON
                        // let login_attempt_bson: bson::Document = login_attempt_to_bson(&login_attempt);

                        // Insert login attempt into database
                        let result = db.collection::<LoginAttempt>("login_attempts").insert_one(login_attempt.clone(), None).await;
                        let login_attempt_id = match result {
                            Ok(result) => {
                                match result.inserted_id.as_object_id() {
                                    Some(object_id) => object_id.clone(),
                                    None => {
                                        // Return a server error with a message
                                        return HttpResponse::InternalServerError().body("Failed to save login attempt");
                                    }
                                }
                            },
                            Err(_) => {
                                // Handle the error case when insertion fails
                                return HttpResponse::InternalServerError().body("Failed to insert login attempt");
                            }
                        };

                        // Update user with login attempt id
                        let login_history_update = if let Some(mut login_history) = user.clone().login_history {
                            login_history.push(login_attempt_id);
                            Some(login_history)
                        } else {
                            Some(vec![login_attempt_id])
                        };

                        // Update the user in the database
                        let update = doc! { "$set": { 
                            "last_logged_in": timestamp,
                            "failed_login_attempts": 0,
                            "lockout_until": Bson::Null,
                            "login_history": login_history_update,
                        } };
        
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
    // Handle failed login attempt
    let failed_attempts = user.failed_login_attempts + 1;
    let lockout_until = if failed_attempts >= MAX_FAILED_ATTEMPTS {
        Some((Utc::now() + Duration::minutes(LOCKOUT_DURATION_MINUTES)).timestamp())
    } else {
        None
    };

    // Update user in database with new failed_attempts and lockout_until
    let update = doc! {
        "$set": {
            "failed_login_attempts": failed_attempts,
            "lockout_until": lockout_until,
        }
    };

    if let Err(err) = collection.update_one(filter.clone(), update, None).await {
        println!("Error updating user: {:?}", err);
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Unauthorized().json(json!({"message": "Invalid credentials."}))
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


pub async fn verify_otp(db: web::Data<Database>, user_id: String, provided_otp: String) -> HttpResponse {
    let collection = db.collection::<User>("users");
    let user_oid = match ObjectId::parse_str(&user_id) {
        Ok(oid) => oid,
        Err(_) => return HttpResponse::BadRequest().json(json!({"message": "Invalid user ID"})),
    };

    let filter = doc! { "_id": user_oid };
    let user = match collection.find_one(filter.clone(), None).await {
        Ok(Some(user)) => user,
        Ok(None) => return HttpResponse::Unauthorized().json(json!({"message": "User not found"})),
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Database error"})),
    };

    if let Some(stored_otp) = user.otp_code {
        if provided_otp == stored_otp && user.otp_expires_at.unwrap_or(0) > Utc::now().timestamp() {
            // OTP verified, proceed with granting access
            // Remove OTP code from user record
            let update = doc! { "$unset": { "otp_code": "", "otp_expires_at": "" }};
            collection.update_one(filter, update, None).await.unwrap(); // add error handling
            HttpResponse::Ok().json(json!({"message": "OTP verified successfully"}))
        } else {
            HttpResponse::Unauthorized().json(json!({"message": "Invalid or expired OTP"}))
        }
    } else {
        HttpResponse::Unauthorized().json(json!({"message": "OTP not found"}))
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

    let issuer_name = match std::env::var("MFA_ISSUER") {
        Ok(issuer) => issuer,
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Encryption key not set"})),
    };

    // Generate a new TOTP secret 
    let secret = generate_totp_secret();

    let totp = TOTP::new(secret.clone());
    // Use the user's email and ID as the label for the TOTP URI
    let uri = totp.to_uri(user.email, issuer_name);

    // Generate a QR code for the secret
    let qr_code = match QrCode::new(&uri) {
        Ok(qr_code) => qr_code,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let image = qr_code.render::<svg::Color>().build();
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

pub async fn verify_mfa(db: web::Data<Database>, user_id: web::Path<String>, form: web::Json<MfaVerificationRequest>, req: HttpRequest) -> HttpResponse {
    // Extract the IP address from the request
    let ip_address = req
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Extract the User-Agent header from the request
    let device_info = req
        .headers()
        .get("User-Agent")
        .and_then(|ua| ua.to_str().ok())
        .unwrap_or_else(|| "unknown")
        .to_string();

    // @dev TODO: Placeholder for geographic location
    let geographic_location = "unknown".to_string(); // use a service to get this
    
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

    // Check if MFA is enabled for the user & 
    if !user.mfa_enabled.unwrap_or(false)  {
        return HttpResponse::BadRequest().json(json!({"message": "MFA is not enabled for this user"}));
    }
    if !user.is_mfa_required  {
        return HttpResponse::BadRequest().json(json!({"message": "You must first login using your credentials."}));
    }

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
        match create_token(&user.username, user.permissions) {
            Ok(token) => {
                let timestamp = Utc::now().timestamp(); // Update last_logged_in field

                let user_id = match user.id {
                    Some(id) => id,
                    None => {
                        return HttpResponse::InternalServerError()
                            .body("User ID is None")
                            .into();
                    }
                };
                
                let login_attempt = LoginAttempt {
                    id: None,
                    ip_address,
                    timestamp,
                    geographic_location,
                    device_info,
                    user_id: user_id,
                };
                
                // Convert LoginAttempt to BSON
                // let login_attempt_bson: bson::Document = login_attempt_to_bson(&login_attempt);

                // Insert login attempt into database
                let result = db.collection::<LoginAttempt>("login_attempts").insert_one(login_attempt.clone(), None).await;
                let login_attempt_id = match result {
                    Ok(result) => {
                        match result.inserted_id.as_object_id() {
                            Some(object_id) => object_id.clone(),
                            None => {
                                // Return a server error with a message
                                return HttpResponse::InternalServerError().body("Failed to save login attempt");
                            }
                        }
                    },
                    Err(_) => {
                        // Handle the error case when insertion fails
                        return HttpResponse::InternalServerError().body("Failed to insert login attempt");
                    }
                };

                // Update user with login attempt id
                let login_history_update = if let Some(mut login_history) = user.clone().login_history {
                    login_history.push(login_attempt_id);
                    Some(login_history)
                } else {
                    Some(vec![login_attempt_id])
                };

                // Update the user in the database
                let update = doc! {
                    "$set": {
                        "is_mfa_required": false,
                        "last_logged_in": timestamp,
                        "failed_login_attempts": 0,
                        "lockout_until": Bson::Null,
                        "login_history": login_history_update,
                    }
                };

                if let Err(_) = collection.update_one(filter, update, None).await {
                    return HttpResponse::InternalServerError().finish();
                }
                let user_response: UserResponse = user.into();
                return HttpResponse::Ok().json(TokenResponse { token, user: user_response });
            },
            Err(_) => return HttpResponse::InternalServerError().finish(),
        }
    } else {
        // Handle failed login attempt
        let failed_attempts = user.failed_login_attempts + 1;
        let lockout_until = if failed_attempts >= MAX_FAILED_ATTEMPTS {
            Some((Utc::now() + Duration::minutes(LOCKOUT_DURATION_MINUTES)).timestamp())
        } else {
            None
        };

        // Update user in database with new failed_attempts and lockout_until
        let update = doc! {
            "$set": {
                "failed_login_attempts": failed_attempts,
                "lockout_until": lockout_until,
            }
        };

        if let Err(err) = collection.update_one(filter.clone(), update, None).await {
            println!("Error updating user: {:?}", err);
            return HttpResponse::InternalServerError().finish();
        }

        HttpResponse::Unauthorized().json(json!({"message": "MFA verification failed"}))
    }
}


/*
  MFA RECOVERY HANDLER
*/

#[derive(Deserialize)]
pub struct MfaRecoveryRequest {
    recovery_code: Vec<String>,
}

#[derive(Error, Debug)]
pub enum MfaError {
    #[error("Database error")]
    DatabaseError(#[from] mongodb::error::Error),

    #[error("Base64 decoding error")]
    DecodeError(#[from] base64::DecodeError),

    #[error("Decryption error")]
    DecryptionError,

    #[error("Invalid UTF-8 string")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Environment variable error")]
    EnvVarError(#[from] std::env::VarError),

    #[error("MFA not enabled")]
    MfaNotEnabled,

    #[error("Invalid recovery code")]
    InvalidRecoveryCode,
}

impl ResponseError for MfaError {
    fn error_response(&self) -> HttpResponse {
        match *self {
            MfaError::DatabaseError(ref _err) => HttpResponse::InternalServerError().json(json!({"message": "Database error"})),
            MfaError::DecodeError(ref _err) => HttpResponse::BadRequest().json(json!({"message": "Base64 decoding error"})),
            MfaError::DecryptionError => HttpResponse::InternalServerError().json(json!({"message": "Decryption error"})),
            MfaError::Utf8Error(ref _err) => HttpResponse::BadRequest().json(json!({"message": "Invalid UTF-8 string"})),
            MfaError::EnvVarError(ref _err) => HttpResponse::InternalServerError().json(json!({"message": "Environment variable error"})),
            MfaError::MfaNotEnabled => HttpResponse::Forbidden().json(json!({"message": "MFA not enabled"})),
            MfaError::InvalidRecoveryCode => HttpResponse::Unauthorized().json(json!({"message": "Invalid recovery code"})),
        }
    }
}



pub async fn recover_mfa(
    db: web::Data<Database>,
    user_id: web::Path<String>,
    form: web::Json<MfaRecoveryRequest>,
) -> HttpResponse {
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

    // Check if MFA is enabled for the user
    if !user.mfa_enabled.unwrap_or(false) {
        return HttpResponse::BadRequest().json(json!({"message": "MFA is not enabled for this user"}));
    }

    // Retrieve and decrypt the recovery codes
    let issuer_name = match std::env::var("MFA_ISSUER") {
        Ok(issuer) => issuer,
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Encryption key not set"})),
    };

    let decryption_key = match std::env::var("ENCRYPTION_KEY") {
        Ok(val) => match general_purpose::STANDARD.decode(&val) {
            Ok(decoded) => decoded,
            Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Invalid ENCRYPTION_KEY"})),
        },
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Encryption key not set"})),
    };

    let decryption_iv = match std::env::var("ENCRYPTION_IV") {
        Ok(val) => match general_purpose::STANDARD.decode(&val) {
            Ok(decoded) => decoded,
            Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Invalid ENCRYPTION_IV"})),
        },
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Encryption IV not set"})),
    };

    let encrypted_recovery_codes = match user.mfa_recovery_codes {
        Some(ref codes) => codes,
        None => return HttpResponse::BadRequest().json(json!({"message": "Recovery codes not found"})),
    };

    let decrypted_recovery_codes_result: Result<Vec<String>, MfaError> = encrypted_recovery_codes
        .iter()
        .map(|code| {
            let decoded = general_purpose::STANDARD.decode(code)?;
            let decrypted = decrypt(&decoded, &decryption_key, &decryption_iv);
            String::from_utf8(decrypted).map_err(MfaError::from)
        })
        .collect();

    let decrypted_recovery_codes = match decrypted_recovery_codes_result {
        Ok(codes) => codes,
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Decryption error"})),
    };

    // Verify the provided recovery code
    if form.recovery_code.len() != decrypted_recovery_codes.len() {
        return HttpResponse::Unauthorized().json(json!({"message": "Invalid recovery code"}));
    }

    for (user_code, decrypted_code) in form.recovery_code.iter().zip(decrypted_recovery_codes.iter()) {
        if user_code != decrypted_code {
            return HttpResponse::Unauthorized().json(json!({"message": "Invalid recovery code"}));
        }
    }

    // Check if MFA secret is available
    let encrypted_secret = match user.clone().mfa_secret {
        Some(secret) => secret,
        None => return HttpResponse::BadRequest().json(json!({"message": "MFA not set up for this user"})),
    };

    // Decrypt the secret
    let encrypted_secret_bytes = match general_purpose::STANDARD.decode(&encrypted_secret) {
        Ok(bytes) => bytes,
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Failed to decode encrypted secret"})),
    };
    let decrypted_secret_bytes = decrypt(&encrypted_secret_bytes, &decryption_key, &decryption_iv);
    let decrypted_secret = match String::from_utf8(decrypted_secret_bytes) {
        Ok(secret) => secret,
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Invalid UTF-8 sequence in decrypted secret"})),
    };

    // Use the otpauth crate to verify the TOTP
    let totp = TOTP::new(decrypted_secret.clone());
    
    // Use the user's email and ID as the label for the TOTP URI
    let uri = totp.to_uri(user.email, issuer_name);

    // Generate a QR code for the secret
    let qr_code = match QrCode::new(&uri) {
        Ok(qr_code) => qr_code,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let image = qr_code.render::<svg::Color>().build();
    let base64_image = general_purpose::STANDARD.encode(&image);

    // Respond with the QR code image and recovery codes
    let response = json!({
        "type": "totp",
        "object": "authentication_factor",
        "id": format!("auth_factor_{}", user_id),
        "totp": {
            "qr_code": format!("data:image/svg+xml;base64,{}", base64_image),
            "secret": decrypted_secret,
            "uri": uri
        }
    });

    HttpResponse::Ok().json(response)
}

/*
  MFA DISABLE HANDLER
*/

pub async fn disable_mfa(
    db: web::Data<Database>,
    user_id: web::Path<String>,
    form: web::Json<MfaVerificationRequest>
) -> HttpResponse {
    let collection = db.collection::<User>("users");
    let object_id = match ObjectId::parse_str(user_id.as_ref()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(json!({"message": "Invalid user ID"})),
    };    
    let filter = doc! { "_id": object_id };

    let user = match collection.find_one(filter.clone(), None).await {
        Ok(Some(user)) => user,
        Ok(None) => return HttpResponse::Unauthorized().json(json!({"message": "User not found"})),
        Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Database error"})),
    };

    // Check if MFA is enabled for the user
    if !user.mfa_enabled.unwrap_or(false) {
        return HttpResponse::Forbidden().json(json!({"message": "MFA not enabled"}));
    }

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
        // Update user record to disable MFA
        let update = doc! {
            "$set": {
                "mfa_enabled": false,
                "mfa_secret": bson::Bson::Null,
                "mfa_recovery_codes": bson::Bson::Null,
            }
        };

        match collection.update_one(filter, update, None).await {
            Ok(_) => HttpResponse::Ok().json(json!({"message": "MFA disabled successfully"})),
            Err(_) => HttpResponse::InternalServerError().json(json!({"message": "Failed to disable MFA on update"})),
        }
    } else {
        HttpResponse::Unauthorized().json(json!({"message": "MFA verification failed"}))
    }
}


/*
  OAUTH2 HANDLERS
*/

//@notice Google Oauth2 Authenticator 
// async fn google_login() -> impl Responder {
//     let client = oauth::google_client();
//     let (auth_url, _csrf_token) = client.authorize_url(CsrfToken::new_random).url();
    
//     HttpResponse::Found().header("Location", auth_url.to_string()).finish()
// }

// async fn google_callback(params: web::Query<oauth2::StandardTokenResponse>) -> impl Responder {
//     // Exchange the code for a token, then use the token to fetch user info
//     HttpResponse::Ok().body("Google callback")
// }

#[derive(Debug, Deserialize)]
pub struct OAuth2Params {
    pub code: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    email: String,
    name: String,
}

async fn fetch_google_user_info(token: &StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>) -> Result<GoogleUserInfo, Box<dyn std::error::Error>> {
    let client = ReqwestClient::new();
    let user_info_resp = client
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(token.access_token().secret())
        .send()
        .await?
        .json::<GoogleUserInfo>()
        .await?;

    Ok(user_info_resp)
}

// Google OAuth2 login endpoint
pub async fn google_login(session: Session) -> impl Responder {
    let client = match google_client() {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to create Google client: {}", err)),
    };

    let (auth_url, csrf_token) = client.authorize_url(CsrfToken::new_random).url();

    // Store the CSRF token in the session
    if let Err(err) = session.insert("csrf_token", csrf_token.secret().clone()) {
        return HttpResponse::InternalServerError().body(format!("Failed to store CSRF token: {}", err));
    }

    // Append the CSRF token as a query parameter in the authorization URL
    let auth_url_with_csrf = format!("{}&csrf_token={}", auth_url, csrf_token.secret());

    HttpResponse::Found().append_header(("Location", auth_url_with_csrf)).finish()
}

// Google OAuth2 callback endpoint
pub async fn google_callback(
    db: web::Data<Database>,
    session: Session,
    query: web::Query<OAuth2Params>,
    req: HttpRequest,
) -> impl Responder {
    // Extract the IP address from the request
    let ip_address = req
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Extract the User-Agent header from the request
    let device_info = req
        .headers()
        .get("User-Agent")
        .and_then(|ua| ua.to_str().ok())
        .unwrap_or_else(|| "unknown")
        .to_string();

    // @dev TODO: Placeholder for geographic location
    let geographic_location = "unknown".to_string(); // use a service to get this

    let client = match google_client() {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to create Google client: {}", err)),
    };

    // Retrieve the CSRF token from the session
    let csrf_token_in_session: Option<String> = match session.get("csrf_token") {
        Ok(Some(token)) => Some(token),
        Ok(None) => return HttpResponse::BadRequest().body("CSRF token not found in session."),
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to retrieve CSRF token: {}", err)),
    };

    //@dev test this section
    // Ensure CSRF token from the query parameter matches the one in the session
    let csrf_token_from_query = query.csrf_token.clone();
    if csrf_token_in_session != Some(csrf_token_from_query) {
        return HttpResponse::BadRequest().body("CSRF token mismatch.");
    }

    let token_result = client.exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(oauth2::reqwest::async_http_client)
        .await;

    let token = match token_result {
        Ok(token) => token,
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to exchange code for token: {}", err)),
    };

    let user_info_result = fetch_google_user_info(&token).await;
    let user_info = match user_info_result {
        Ok(info) => info,
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to fetch user info: {}", err)),
    };

    let collection = db.collection::<User>("users");
    let filter = doc! { "email": &user_info.email };
    let user_option = collection.find_one(filter.clone(), None).await;

    match user_option {
        Ok(Some(user)) => {
            // User already exists
            // HttpResponse::Ok().body(format!("Welcome back, {}!", user.username))
            if user.mfa_enabled.unwrap_or(false) {
                // @dev: add some signal field to db that the user has authenticated password 
                //       and awaits mfa authentication, so a user cannot call the mfa_verified directly. 
                // Update user record to disable MFA
                let update = doc! {
                    "$set": {
                        "is_mfa_required": true,
                    }
                };

                match collection.update_one(filter, update, None).await {
                    Ok(_) => return HttpResponse::Ok().json(json!({"message": "Proceed to MFA stage", "mfa_required": true})),
                    Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Failed to initiate MFA process"})),
                }
            } else {
                // Check if account is locked
                if let Some(lockout_until) = user.lockout_until {
                    if Utc::now().timestamp() < lockout_until {
                        return HttpResponse::Forbidden().json(json!({"message": "Account is temporarily locked."}));
                    }
                }
                match create_token(&user.username, user.permissions) {
                    Ok(token) => {
                        let timestamp = Utc::now().timestamp(); // Update last_logged_in field
                        
                        let user_id = match user.id {
                            Some(id) => id,
                            None => {
                                return HttpResponse::InternalServerError()
                                    .body("User ID is None")
                                    .into();
                            }
                        };
                        
                        let login_attempt = LoginAttempt {
                            id: None,
                            ip_address,
                            timestamp,
                            geographic_location,
                            device_info,
                            user_id: user_id,
                        };
                        
                        // Convert LoginAttempt to BSON
                        // let login_attempt_bson: bson::Document = login_attempt_to_bson(&login_attempt);
        
                        // Insert login attempt into database
                        let result = db.collection::<LoginAttempt>("login_attempts").insert_one(login_attempt.clone(), None).await;
                        let login_attempt_id = match result {
                            Ok(result) => {
                                match result.inserted_id.as_object_id() {
                                    Some(object_id) => object_id.clone(),
                                    None => {
                                        // Return a server error with a message
                                        return HttpResponse::InternalServerError().body("Failed to save login attempt");
                                    }
                                }
                            },
                            Err(_) => {
                                // Handle the error case when insertion fails
                                return HttpResponse::InternalServerError().body("Failed to insert login attempt");
                            }
                        };
        
                        // Update user with login attempt id
                        let login_history_update = if let Some(mut login_history) = user.clone().login_history {
                            login_history.push(login_attempt_id);
                            Some(login_history)
                        } else {
                            Some(vec![login_attempt_id])
                        };
        
                        // Update the user in the database
                        let update = doc! { "$set": { 
                            "last_logged_in": timestamp,
                            "failed_login_attempts": 0,
                            "lockout_until": Bson::Null,
                            "login_history": login_history_update,
                        } };
                        let filter = doc! { "_id": user.id.clone() };
        
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
        Ok(None) => {
            // User does not exist, create a new user
            let new_user = User {
                id: None,
                username: user_info.name,
                // prompt a step that if user's password was an empty string 
                // in the database or an Option with null value. user must then select a password at this stage of login
                password: "".to_string(), // No password needed for OAuth users 
                email: user_info.email.clone(),
                onboarding: true,
                phone: None,
                tel: None,
                email_verified: Some(true),
                phone_verified: None,
                email_verification_token: None,
                phone_verification_token: None,
                password_reset_token: None,
                is_mfa_required: false,
                mfa_enabled: None,
                mfa_secret: None,
                mfa_recovery_codes: None,
                communication_preferences: CommunicationPreferences { receive_promotions_email: Some(true), receive_promotions_sms: Some(false) },
                created: chrono::Utc::now().timestamp(),
                updated: chrono::Utc::now().timestamp(),
                last_logged_in: Some(chrono::Utc::now().timestamp()),
                failed_login_attempts: 0,
                lockout_until: None,
                permissions: ROLE_USER,
                login_history: None,
                otp_code: None,
                otp_expires_at: None,
            };
            let insert_result = collection.insert_one(new_user.clone(), None).await;

            match insert_result {
                Ok(_) => {
                    let user_response: UserResponse = new_user.into();
                    HttpResponse::Ok().json(user_response)
                    // HttpResponse::Ok().body(format!("Welcome, {}!", user_info.name))
                },
                Err(err) => HttpResponse::InternalServerError().body(format!("Failed to create user: {}", err)),
            }
        }
        Err(err) => HttpResponse::InternalServerError().body(format!("Database query failed: {}", err)),
    }
}



// FACEBOOK
pub async fn facebook_login(session: Session) -> impl Responder {
    let client = match facebook_client() {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to create Facebook client: {}", err)),
    };

    let (auth_url, csrf_token) = client.authorize_url(CsrfToken::new_random).url();

    // Store the CSRF token in the session
    if let Err(err) = session.insert("csrf_token", csrf_token.secret().clone()) {
        return HttpResponse::InternalServerError().body(format!("Failed to store CSRF token: {}", err));
    }

    // Append the CSRF token as a query parameter in the authorization URL
    let auth_url_with_csrf = format!("{}&csrf_token={}", auth_url, csrf_token.secret());

    HttpResponse::Found().append_header(("Location", auth_url_with_csrf)).finish()
}

#[derive(Debug, Deserialize)]
struct FacebookUserInfo {
    email: String,
    name: String,
}

async fn fetch_facebook_user_info(token: &StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>) -> Result<FacebookUserInfo, Box<dyn std::error::Error>> {
    let client = ReqwestClient::new();
    let user_info_resp = client
        .get("https://graph.facebook.com/me?fields=email,name")
        .bearer_auth(token.access_token().secret())
        .send()
        .await?
        .json::<FacebookUserInfo>()
        .await?;

    Ok(user_info_resp)
}

pub async fn facebook_callback(
    db: web::Data<Database>,
    session: Session,
    query: web::Query<OAuth2Params>,
    req: HttpRequest,
) -> impl Responder {
    // Extract the IP address from the request
    let ip_address = req
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Extract the User-Agent header from the request
    let device_info = req
        .headers()
        .get("User-Agent")
        .and_then(|ua| ua.to_str().ok())
        .unwrap_or_else(|| "unknown")
        .to_string();

    // @dev TODO: Placeholder for geographic location
    let geographic_location = "unknown".to_string(); // use a service to get this

    let client = match facebook_client() {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to create Facebook client: {}", err)),
    };

    // Retrieve the CSRF token from the session
    let csrf_token_in_session = match session.get("csrf_token") {
        Ok(Some(token)) => Some(token),
        Ok(None) => return HttpResponse::BadRequest().body("CSRF token not found in session."),
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to retrieve CSRF token: {}", err)),
    };

    //@dev test this section
    // Ensure CSRF token from the query parameter matches the one in the session
    let csrf_token_from_query = query.csrf_token.clone();
    if Some(csrf_token_from_query) != csrf_token_in_session {
        return HttpResponse::BadRequest().body("CSRF token mismatch.");
    }

    let token_result = client.exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(oauth2::reqwest::async_http_client)
        .await;

    let token = match token_result {
        Ok(token) => token,
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to exchange code for token: {}", err)),
    };

    let user_info_result = fetch_facebook_user_info(&token).await;
    let user_info = match user_info_result {
        Ok(info) => info,
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to fetch user info: {}", err)),
    };

    let collection = db.collection::<User>("users");
    let filter = doc! { "email": &user_info.email };
    let user_option = collection.find_one(filter.clone(), None).await;

    match user_option {
        Ok(Some(user)) => {
            // User already exists
            if user.mfa_enabled.unwrap_or(false) {
                // Update user record to disable MFA
                let update = doc! {
                    "$set": {
                        "is_mfa_required": true,
                    }
                };

                match collection.update_one(filter, update, None).await {
                    Ok(_) => return HttpResponse::Ok().json(json!({"message": "Proceed to MFA stage", "mfa_required": true})),
                    Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Failed to initiate MFA process"})),
                }
            } else {
                // Check if account is locked
                if let Some(lockout_until) = user.lockout_until {
                    if Utc::now().timestamp() < lockout_until {
                        return HttpResponse::Forbidden().json(json!({"message": "Account is temporarily locked."}));
                    }
                }
                match create_token(&user.username, user.permissions) {
                    Ok(token) => {
                        let timestamp = Utc::now().timestamp(); // Update last_logged_in field
                        let user_id = match user.id {
                            Some(id) => id,
                            None => {
                                return HttpResponse::InternalServerError()
                                    .body("User ID is None")
                                    .into();
                            }
                        };
                        
                        let login_attempt = LoginAttempt {
                            id: None,
                            ip_address,
                            timestamp,
                            geographic_location,
                            device_info,
                            user_id: user_id,
                        };
                        
                        // Convert LoginAttempt to BSON
                        // let login_attempt_bson: bson::Document = login_attempt_to_bson(&login_attempt);
        
                        // Insert login attempt into database
                        let result = db.collection::<LoginAttempt>("login_attempts").insert_one(login_attempt.clone(), None).await;
                        let login_attempt_id = match result {
                            Ok(result) => {
                                match result.inserted_id.as_object_id() {
                                    Some(object_id) => object_id.clone(),
                                    None => {
                                        // Return a server error with a message
                                        return HttpResponse::InternalServerError().body("Failed to save login attempt");
                                    }
                                }
                            },
                            Err(_) => {
                                // Handle the error case when insertion fails
                                return HttpResponse::InternalServerError().body("Failed to insert login attempt");
                            }
                        };
        
                        // Update user with login attempt id
                        let login_history_update = if let Some(mut login_history) = user.clone().login_history {
                            login_history.push(login_attempt_id);
                            Some(login_history)
                        } else {
                            Some(vec![login_attempt_id])
                        };
        
                        // Update the user in the database
                        let update = doc! { "$set": { 
                            "last_logged_in": timestamp,
                            "failed_login_attempts": 0,
                            "lockout_until": Bson::Null,
                            "login_history": login_history_update,
                        } };
                        let filter = doc! { "_id": user.id.clone() };
                        
        
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
        Ok(None) => {
            // User does not exist, create a new user
            let new_user = User {
                id: None,
                username: user_info.name,
                password: "".to_string(), // No password needed for OAuth users 
                email: user_info.email.clone(),
                onboarding: true,
                phone: None,
                tel: None,
                email_verified: Some(true),
                phone_verified: None,
                email_verification_token: None,
                phone_verification_token: None,
                password_reset_token: None,
                is_mfa_required: false,
                mfa_enabled: None,
                mfa_secret: None,
                mfa_recovery_codes: None,
                communication_preferences: CommunicationPreferences { receive_promotions_email: Some(true), receive_promotions_sms: Some(false) },
                created: chrono::Utc::now().timestamp(),
                updated: chrono::Utc::now().timestamp(),
                last_logged_in: Some(chrono::Utc::now().timestamp()),
                failed_login_attempts: 0,
                lockout_until: None,
                permissions: ROLE_USER,
                login_history: None,
                otp_code: None,
                otp_expires_at: None,
            };
            let insert_result = collection.insert_one(new_user.clone(), None).await;

            match insert_result {
                Ok(_) => {
                    let user_response: UserResponse = new_user.into();
                    HttpResponse::Ok().json(user_response)
                },
                Err(err) => HttpResponse::InternalServerError().body(format!("Failed to create user: {}", err)),
            }
        }
        Err(err) => HttpResponse::InternalServerError().body(format!("Database query failed: {}", err)),
    }
}


// DISCORD
pub async fn discord_login(session: Session) -> impl Responder {
    let client = match discord_client() {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to create Discord client: {}", err)),
    };

    let (auth_url, csrf_token) = client.authorize_url(CsrfToken::new_random).url();

    // Store the CSRF token in the session
    if let Err(err) = session.insert("csrf_token", csrf_token.secret().clone()) {
        return HttpResponse::InternalServerError().body(format!("Failed to store CSRF token: {}", err));
    }

    // Append the CSRF token as a query parameter in the authorization URL
    let auth_url_with_csrf = format!("{}&csrf_token={}", auth_url, csrf_token.secret());

    HttpResponse::Found().append_header(("Location", auth_url_with_csrf)).finish()
}


#[derive(Debug, Deserialize)]
struct DiscordUserInfo {
    email: String,
    username: String,
}

async fn fetch_discord_user_info(token: &StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>) -> Result<DiscordUserInfo, Box<dyn std::error::Error>> {
    let client = ReqwestClient::new();
    let user_info_resp = client
        .get("https://discord.com/api/users/@me")
        .bearer_auth(token.access_token().secret())
        .send()
        .await?
        .json::<DiscordUserInfo>()
        .await?;

    Ok(user_info_resp)
}

pub async fn discord_callback(
    db: web::Data<Database>,
    session: Session,
    query: web::Query<OAuth2Params>,
    req: HttpRequest,
) -> impl Responder {
    // Extract the IP address from the request
    let ip_address = req
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Extract the User-Agent header from the request
    let device_info = req
        .headers()
        .get("User-Agent")
        .and_then(|ua| ua.to_str().ok())
        .unwrap_or_else(|| "unknown")
        .to_string();

    // @dev TODO: Placeholder for geographic location
    let geographic_location = "unknown".to_string(); // use a service to get this
    
    let client = match discord_client() {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to create Discord client: {}", err)),
    };

    // Retrieve the CSRF token from the session
    let csrf_token_in_session: Option<String> = match session.get("csrf_token") {
        Ok(Some(token)) => Some(token),
        Ok(None) => return HttpResponse::BadRequest().body("CSRF token not found in session."),
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to retrieve CSRF token: {}", err)),
    };

    //@dev test this section
    // Ensure CSRF token from the query parameter matches the one in the session
    let csrf_token_from_query = query.csrf_token.clone();
    if csrf_token_in_session != Some(csrf_token_from_query) {
        return HttpResponse::BadRequest().body("CSRF token mismatch.");
    }

    let token_result = client.exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(oauth2::reqwest::async_http_client)
        .await;

    let token = match token_result {
        Ok(token) => token,
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to exchange code for token: {}", err)),
    };

    let user_info_result = fetch_discord_user_info(&token).await;
    let user_info = match user_info_result {
        Ok(info) => info,
        Err(err) => return HttpResponse::InternalServerError().body(format!("Failed to fetch user info: {}", err)),
    };

    let collection = db.collection::<User>("users");
    let filter = doc! { "email": &user_info.email };
    let user_option = collection.find_one(filter.clone(), None).await;

    match user_option {
        Ok(Some(user)) => {
            // User already exists
            if user.mfa_enabled.unwrap_or(false) {
                // Update user record to disable MFA
                let update = doc! {
                    "$set": {
                        "is_mfa_required": true,
                    }
                };

                match collection.update_one(filter, update, None).await {
                    Ok(_) => return HttpResponse::Ok().json(json!({"message": "Proceed to MFA stage", "mfa_required": true})),
                    Err(_) => return HttpResponse::InternalServerError().json(json!({"message": "Failed to initiate MFA process"})),
                }
            } else {
                // Check if account is locked
                if let Some(lockout_until) = user.lockout_until {
                    if Utc::now().timestamp() < lockout_until {
                        return HttpResponse::Forbidden().json(json!({"message": "Account is temporarily locked."}));
                    }
                }
                match create_token(&user.username, user.permissions) {
                    Ok(token) => {
                        let timestamp = Utc::now().timestamp(); // Update last_logged_in field
                        
                        let user_id = match user.id {
                            Some(id) => id,
                            None => {
                                return HttpResponse::InternalServerError()
                                    .body("User ID is None")
                                    .into();
                            }
                        };
                        
                        let login_attempt = LoginAttempt {
                            id: None,
                            ip_address,
                            timestamp,
                            geographic_location,
                            device_info,
                            user_id: user_id,
                        };
                        
                        // Convert LoginAttempt to BSON
                        // let login_attempt_bson: bson::Document = login_attempt_to_bson(&login_attempt);

                        // Insert login attempt into database
                        let result = db.collection::<LoginAttempt>("login_attempts").insert_one(login_attempt.clone(), None).await;
                        let login_attempt_id = match result {
                            Ok(result) => {
                                match result.inserted_id.as_object_id() {
                                    Some(object_id) => object_id.clone(),
                                    None => {
                                        // Return a server error with a message
                                        return HttpResponse::InternalServerError().body("Failed to save login attempt");
                                    }
                                }
                            },
                            Err(_) => {
                                // Handle the error case when insertion fails
                                return HttpResponse::InternalServerError().body("Failed to insert login attempt");
                            }
                        };

                        // Update user with login attempt id
                        let login_history_update = if let Some(mut login_history) = user.clone().login_history {
                            login_history.push(login_attempt_id);
                            Some(login_history)
                        } else {
                            Some(vec![login_attempt_id])
                        };

                        // Update the user in the database
                        let update = doc! { "$set": { 
                            "last_logged_in": timestamp,
                            "failed_login_attempts": 0,
                            "lockout_until": Bson::Null,
                            "login_history": login_history_update,
                        } };
                        
                        let filter = doc! { "_id": user.id.clone() };
        
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
        Ok(None) => {
            // User does not exist, create a new user
            let new_user = User {
                id: None,
                username: user_info.username,
                password: "".to_string(), // No password needed for OAuth users 
                email: user_info.email.clone(),
                onboarding: true,
                phone: None,
                tel: None,
                email_verified: Some(true),
                phone_verified: None,
                email_verification_token: None,
                phone_verification_token: None,
                password_reset_token: None,
                is_mfa_required: false,
                mfa_enabled: None,
                mfa_secret: None,
                mfa_recovery_codes: None,
                communication_preferences: CommunicationPreferences { receive_promotions_email: Some(true), receive_promotions_sms: Some(false) },
                created: chrono::Utc::now().timestamp(),
                updated: chrono::Utc::now().timestamp(),
                last_logged_in: Some(chrono::Utc::now().timestamp()),
                failed_login_attempts: 0,
                lockout_until: None,
                permissions: ROLE_USER,
                login_history: None,
                otp_code: None,
                otp_expires_at: None,
            };
            let insert_result = collection.insert_one(new_user.clone(), None).await;

            match insert_result {
                Ok(_) => {
                    let user_response: UserResponse = new_user.into();
                    HttpResponse::Ok().json(user_response)
                },
                Err(err) => HttpResponse::InternalServerError().body(format!("Failed to create user: {}", err)),
            }
        }
        Err(err) => HttpResponse::InternalServerError().body(format!("Database query failed: {}", err)),
    }
}



