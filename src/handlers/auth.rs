use actix_web::{web, HttpResponse, Responder};
use mongodb::{
    bson::{doc, oid::ObjectId, Bson}, Database
};
use regex::Regex;
use bcrypt::{hash, DEFAULT_COST, verify};
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use otpauth::TOTP;
use qrcode::{QrCode, render::svg};

use crate::models::user::User;
use crate::utils::{jwt::{Claims, create_token, create_reset_token}, email::send_reset_email};

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
}

#[derive(Serialize)]
struct UserResponse {
    id: String,
    username: String,
    email: String,
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

    // Create the user document to insert into MongoDB
    let mut new_user_doc = doc! {
        "username": username.0.clone(),
        "email": email.0.clone(),
        "password": hashed_password,
    };

    if let Some(phone) = phone {
        new_user_doc.insert("phone", phone.0);
    }

    // Insert the new user into the database
    match db
        .collection("users")
        .insert_one(new_user_doc.clone(), None)
        .await
    {
        Ok(insert_result) => {
            let id = insert_result.inserted_id.as_object_id().unwrap().to_hex();

            // Create a response struct, excluding the password
            let user_response = UserResponse {
                id,
                username: username.0,
                email: email.0,
            };

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

    if let Ok(valid) = verify(&form.password, &user.password) {
        if valid {
            match create_token(&user.username) {
                Ok(token) => return HttpResponse::Ok().json(TokenResponse { token }),
                Err(_) => return HttpResponse::InternalServerError().finish(),
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
            // @dev: TODO: Notify the user of the successful password reset
        
            HttpResponse::Ok().json(json!({"message": "Password reset successfully"}))
        }
        _ => {
            // Tokens don't match or one of them is None
            return HttpResponse::Ok().json(json!({"message": "Invalid reset token"}));
        }
    }
}


/*
  MFA SETUP HANDLER
*/

// pub async fn setup_mfa(db: web::Data<Database>, user_id: web::Path<String>) -> HttpResponse {
//     // Generate a new TOTP secret
//     let totp = TOTP::new("base32secret3232");
//     let secret = totp.secret();

//     // Generate a QR code for the secret
//     let uri = totp.uri("user@example.com", "MyApp");
//     let code = QrCode::new(uri).unwrap();
//     let image = code.render::<svg::Color>().build();

//     // Save the secret in the user's profile (after confirmation)
//     // Respond with the QR code image
//     HttpResponse::Ok().content_type("image/svg+xml").body(image)
// }

/*
  MFA SETUP HANDLER
*/

// pub async fn verify_mfa(db: web::Data<Database>, user_id: web::Path<String>, form: web::Json<MfaVerificationRequest>) -> HttpResponse {
//     // Retrieve the user's MFA secret from the database
//     // Use the otpauth crate to verify the TOTP
//     let totp = TOTP::from_base32(&user.mfa_secret.unwrap()).unwrap();
//     let verified = totp.verify(form.totp_code, 30, 0);

//     if verified {
//         // Proceed with login
//         HttpResponse::Ok().json({"message": "MFA verification successful"})
//     } else {
//         HttpResponse::Unauthorized().json({"message": "MFA verification failed"})
//     }
// }