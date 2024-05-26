use actix_web::{web, HttpResponse};
use mongodb::{
    Database,
    bson::{doc, Bson},
};
use bcrypt::{hash, DEFAULT_COST, verify};
use jsonwebtoken::{encode, Header, EncodingKey};
use serde_json::json;


use crate::models::user::User;
use crate::utils::{jwt::{Claims, create_token, create_reset_token}, email::send_reset_email};

pub async fn register_user(db: web::Data<Database>, form: web::Json<User>) -> HttpResponse {
    let hashed_password = hash(form.password.clone(), DEFAULT_COST).unwrap();
    let new_user = User {
        id: None,
        username: form.username.clone(),
        password: hashed_password,
        email: form.email.clone(),
        // Initialize other fields as needed
    };

    // MongoDB insertion logic here

    HttpResponse::Ok().json(new_user) // Respond with the created user (excluding password)
}

pub async fn login_user(db: web::Data<Database>, form: web::Json<User>) -> HttpResponse {
    let collection = db.collection::<User>("users");
    let user = collection.find_one(doc! { "username": &form.username }, None).await.unwrap();

    match user {
        Some(user) => {
            if verify(&form.password, &user.password).unwrap() {
                let token = create_token(&user.username).unwrap();
                HttpResponse::Ok().json(token)
            } else {
                HttpResponse::Unauthorized().finish()
            }
        },
        None => HttpResponse::Unauthorized().finish(),
    }
}

pub async fn forgot_password<ForgotPasswordRequest>(db: web::Data<Database>, form: web::Json<ForgotPasswordRequest>) -> HttpResponse {
    // let email = form.into_inner();
    let collection = db.collection::<User>("users");
    let user = collection.find_one(doc! { "email": "some-email" }, None).await.unwrap();

    if let Some(user) = user {
        let reset_token: String = create_reset_token(&user.email).unwrap();
        send_reset_email(&user.email, &reset_token).unwrap();  // Handle errors appropriately in production

        HttpResponse::Ok().json(json!({
            "message": "If your email is registered with us, you will receive a password reset link."
        }))
    } else {
        HttpResponse::Ok().json(json!({
            "message": "If your email is registered with us, you will receive a password reset link."
        }))  // Avoid confirming or denying the existence of an account
    }
}

pub async fn reset_password<ResetPasswordRequest>(db: web::Data<Database>, form: web::Json<ResetPasswordRequest>) -> HttpResponse {
    // Validate the reset token and extract the email
    // Find the user by email in the database
    // Hash the new password and update the user's password in the database
    // Respond with a success message
    HttpResponse::Ok().into()
}

