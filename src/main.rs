mod db;
mod models;
mod handlers;
mod middlewares;
mod utils;
mod services;

use actix_web::{web, App, HttpServer, middleware, cookie::Key};
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use dotenv::dotenv;
use env_logger;
use crate::db::init_database;
use crate::middlewares::{
    jwt::JwtMiddleware, 
    rate_limiter::RateLimiter,
    permissions::PermissionMiddleware,
}; 
use utils::permissions::get_route_permissions;
use services::localization::Localization;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok(); // Load .env file
    std::env::set_var("RUST_LOG", "debug");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();
    let session_key = Key::generate();

    let db = init_database().await;
    let rate_limiter = RateLimiter::new();
    let route_permissions = get_route_permissions();

    let localization = Localization::new();

    let user_lang = "fa-IR"; // For example, this can be dynamically set based on user preference

    let invalid_credentials_message = localization.get_message(user_lang, "invalid-credentials");
    let account_locked_message = localization.get_message(user_lang, "account-locked");

    println!("{}", invalid_credentials_message);
    println!("{}", account_locked_message);


    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(db.clone()))
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                session_key.clone(),
            ))
            .wrap(rate_limiter.clone())
            .wrap(JwtMiddleware)
            .wrap(PermissionMiddleware::new(route_permissions.clone()))
            .route("/register", web::post().to(handlers::auth::register_user))
            .route("/login", web::post().to(handlers::auth::login_user))
            .route("/forgot_password", web::post().to(handlers::auth::forgot_password))
            .route("/reset_password", web::post().to(handlers::auth::reset_password))
            .route("/verify_email", web::get().to(handlers::auth::verify_email))
            .route("/verify_phone", web::post().to(handlers::auth::verify_phone))
            .route("/setup_mfa/{user_id}", web::post().to(handlers::auth::setup_mfa))
            .route("/verify_mfa/{user_id}", web::post().to(handlers::auth::verify_mfa))
            .route("/recover_mfa/{user_id}", web::post().to(handlers::auth::recover_mfa))
            .route("/disable_mfa/{user_id}", web::post().to(handlers::auth::disable_mfa))
            .route("/auth/google/login", web::get().to(handlers::auth::google_login)) //@dev test these
            .route("/auth/google/callback", web::get().to(handlers::auth::google_callback))
            .route("/auth/facebook/login", web::get().to(handlers::auth::facebook_login))
            .route("/auth/facebook/callback", web::get().to(handlers::auth::facebook_callback))
            .route("/auth/discord/login", web::get().to(handlers::auth::discord_login))
            .route("/auth/discord/callback", web::get().to(handlers::auth::discord_callback))
            // Define more routes as needed
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
