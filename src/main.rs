mod db;
mod models;
mod handlers;
mod middlewares;
mod utils;

use actix_web::{web, App, HttpServer, middleware};
use dotenv::dotenv;
use env_logger;
use crate::db::init_database;
use crate::middlewares::jwt::JwtMiddleware; 

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok(); // Load .env file
    std::env::set_var("RUST_LOG", "debug");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();

    let db = init_database().await;
    
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(db.clone()))
            .wrap(JwtMiddleware)
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
            // Define more routes as needed
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
