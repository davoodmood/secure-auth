use actix_web::web;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/")
            /* Public User Endpoints */
            .route("/register", web::post().to(handlers::auth::register_user))
            .route("/login", web::post().to(handlers::auth::login_user))
            .route("/forgot_password", web::post().to(handlers::auth::forgot_password))
            .route("/reset_password", web::post().to(handlers::auth::reset_password))
            .route("/verify_email", web::get().to(handlers::auth::verify_email))
            .route("/verify_phone", web::post().to(handlers::auth::verify_phone))
            // Other root-level routes
    );
}
