use actix_web::web;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            /* 2FA Endpoints */
            .route("/setup_mfa/{user_id}", web::post().to(handlers::auth::setup_mfa))
            .route("/recover_mfa/{user_id}", web::post().to(handlers::auth::recover_mfa))
            .route("/disable_mfa/{user_id}", web::post().to(handlers::auth::disable_mfa))
            .route("/verify_mfa/{user_id}", web::post().to(handlers::auth::verify_mfa)) // @notice Public Endpoint
            /* Oauth2 Endpoints (Public Endpoints) */
            .route("/google", web::get().to(handlers::auth::google_login))
            .route("/google/login", web::get().to(handlers::auth::google_login)) //@dev test these
            .route("/google/callback", web::get().to(handlers::auth::google_callback))
            .route("/facebook", web::get().to(handlers::auth::facebook_login))
            .route("/facebook/login", web::get().to(handlers::auth::facebook_login))
            .route("/facebook/callback", web::get().to(handlers::auth::facebook_callback))
            .route("/discord", web::get().to(handlers::auth::discord_login))
            .route("/discord/login", web::get().to(handlers::auth::discord_login))
            .route("/discord/callback", web::get().to(handlers::auth::discord_callback))
    );
}
