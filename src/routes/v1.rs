mod auth;
mod root;

use actix_web::web;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/v1")
            .configure(root::routes)
            .configure(auth::routes)
    );
}
