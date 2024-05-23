use actix_web::{dev::{Service, ServiceRequest, ServiceResponse, Transform}, Error, HttpResponse};
use futures::future::{ok, Ready};
use std::task::{Context, Poll};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use actix_web::web::Data;
use std::env;

pub struct JwtMiddleware;

impl<S, B> Transform<S> for JwtMiddleware
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = JwtMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtMiddlewareService { service })
    }
}

pub struct JwtMiddlewareService<S> {
    service: S,
}

impl<S, B> Service for JwtMiddlewareService<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        if let Some(auth_header) = req.headers().get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("bearer") || auth_str.starts_with("Bearer") {
                    let token = auth_str[7..].trim();
                    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
                    let validation = Validation { leeway: 0, validate_exp: true, ..Validation::default() };
                    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation);

                    return match token_data {
                        Ok(_) => self.service.call(req),
                        Err(_) => ok(req.into_response(HttpResponse::Unauthorized().finish().into_body())),
                    };
                }
            }
        }

        ok(req.into_response(HttpResponse::Unauthorized().finish().into_body()))
    }
}
