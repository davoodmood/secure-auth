// @dev middlewares can be further studied bellow:
// https://ginkcode.com/post/implement-a-middleware-in-actix-web
// 
use actix_web::{
    body::EitherBody, dev::{
        forward_ready, Service, ServiceRequest, ServiceResponse, Transform
    }, http::header, web, Error, HttpResponse
};
use futures::{
    future::LocalBoxFuture, 
    FutureExt
};
// use futures_util::{future::LocalBoxFuture, FutureExt};
use std::{
    future::{ready, Ready},
    rc::Rc,
};
use jsonwebtoken::{
    decode, 
    DecodingKey, 
    Validation, 
    // Algorithm
};
use std::env;

use crate::utils::jwt::Claims;

#[derive(Clone)] 
pub struct JwtMiddleware;

impl<S, B> Transform<S, ServiceRequest> for JwtMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static, // Clone + Send + Sync + 
    S::Future: 'static, // + Send
    B: 'static,
{
    // type Response = ServiceResponse<B>;
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = JwtMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtMiddlewareService { 
            service: Rc::new(service),
        }))
    }
}


pub struct JwtMiddlewareService<S> {
    service: Rc<S>,
}

// impl JwtMiddlewareService {
//     pub fn new() -> Self {
//         JwtMiddlewareService
//     }
// }


impl<S, B> Service<ServiceRequest> for JwtMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static, // Clone + Send + Sync + 
    S::Future: 'static, // + Send
    B: 'static,
{
    // type Response = ServiceResponse<B>;
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    // type Future = Pin<Box<dyn futures::Future<Output = Result<Self::Response, Self::Error>>>>;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    // fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    //     self.service.poll_ready(cx)
    // }
    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Extract JWT token from request headers
        let auth_header: Option<&header::HeaderValue> = req.headers().get(header::AUTHORIZATION);

        if auth_header.is_none() {
            let http_res = HttpResponse::Unauthorized().finish();
            let (http_req, _) = req.into_parts();
            let res = ServiceResponse::new(http_req, http_res);
            // Map to R type
            return (async move { Ok(res.map_into_right_body()) }).boxed_local();
        }

        let service = Rc::clone(&self.service);

        Box::pin(async move {
            if let Some(auth_header) = auth_header {
                if let Ok(auth_token) = auth_header.to_str() {
                    if let Some(token) = auth_token.strip_prefix("Bearer ") {
                        // Validate JWT token
                        let secret = web::Data::new(env::var("JWT_SECRET").expect("JWT_SECRET must be set"));
                        let validation = Validation::default();

                        match decode::<Claims>(token, &DecodingKey::from_secret(secret.get_ref().as_ref()), &validation) {
                            Ok(_) => {
                                // Token is valid, proceed with inner service
                                let res = service.call(req).await?.map_into_left_body();
                                return Ok(res);
                            }
                            Err(_) => {
                                let res = HttpResponse::Unauthorized().body("Unauthorized").map_into_right_body();
                                let (http_req, _) = req.into_parts();
                                let res = ServiceResponse::new(http_req, res);
                                return Ok(res);
                            }
                        }
                    }
                }
            }
            let res = HttpResponse::Unauthorized().body("Unauthorized").map_into_right_body();
            let (http_req, _) = req.into_parts();
            let res = ServiceResponse::new(http_req, res);
            return Ok(res);
        })
    }
}