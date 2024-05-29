// @dev middlewares can be further studied bellow:
// https://ginkcode.com/post/implement-a-middleware-in-actix-web
// 
use actix_web::{
    body::EitherBody, dev::{
        forward_ready, Service, ServiceRequest, ServiceResponse, Transform
    }, http::header, Error, HttpResponse
};
use futures::{
    future::LocalBoxFuture, 
    FutureExt
};
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
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static, 
    B: 'static,
{
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

impl<S, B> Service<ServiceRequest> for JwtMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static, // Clone + Send + Sync + 
    S::Future: 'static, // + Send
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    // type Future = Pin<Box<dyn futures::Future<Output = Result<Self::Response, Self::Error>>>>;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    // fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    //     self.service.poll_ready(cx)
    // }
    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Get the path of the request
        let path = req.uri().path().to_owned();

        // List of public routes that don't require JWT verification
        let public_routes = vec!["/register", "/login", "/forgot_password", "/reset_password"];

        // Check if the requested path is in the list of public routes
        let is_public_route = public_routes.iter().any(|route| path.starts_with(route));

        // If it's a public route, proceed without JWT verification
        if is_public_route {
            let fut = self.service.call(req);
            return Box::pin(async move { fut.await.map(|res| res.map_into_right_body()) })
        }

        // Extract JWT token from request headers
        let auth_header = req.headers().get(header::AUTHORIZATION).cloned();

        if auth_header.is_none() {
            let http_res = HttpResponse::Unauthorized().finish();
            let (http_req, _) = req.into_parts();
            let res = ServiceResponse::new(http_req, http_res);
            return (async move { Ok(res.map_into_right_body()) }).boxed_local();
        }
        
        let service = Rc::clone(&self.service);
        let (http_req, payload) = req.into_parts();

        Box::pin(async move {
            if let Some(auth_header) = auth_header {
                if let Ok(auth_token) = auth_header.to_str() {
                    if let Some(token) = auth_token.strip_prefix("Bearer ") {
                        // Validate JWT token
                        let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
                        let validation = Validation::default();

                        match decode::<Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation) {
                            Ok(_) => {
                                // Token is valid, proceed with inner service
                                let req = ServiceRequest::from_parts(http_req, payload);
                                let res = service.call(req).await?.map_into_left_body();
                                return Ok(res);
                            }
                            Err(_) => {
                                let http_res = HttpResponse::Unauthorized().body("Unauthorized").map_into_right_body();
                                let res = ServiceResponse::new(http_req, http_res);
                                return Ok(res);
                            }
                        }
                    }
                }
            }
            let http_res = HttpResponse::Unauthorized().body("Unauthorized").map_into_right_body();
            let res = ServiceResponse::new(http_req, http_res);
            Ok(res)
        })

    }
}