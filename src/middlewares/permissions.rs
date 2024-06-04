// use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage, Result, HttpResponse};
use actix_web::{
    body::EitherBody, dev::{
        forward_ready, Service, ServiceRequest, ServiceResponse, Transform
    }, Error, HttpRequest, HttpResponse
};
use futures::future::{ok, LocalBoxFuture, Ready};
use std::collections::HashMap;
use std::rc::Rc;
use crate::utils::jwt::decode_token;

#[derive(Clone)]
pub struct PermissionMiddleware {
    route_permissions: HashMap<String, i32>,
}

impl PermissionMiddleware {
    pub fn new(route_permissions: HashMap<String, i32>) -> Self {
        PermissionMiddleware { route_permissions }
    }

    async fn check_permissions(&self, req: &HttpRequest) -> Result<bool, Error> {
        let user_permissions = self.extract_permissions(req)?;

        if let Some(required_permission) = self.route_permissions.get(req.path()) {
            Ok((user_permissions & required_permission) == *required_permission)
        } else {
            Ok(true) // If no permissions are specified for the route, allow access by default
        }
    }

    fn extract_permissions(&self, req: &HttpRequest) -> Result<i32, Error> {
        if let Some(header) = req.headers().get("Authorization") {
            let token_str = header.to_str().map_err(|_| actix_web::error::ErrorUnauthorized("Invalid token format"))?;
            let token = token_str.split_whitespace().nth(1).ok_or_else(|| actix_web::error::ErrorUnauthorized("No token provided"))?;
            let claims = decode_token(&token).map_err(|_| actix_web::error::ErrorUnauthorized("Invalid token"))?;

            Ok(claims.permissions)
        } else {
            Err(actix_web::error::ErrorUnauthorized("No token provided"))
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for PermissionMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = PermissionMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(PermissionMiddlewareService {
            service: Rc::new(service),
            route_permissions: self.route_permissions.clone(),
        })
    }
}

pub struct PermissionMiddlewareService<S> {
    service: Rc<S>,
    route_permissions: HashMap<String, i32>,
}

impl<S, B> Service<ServiceRequest> for PermissionMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let (http_req, payload) = req.into_parts();
        let service = Rc::clone(&self.service);

        let permissions_middleware = PermissionMiddleware::new(self.route_permissions.clone());
        
        Box::pin(async move {
            match permissions_middleware.check_permissions(&http_req.clone()).await {
                Ok(true) => {
                    let req = ServiceRequest::from_parts(http_req, payload);
                    service.call(req).await.map(ServiceResponse::map_into_left_body)
                }
                Ok(false) => {
                    let http_res = HttpResponse::Forbidden().body("Permission denied").map_into_right_body();
                    let res = ServiceResponse::new(http_req, http_res);
                    return Ok(res);
                }
                Err(_) => {
                    let http_res = HttpResponse::Unauthorized().body("Unauthorized Access").map_into_right_body();
                    let res = ServiceResponse::new(http_req, http_res);
                    return Ok(res);
                }
            }
        })
    }
}
