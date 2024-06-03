use actix_web::{
    body::EitherBody, dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform}, error::ErrorInternalServerError, http::StatusCode, Error, HttpResponse
};
use std::future::{ready, Ready};
use futures::future::LocalBoxFuture;
use std::{collections::HashMap, sync::Arc};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};


#[derive(Clone)]
pub struct RateLimiter {
    visitors: Arc<Mutex<HashMap<String, u64>>>, // IP address and last request timestamp
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            visitors: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimiterMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimiterMiddleware {
            service: Arc::new(service),
            visitors: self.visitors.clone(),
        }))
    }
}

pub struct RateLimiterMiddleware<S> {
    service: Arc<S>,
    visitors: Arc<Mutex<HashMap<String, u64>>>,
}

impl<S, B> Service<ServiceRequest> for RateLimiterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{

    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Get the path of the request
        let path = req.uri().path().to_owned();

        // List of public routes that require rate limiting
        let protected_routes = vec![
            "/forgot_password", 
            "/reset_password",
            "/verify_mfa",
            "/recover_mfa",
        ];

        // Check if the requested path is in the list of protected routes
        let is_protected_route = protected_routes.iter().any(|route| path.starts_with(route));

        if !is_protected_route {
            let fut = self.service.call(req);
            return Box::pin(async move {
                match fut.await {
                    Ok(res) => {
                        let res = res.map_into_left_body();
                        Ok(res)
                    }
                    Err(err) => Err(err),
                }
            })
        }

        let ip = req
        .connection_info()
        .realip_remote_addr()
        .map(|ip| ip.to_string())
        .unwrap_or_default();

        let mut visitors = match self.visitors.lock() {
            Ok(guard) => guard,
            Err(_) => {
                let res = req.into_response(
                    HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Failed to acquire lock")
                        .map_into_right_body(),
                );
                return Box::pin(async { Ok(res) });
            }
        };

        let current_timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => {
                let res = req.into_response(
                    HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("System time error")
                        .map_into_right_body(),
                );
                return Box::pin(async { Ok(res) });
            }
        };

        if let Some(last_timestamp) = visitors.get(&ip) {
            if current_timestamp - last_timestamp < 30 {
                // Limit to 1 request per half a minute per IP
                let res = req.into_response(
                    HttpResponse::build(StatusCode::TOO_MANY_REQUESTS)
                        .body("Too Many Requests, 1 per 30 seconds allowed")
                        .map_into_right_body(),
                );
                return Box::pin(async { Ok(res) });
            }
        }


        visitors.insert(ip, current_timestamp);
        let fut = self.service.call(req);

        Box::pin(async move {
            fut.await
                .map(ServiceResponse::map_into_left_body)
                .map_err(|e| ErrorInternalServerError(format!("Error: {}", e)))
        })
    }
}