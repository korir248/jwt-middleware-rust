use actix_web::FromRequest;
use actix_web::{Error as ActixError, dev::Service};
use actix_web::{HttpMessage, dev::ServiceRequest};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use std::future::Future;
use std::future::{Ready, ready};
use std::pin::Pin;
use std::rc::Rc;

use crate::config::JwtConfig;

pub struct JwtMiddleware {
    config: Rc<JwtConfig>,
}

impl JwtMiddleware {
    pub fn new(config: JwtConfig) -> Self {
        Self {
            config: Rc::new(config),
        }
    }
}

impl<S> actix_web::dev::Transform<S, ServiceRequest> for JwtMiddleware
where
    S: Service<ServiceRequest, Response = actix_web::dev::ServiceResponse, Error = ActixError>
        + 'static,
    S::Future: 'static,
{
    type Response = actix_web::dev::ServiceResponse;
    type Error = ActixError;
    type Transform = JwtMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtMiddlewareService {
            service: Rc::new(service),
            config: Rc::clone(&self.config),
        }))
    }
}

pub struct JwtMiddlewareService<S> {
    service: Rc<S>,
    config: Rc<JwtConfig>,
}

impl<S> Service<ServiceRequest> for JwtMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = actix_web::dev::ServiceResponse, Error = ActixError>
        + 'static,
    S::Future: 'static,
{
    type Response = actix_web::dev::ServiceResponse;
    type Error = ActixError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        let bearer = BearerAuth::extract(req.request());

        let config = Rc::clone(&self.config);

        Box::pin(async move {
            let token = match bearer.await {
                Ok(bearer) => bearer.token().to_string(),
                Err(e) => {
                    log::error!("Token not found in header: {}", e);
                    return Err(e.into());
                }
            };

            let claims = match config.validate_jwt(&token) {
                Ok(claims) => claims,
                Err(e) => {
                    log::error!("Invalid token: {:#?}", e);
                    return Err(actix_web::error::ErrorUnauthorized(format!(
                        "Invalid token: {}",
                        e
                    )));
                }
            };
            req.request().extensions_mut().insert(claims);

            let res = service.call(req).await?;

            Ok(res)
        })
    }
}
