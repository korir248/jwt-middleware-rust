use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder, web};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::{Claims, JwtConfig};

#[derive(Deserialize, Serialize)]
pub struct LoginInput {
    user_id: String,
}

// demo handler
pub async fn login_handler(
    input: web::Json<LoginInput>,
    config: web::Data<JwtConfig>,
) -> impl Responder {
    
    match config.create_jwt(
        input.into_inner().user_id,
        ["user".to_owned(), "admin".to_owned()].into(),
    ) {
        Ok(token) => {
            log::info!("Generated token: {}", &token);
            HttpResponse::Ok().json(json!({ "token": token }))
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Token creation failed: {}", e)),
    }
}

pub async fn protected_handler(req: HttpRequest) -> impl Responder {
    match req.extensions().get::<Claims>() {
        Some(claims) => HttpResponse::Ok().body(format!(
            "Hello {}! Your roles are: {:?}",
            claims.user_id, claims.roles
        )),
        None => HttpResponse::InternalServerError()
            .body("Claims not found - middleware may be misconfigured"),
    }
}
