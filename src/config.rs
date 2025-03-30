use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: String, //sub
    pub exp: usize,
    pub iat: usize,
    pub roles: Vec<String>,
}

#[derive(Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_hours: i64,
}

impl JwtConfig {
    pub fn new(secret: String, expiration_hours: i64) -> Self {
        Self {
            secret,
            expiration_hours,
        }
    }
    pub fn create_jwt(
        &self,
        user_id: String,
        roles: Vec<String>,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.expiration_hours);

        let claims = Claims {
            user_id,
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
            roles,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
    }

    pub fn validate_jwt(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &Validation::default(),
        )?;

        Ok(token_data.claims)
    }
}
