use crate::{
    config::Config,
    errors::{AppError, AppResult},
    models::Claims,
};
use anyhow::anyhow;
use argon2::password_hash::rand_core::OsRng;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use chrono::{Duration, Utc};
use governor::{RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::{num::NonZeroU32, sync::Arc};
use uuid::Uuid;

pub type KeyedRateLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// Hash a plaintext password using Argon2.
///
/// # Errors
/// Returns an error if hashing fails.
pub fn hash_password(password: &str) -> AppResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Anyhow(anyhow!(e.to_string())))?
        .to_string();
    Ok(hash)
}

/// Verify a plaintext password against a stored hash.
///
/// # Errors
/// Returns an error if the hash format is invalid.
pub fn verify_password(password: &str, hash: &str) -> AppResult<bool> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| AppError::Anyhow(anyhow!(e.to_string())))?;
    let argon2 = Argon2::default();
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Create access and refresh JWT tokens for a user.
///
/// # Errors
/// Returns an error if token encoding fails or time conversion fails.
pub fn create_jwt_tokens(user_id: Uuid, config: &Config) -> AppResult<(String, String)> {
    let access_ts = (Utc::now() + Duration::minutes(15)).timestamp();
    let refresh_ts = (Utc::now() + Duration::days(7)).timestamp();
    let access_exp = usize::try_from(access_ts).map_err(|e| AppError::Anyhow(anyhow!(e.to_string())))?;
    let refresh_exp = usize::try_from(refresh_ts).map_err(|e| AppError::Anyhow(anyhow!(e.to_string())))?;

    let access_claims = Claims {
        sub: user_id,
        exp: access_exp,
        refresh: false,
    };
    let refresh_claims = Claims {
        sub: user_id,
        exp: refresh_exp,
        refresh: true,
    };

    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
    let access =
        encode(&Header::default(), &access_claims, &key).map_err(|e| AppError::Anyhow(e.into()))?;
    let refresh = encode(&Header::default(), &refresh_claims, &key)
        .map_err(|e| AppError::Anyhow(e.into()))?;

    Ok((access, refresh))
}

/// Decode and validate a JWT token.
///
/// # Errors
/// Returns Unauthorized if decoding fails.
pub fn decode_jwt(token: &str, config: &Config) -> AppResult<Claims> {
    let key = DecodingKey::from_secret(config.jwt_secret.as_bytes());
    let data = decode::<Claims>(token, &key, &Validation::default())
        .map_err(|_| AppError::Unauthorized)?;
    Ok(data.claims)
}

/// Build a keyed rate limiter (60 requests per minute per key).
///
/// # Panics
/// Panics if the `NonZeroU32` constructor fails (impossible for 60).
///
/// # Must Use
/// The returned rate limiter should be stored; dropping it loses rate limiting state.
#[must_use]
pub fn build_rate_limiter() -> Arc<KeyedRateLimiter> {
    let quota = governor::Quota::per_minute(NonZeroU32::new(60).unwrap());
    Arc::new(RateLimiter::keyed(quota))
}

/// Fetch placeholder posts from an external service.
///
/// # Errors
/// Returns network or JSON parsing errors, or non-success status.
pub async fn fetch_placeholder_posts(client: &reqwest::Client) -> AppResult<serde_json::Value> {
    let res = client
        .get("https://jsonplaceholder.typicode.com/posts")
        .send()
        .await
        .map_err(|e| AppError::Anyhow(e.into()))?;

    let status = res.status();
    if !status.is_success() {
        return Err(AppError::Anyhow(anyhow::anyhow!(
            "external API returned status {status}"
        )));
    }

    let json = res
        .json::<serde_json::Value>()
        .await
        .map_err(|e| AppError::Anyhow(e.into()))?;
    Ok(json)
}
