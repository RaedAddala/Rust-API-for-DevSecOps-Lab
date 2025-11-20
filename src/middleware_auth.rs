use std::sync::Arc;

use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};

use crate::{AppState, errors::AppError, models::Claims, utils::decode_jwt};


/// Authentication middleware validating JWT access tokens.
///
/// # Errors
/// Returns unauthorized if token is missing or invalid; may return decoding errors wrapped in `AppError`.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(AppError::Unauthorized)?;
    let claims: Claims = decode_jwt(token, &state.config)?;
    let user_id = claims.sub;

    // Rate limit key: user_id or IP
    let key = user_id.to_string();
    if state.rate_limiter.check_key(&key).is_err() {
        return Err(AppError::Anyhow(anyhow::anyhow!("rate limit exceeded")));
    }

    // Insert user_id into request extensions
    req.extensions_mut().insert(user_id);

    Ok(next.run(req).await)
}
