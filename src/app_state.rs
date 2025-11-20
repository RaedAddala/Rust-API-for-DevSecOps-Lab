use crate::{Config, utils::KeyedRateLimiter};
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub rate_limiter: Arc<KeyedRateLimiter>,
    pub http_client: reqwest::Client,
}
