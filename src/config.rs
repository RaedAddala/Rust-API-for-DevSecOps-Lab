use anyhow::Context;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub server_port: u16,
    pub upload_dir: String,
    pub max_upload_bytes: u64,
}

impl Config {
    /// Load configuration from environment variables, applying defaults where appropriate.
    ///
    /// # Errors
    /// Returns an error if mandatory variables (`DATABASE_URL`, `JWT_SECRET`) are missing or invalid,
    /// or if numeric parsing fails.
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
        let jwt_secret = std::env::var("JWT_SECRET").context("JWT_SECRET must be set")?;
        let server_port = std::env::var("SERVER_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8080);
        let upload_dir = std::env::var("UPLOAD_DIR").unwrap_or_else(|_| "uploads".to_string());
        let max_upload_bytes = std::env::var("MAX_UPLOAD_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5 * 1024 * 1024); // 5MB

        Ok(Self {
            database_url,
            jwt_secret,
            server_port,
            upload_dir,
            max_upload_bytes,
        })
    }
}
