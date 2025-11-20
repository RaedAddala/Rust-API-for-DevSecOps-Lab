use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(sqlx::FromRow, Debug, Clone)]
#[allow(dead_code)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Debug, Clone)]
#[allow(dead_code)]
pub struct Book {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub title: String,
    pub author: String,
    pub isbn: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Debug, Clone)]
#[allow(dead_code)]
pub struct Loan {
    pub id: Uuid,
    pub user_id: Uuid,
    pub book_id: Uuid,
    pub borrowed_at: DateTime<Utc>,
    pub returned_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: usize,
    pub refresh: bool,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateBookRequest {
    #[validate(length(min = 1))]
    pub title: String,
    #[validate(length(min = 1))]
    pub author: String,
    #[validate(length(min = 10, max = 17))]
    pub isbn: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BookResponse {
    pub id: Uuid,
    pub title: String,
    pub author: String,
    pub isbn: String,
    pub description: Option<String>,
    pub owner_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct BorrowRequest {
    pub book_id: Uuid,
}
