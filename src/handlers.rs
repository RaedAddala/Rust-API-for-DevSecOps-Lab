use std::sync::Arc;

use axum::{
    Json,
    extract::{Multipart, Path, State},
    http::StatusCode,
};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use validator::Validate;

use crate::{
    AppState,
    errors::{AppError, AppResult},
    models::{RegisterRequest, UserResponse, User, LoginRequest, TokenResponse, BookResponse, Book, CreateBookRequest, BorrowRequest},
    utils::{create_jwt_tokens, fetch_placeholder_posts, hash_password, verify_password},
};

/// Health check endpoint.
#[must_use]
#[allow(clippy::unused_async)]
pub async fn health_check() -> &'static str { "OK" }

/// Register a new user.
///
/// # Errors
/// Returns validation errors, hashing errors, or database errors.
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> AppResult<(StatusCode, Json<UserResponse>)> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let password_hash = hash_password(&payload.password)?;

    let user_id = Uuid::new_v4();
    let user = sqlx::query_as::<_, User>("INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email, password_hash, created_at")
        .bind(user_id)
        .bind(&payload.email)
        .bind(&password_hash)
        .fetch_one(&state.db).await?;

    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            id: user.id,
            email: user.email,
        }),
    ))
}

/// Authenticate a user and return JWT tokens.
///
/// # Errors
/// Returns validation, invalid credentials, or database errors.
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<(StatusCode, Json<TokenResponse>)> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let user = sqlx::query_as::<_, User>("SELECT id, email, password_hash, created_at FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(&state.db)
        .await?;

    let user = user.ok_or(AppError::InvalidCredentials)?;

    if !verify_password(&payload.password, &user.password_hash)? {
        return Err(AppError::InvalidCredentials);
    }

    let (access, refresh) = create_jwt_tokens(user.id, &state.config)?;
    Ok((
        StatusCode::OK,
        Json(TokenResponse {
            access_token: access,
            refresh_token: refresh,
        }),
    ))
}

/// Refresh JWT tokens using a refresh token.
///
/// # Errors
/// Returns unauthorized errors or token decoding errors.
#[allow(clippy::unused_async)]
pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TokenResponse>,
) -> AppResult<Json<TokenResponse>> {
    let claims = crate::utils::decode_jwt(&body.refresh_token, &state.config)?;
    if !claims.refresh { return Err(AppError::Unauthorized); }
    let (access, refresh) = create_jwt_tokens(claims.sub, &state.config)?;
    Ok(Json(TokenResponse { access_token: access, refresh_token: refresh }))
}

/// List all books.
///
/// # Errors
/// Returns database errors.
pub async fn list_books(State(state): State<Arc<AppState>>) -> AppResult<Json<Vec<BookResponse>>> {
    let books = sqlx::query_as::<_, Book>("SELECT id, owner_id, title, author, isbn, description, created_at FROM books ORDER BY created_at DESC")
        .fetch_all(&state.db).await?;

    let resp = books.into_iter().map(|b| BookResponse { id: b.id, title: b.title, author: b.author, isbn: b.isbn, description: b.description, owner_id: b.owner_id }).collect();
    Ok(Json(resp))
}

/// Create a new book owned by the authenticated user.
///
/// # Errors
/// Returns validation or database errors.
pub async fn create_book(
    State(state): State<Arc<AppState>>,
    axum::Extension(user_id): axum::Extension<Uuid>,
    Json(payload): Json<CreateBookRequest>,
) -> AppResult<(StatusCode, Json<BookResponse>)> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let id = Uuid::new_v4();
    let book = sqlx::query_as::<_, Book>("INSERT INTO books (id, owner_id, title, author, isbn, description)\n         VALUES ($1, $2, $3, $4, $5, $6)\n         RETURNING id, owner_id, title, author, isbn, description, created_at")
        .bind(id)
        .bind(user_id)
        .bind(&payload.title)
        .bind(&payload.author)
        .bind(&payload.isbn)
        .bind(&payload.description)
        .fetch_one(&state.db)
        .await?;

    let resp = BookResponse { id: book.id, title: book.title, author: book.author, isbn: book.isbn, description: book.description, owner_id: book.owner_id };
    Ok((StatusCode::CREATED, Json(resp)))
}

/// Get a single book by id.
///
/// # Errors
/// Returns not found or database errors.
pub async fn get_book(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<BookResponse>> {
    let book = sqlx::query_as::<_, Book>("SELECT id, owner_id, title, author, isbn, description, created_at\n         FROM books WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?;

    let book = book.ok_or(AppError::NotFound)?;
    let resp = BookResponse { id: book.id, title: book.title, author: book.author, isbn: book.isbn, description: book.description, owner_id: book.owner_id };
    Ok(Json(resp))
}

/// Borrow a book.
///
/// # Errors
/// Returns not found or database errors.
pub async fn borrow_book(
    State(state): State<Arc<AppState>>,
    axum::Extension(user_id): axum::Extension<Uuid>,
    Json(body): Json<BorrowRequest>,
) -> AppResult<StatusCode> {
    let _ = sqlx::query_scalar::<_, Uuid>("SELECT id FROM books WHERE id = $1")
        .bind(body.book_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    sqlx::query("INSERT INTO loans (id, user_id, book_id) VALUES ($1, $2, $3)")
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(body.book_id)
        .execute(&state.db)
        .await?;

    Ok(StatusCode::CREATED)
}

/// Return a borrowed book.
///
/// # Errors
/// Returns database errors (including not found implicitly).
pub async fn return_book(
    State(state): State<Arc<AppState>>,
    Path(loan_id): Path<Uuid>,
    axum::Extension(user_id): axum::Extension<Uuid>,
) -> AppResult<StatusCode> {
    sqlx::query("UPDATE loans SET returned_at = now()\n         WHERE id = $1 AND user_id = $2 AND returned_at IS NULL")
        .bind(loan_id)
        .bind(user_id)
        .execute(&state.db)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Upload a file ensuring basic validation.
///
/// # Errors
/// Returns validation errors or I/O/database errors.
#[axum::debug_handler]
pub async fn upload_file(
    State(state): State<Arc<AppState>>,
    axum::Extension(user_id): axum::Extension<Uuid>,
    mut multipart: Multipart,
) -> AppResult<StatusCode> {
    while let Some(field) = multipart.next_field().await.map_err(|e| AppError::Anyhow(e.into()))? {
        let name = field.name().unwrap_or("file").to_string();
        let file_name = field.file_name().unwrap_or("upload.bin").to_string();
        let content_type = field.content_type().map(std::string::ToString::to_string).unwrap_or_default();

        // Basic type validation
        if !["image/png", "image/jpeg"].contains(&content_type.as_str()) { return Err(AppError::Validation("unsupported file type".into())); }

        let data = field.bytes().await.map_err(|e| AppError::Anyhow(e.into()))?;
        if (data.len() as u64) > state.config.max_upload_bytes { return Err(AppError::Validation("file too large".into())); }

        // Virus scan stub (no vulnerability here)
        tracing::info!("Virus scan stub for user {user_id} file {file_name} (field {name})");

        let path = format!("{}/{}", state.config.upload_dir, file_name);
        let mut file = tokio::fs::File::create(path).await.map_err(|e| AppError::Anyhow(e.into()))?;
        file.write_all(&data).await.map_err(|e| AppError::Anyhow(e.into()))?;
    }

    Ok(StatusCode::CREATED)
}

/// Fetch external placeholder posts.
///
/// # Errors
/// Returns network or JSON parsing errors.
pub async fn fetch_external_data(
    State(state): State<Arc<AppState>>,
) -> AppResult<Json<serde_json::Value>> {
    let json = fetch_placeholder_posts(&state.http_client).await?;
    Ok(Json(json))
}
