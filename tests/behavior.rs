use chrono::Utc;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use library_api::{
    AppError, Config, LoginRequest, RegisterRequest, TokenResponse, build_rate_limiter,
    create_jwt_tokens, decode_jwt, hash_password, verify_password,
};
use std::num::NonZeroU32;
use uuid::Uuid;
use validator::Validate;

fn test_config() -> Config {
    Config {
        database_url: "postgres://user:pass@localhost/db".into(),
        jwt_secret: "super_secret_test_key".into(),
        server_port: 0,
        upload_dir: "uploads_test".into(),
        max_upload_bytes: 1024 * 1024,
    }
}

#[tokio::test]
async fn password_hash_and_verify_success_and_failure() {
    let pwd = "correctHorseBatteryStaple";
    let hash = hash_password(pwd).expect("hash should succeed");
    assert_ne!(hash, pwd, "hash should differ from password");
    assert!(
        verify_password(pwd, &hash).unwrap(),
        "verification should succeed"
    );
    assert!(
        !verify_password("wrong", &hash).unwrap(),
        "wrong password should fail"
    );
}

#[tokio::test]
async fn jwt_create_and_decode_access_refresh() {
    let cfg = test_config();
    let user_id = Uuid::new_v4();
    let (access, refresh) = create_jwt_tokens(user_id, &cfg).unwrap();
    let access_claims = decode_jwt(&access, &cfg).unwrap();
    let refresh_claims = decode_jwt(&refresh, &cfg).unwrap();
    assert_eq!(access_claims.sub, user_id);
    assert!(!access_claims.refresh, "access token refresh flag false");
    assert!(refresh_claims.refresh, "refresh token refresh flag true");
}

#[tokio::test]
async fn jwt_decode_unauthorized_invalid() {
    let cfg = test_config();
    let res = decode_jwt("not.a.valid.token", &cfg);
    assert!(
        matches!(res, Err(AppError::Unauthorized)),
        "invalid token yields Unauthorized error"
    );
}

#[tokio::test]
async fn rate_limiter_allows_first_blocks_second_custom_quota() {
    // Custom limiter with quota=1 per minute to force failure on second attempt
    let quota = Quota::per_minute(NonZeroU32::new(1).unwrap());
    let limiter: RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock> =
        RateLimiter::keyed(quota);
    let key = "user123".to_string();
    assert!(
        limiter.check_key(&key).is_ok(),
        "first acquisition should pass"
    );
    assert!(
        limiter.check_key(&key).is_err(),
        "second acquisition should fail due to quota"
    );
}

#[tokio::test]
async fn app_error_status_codes_mapping() {
    use axum::response::IntoResponse;
    let mk = |e: AppError| e.into_response().status();
    assert_eq!(
        mk(AppError::InvalidCredentials),
        axum::http::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        mk(AppError::Unauthorized),
        axum::http::StatusCode::UNAUTHORIZED
    );
    assert_eq!(mk(AppError::NotFound), axum::http::StatusCode::NOT_FOUND);
    assert_eq!(
        mk(AppError::Validation("x".into())),
        axum::http::StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn register_request_validation_invalid_email() {
    let req = RegisterRequest {
        email: "not-an-email".into(),
        password: "longenough".into(),
    };
    assert!(
        req.validate().is_err(),
        "invalid email should fail validation"
    );
}

#[tokio::test]
async fn login_request_validation_short_password() {
    let req = LoginRequest {
        email: "user@example.com".into(),
        password: "short".into(),
    };
    assert!(
        req.validate().is_err(),
        "short password should fail validation"
    );
}

#[tokio::test]
async fn token_response_serde_round_trip() {
    let token = TokenResponse {
        access_token: "a".into(),
        refresh_token: "b".into(),
    };
    let json = serde_json::to_string(&token).unwrap();
    let de: TokenResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(de.access_token, "a");
    assert_eq!(de.refresh_token, "b");
}

#[tokio::test]
async fn jwt_tokens_are_distinct() {
    let cfg = test_config();
    let user_id = Uuid::new_v4();
    let (access, refresh) = create_jwt_tokens(user_id, &cfg).unwrap();
    assert_ne!(access, refresh, "access and refresh tokens must differ");
}

#[tokio::test]
async fn health_check_behavior() {
    let res = library_api::handlers::health_check().await;
    assert_eq!(res, "OK");
}

#[test]
fn password_hash_and_verify_success() {
    let pw = "CorrectHorseBatteryStaple";
    let hash = hash_password(pw).unwrap();
    assert!(verify_password(pw, &hash).unwrap());
}

#[test]
fn password_hash_and_verify_failure() {
    let hash = hash_password("password123").unwrap();
    assert!(!verify_password("different", &hash).unwrap());
}

#[test]
fn jwt_tokens_have_refresh_claim_and_are_distinct() {
    let cfg = test_config();
    let (access, refresh) = create_jwt_tokens(Uuid::new_v4(), &cfg).unwrap();
    assert_ne!(access, refresh);
    let access_claims = decode_jwt(&access, &cfg).unwrap();
    let refresh_claims = decode_jwt(&refresh, &cfg).unwrap();
    assert!(!access_claims.refresh);
    assert!(refresh_claims.refresh);
    assert!(access_claims.exp < refresh_claims.exp);
}

#[test]
fn decode_jwt_invalid_token_unauthorized() {
    let cfg = test_config();
    let err = decode_jwt("not.a.jwt", &cfg).unwrap_err();
    matches!(err, AppError::Unauthorized);
}

#[test]
fn register_request_validation_failure_short_password() {
    let req = RegisterRequest {
        email: "user@example.com".into(),
        password: "short".into(),
    };
    assert!(req.validate().is_err());
}

#[test]
fn login_request_validation_failure_bad_email() {
    let req = LoginRequest {
        email: "not-an-email".into(),
        password: "longenoughpassword".into(),
    };
    assert!(req.validate().is_err());
}

#[test]
fn rate_limiter_allows_initial_requests() {
    let rl = build_rate_limiter();
    let key = Uuid::new_v4().to_string();
    assert!(rl.check_key(&key).is_ok());
}

#[test]
fn rate_limiter_exhaustion_after_many_hits() {
    let rl = build_rate_limiter();
    let key = "same-user".to_string();
    // exceed quota (60 per minute) by performing 61 checks
    for _ in 0..60 {
        assert!(rl.check_key(&key).is_ok());
    }
    assert!(rl.check_key(&key).is_err());
}

#[test]
fn jwt_access_and_refresh_expiration_order() {
    let cfg = test_config();
    let (access, refresh) = create_jwt_tokens(Uuid::new_v4(), &cfg).unwrap();
    let a = decode_jwt(&access, &cfg).unwrap();
    let r = decode_jwt(&refresh, &cfg).unwrap();
    assert!(a.exp < r.exp);
    assert!(Utc::now().timestamp() as usize <= a.exp);
}
