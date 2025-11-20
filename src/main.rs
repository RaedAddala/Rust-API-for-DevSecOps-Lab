use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use axum::http::header::STRICT_TRANSPORT_SECURITY;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::HeaderValue,
    middleware,
    routing::{get, post},
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::{error, info, warn};

use library_api::{AppState, Config, build_rate_limiter, handlers, middleware_auth};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,library_api=debug,sqlx=warn".into()),
        )
        .json()
        .init();

    info!("Starting LibraryHub API v{}", env!("CARGO_PKG_VERSION"));

    dotenvy::dotenv().ok();
    let config = Config::from_env()?;

    tokio::fs::create_dir_all(&config.upload_dir).await?;

    let db = connect_with_retry(&config.database_url)
        .await
        .map_err(|e| anyhow!("Failed to connect to PostgreSQL after retries: {e}"))?;

    info!("Running database migrations...");
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .map_err(|e| anyhow!("Migration failed: {e}"))?;
    info!("Database migrations completed successfully");

    let rate_limiter = build_rate_limiter();

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let state = Arc::new(AppState {
        db,
        config: config.clone(),
        rate_limiter,
        http_client,
    });

    let public_routes = Router::new()
        .route("/health", get(handlers::health_check))
        .route("/api/v1/register", post(handlers::register))
        .route("/api/v1/login", post(handlers::login))
        .route("/api/v1/refresh", post(handlers::refresh_token));

    let protected_routes = Router::new()
        .route("/api/v1/books", get(handlers::list_books))
        .route("/api/v1/books", post(handlers::create_book))
        .route("/api/v1/books/{:id}", get(handlers::get_book))
        .route("/api/v1/loans", post(handlers::borrow_book))
        .route("/api/v1/loans/{:id}/return", post(handlers::return_book))
        .route("/api/v1/upload", post(handlers::upload_file))
        .route("/api/v1/external/posts", get(handlers::fetch_external_data))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            middleware_auth::auth_middleware,
        ));

    let hsts_value: HeaderValue =
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload");

    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10 MB upload limit
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                STRICT_TRANSPORT_SECURITY,
                hsts_value,
            ),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], config.server_port));
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Server listening on http://{}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| anyhow!("Server error: {e}"))?;

    info!("Server shut down gracefully");
    Ok(())
}

async fn connect_with_retry(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let mut delay = Duration::from_millis(500);
    let max_attempts = 30;

    for attempt in 1..=max_attempts {
        match PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
        {
            Ok(pool) => {
                info!("Connected to PostgreSQL on attempt {attempt}");
                return Ok(pool);
            }
            Err(e) => {
                warn!(
                    "Database connection failed (attempt {}/{}): {e} — retrying in {:?}",
                    attempt, max_attempts, delay
                );
                if attempt == max_attempts {
                    error!("All connection attempts failed");
                    return Err(e);
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
        }
    }
    unreachable!()
}

// ───── Graceful shutdown on Ctrl+C (SIGINT) or Docker SIGTERM ─────
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => { info!("Received Ctrl+C"); }
        () = terminate => { info!("Received SIGTERM"); }
    }

    info!("Shutdown signal received — closing server...");
}
