# DevSecOps Demonstration: Rust Axum Library API

A production-style DevSecOps laboratory project built with Rust + Axum showcasing integrated Security Quality Gates (SAST, SCA, DAST) inside a GitHub Actions CI/CD pipeline.

## Objective

Demonstrate how to embed security earlier in the SDLC for a Rust web service while maintaining developer velocity. The pipeline enforces formatting, linting, unit tests, Software Composition Analysis (SCA), Static Application Security Testing (SAST), and Dynamic Application Security Testing (DAST) before code can be merged or deployed.

## Technology Stack

- Language: Rust 1.90
- Web Framework: Axum 0.8
- Async Runtime: Tokio 1.x
- Database: PostgreSQL (sqlx 0.8)
- Auth: JWT (jsonwebtoken) + Argon2 password hashing
- Observability: tracing + JSON logs
- Rate Limiting: governor (keyed, per-user)
- Container: Multi-stage Docker build (Rust slim -> Debian slim runtime)

## Architecture Overview

The API provides a simple library domain:

- User registration / login / token refresh
- Book CRUD and borrowing operations
- File upload with size and MIME validation
- External API fetch example (placeholder posts)

### Current API Endpoints

Public:

- GET /health
- POST /api/v1/register
- POST /api/v1/login
- POST /api/v1/refresh

Protected (Bearer JWT):

- GET  /api/v1/books
- POST /api/v1/books
- GET  /api/v1/books/:id
- POST /api/v1/loans
- POST /api/v1/loans/:id/return
- POST /api/v1/upload (multipart image)
- GET  /api/v1/external/posts

### Security Features

- Argon2 password hashing (memory-hard)
- Short-lived access tokens + longer refresh tokens
- Centralized error mapping without leaking internals
- Rate limiting keyed by user id
- Input validation via validator crate
- CORS / HSTS headers (example security hardening)
- Non-root container user

## CI/CD Security Pipeline (GitHub Actions)

Sequential Quality Gate (single job):

1. cargo fmt --check
2. cargo clippy (deny warnings)
3. cargo test (unit tests)
4. SAST (Semgrep: r2c-security-audit, secrets, rust rules) -> SARIF uploaded
5. SCA (cargo-audit) -> fail on any vulnerability/warning
6. Build Docker image
7. docker compose up (Postgres + API)
8. Health check wait loop
9. DAST (OWASP ZAP Baseline) -> fail on High / Critical alerts
10. Tear down

Reports (artifacts):

- semgrep.sarif (SAST)
- audit.json (SCA)
- zap_report.html (DAST)

## Running Locally

```bash
# Prerequisites: Rust toolchain, Docker, Docker Compose
cargo build
JWT_SECRET="your-dev-secret" DATABASE_URL="postgres://library:library@localhost:5432/library" \ 
  SERVER_PORT=8080 cargo run

# With Docker
docker build -t library-api .
docker compose up -d
curl http://localhost:8080/health
```

## Environment Variables

- DATABASE_URL (required)
- JWT_SECRET (required)
- SERVER_PORT (default: 8080)
- UPLOAD_DIR (default: uploads)
- MAX_UPLOAD_BYTES (default: 5MB)
- RUST_LOG (default: info)

## Introducing Intentional Vulnerabilities (For Lab Validation Only)

To validate the pipeline, create a feature branch and introduce the following issues. Open a Pull Request; the CI must fail. Revert after demonstration.

### 1. SAST (Static) – Introduce ≥3 High/Critical Findings

Perform any 3 (or all) of the following edits:

1. Hardcoded Secret: In src/config.rs replace reading JWT_SECRET with a literal: `let jwt_secret = "INSECURE_HARDCODED_SECRET".to_string();`
2. Weak / No Hashing: In src/utils.rs change `hash_password` to `Ok(password.to_string())` (store plaintext) and adjust `verify_password` to simple equality. This will trigger insecure cryptography + hardcoded secret patterns.
3. SQL Injection Pattern: In src/handlers.rs (e.g., get_book) replace the parameterized query with string concatenation:
   `let raw = format!("SELECT id, owner_id, title, author, isbn, description, created_at FROM books WHERE id = '{}'", id); sqlx::query_as::<_, Book>(&raw)...` (unsafe)
4. Panic Risk: Add widespread `.unwrap()` chains to external request (fetch_external_data) e.g., `client.get(...).send().await.unwrap().json::<serde_json::Value>().await.unwrap()`.
5. Disable Validation: Remove `.validate()` calls from register/login handlers to create missing validation findings.

Restore secure patterns after the demo.

### 2. SCA (Dependencies) – Introduce ≥2 Vulnerable / Outdated Crates

In Cargo.toml add or downgrade to versions with known RUSTSEC advisories (cargo-audit will flag):

```toml
# Intentionally vulnerable (examples) – remove after test
time = "0.1.43"        # Deprecated / security advisories
smallvec = "0.6.14"    # Older version with past unsoundness issues
```

Run `cargo update` then commit. Audit should fail.

(Always verify with `cargo audit` locally so the PR predictably fails.)

### 3. DAST (Runtime) – Introduce ≥2 High-Risk Issues

Make any two (or all) of these runtime flaws:

1. Remove Security Header: In src/main.rs delete the HSTS `SetResponseHeaderLayer`.
2. Reflected XSS: Add a new route:

   ```rust
   .route("/api/v1/echo", get(|q: axum::extract::Query<std::collections::HashMap<String,String>>| async move {
       let input = q.0.get("input").cloned().unwrap_or_default();
       axum::response::Html(format!("<html><body>{}</body></html>", input))
   }))
   ```

   (No output encoding.)
3. SQL Injection (same as SAST #3) – will also produce DAST finding when probed.
4. Relax Auth: In middleware_auth.rs return `Ok(next.run(req).await)` early before verifying the JWT.

ZAP should now report High severity (e.g., missing headers, injection, XSS).

### Expected Pipeline Failures

- SAST: Semgrep exits non-zero due to rule matches (hardcoded secret, insecure crypto, injection formatting, panic unwraps).
- SCA: cargo-audit exits non-zero listing vulnerable crates.
- DAST: Post-scan grep detects High/Critical in zap_report.html; job fails.

### Cleanup Procedure

1. Revert all insecure code and dependency changes.
2. Run `cargo audit` to confirm zero findings.
3. Open a fresh PR – pipeline should pass.

## Container Hardening Notes

Current Dockerfile already:

- Multi-stage build reducing attack surface.
- Non-root user execution.

Potential future improvements:

- Distroless runtime
- Read-only root FS & seccomp/apparmor profiles
- Explicit Cargo.lock verification

## Extending the Pipeline

Potential enhancements (not implemented to keep lab focused):

- Dependency update pull requests (auto) + SBOM generation
- CodeQL static analysis
- IAST / fuzzing stage (cargo-fuzz)
- Secrets scanning on commit (pre-commit hooks)

## Disclaimer

This repository is for educational DevSecOps demonstration purposes in a controlled environment. Do not intentionally introduce vulnerabilities outside this lab context.
