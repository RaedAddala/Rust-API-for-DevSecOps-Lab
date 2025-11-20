FROM rust:1.90-slim as builder

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && rm -rf src

COPY src ./src
COPY migrations ./migrations
RUN SQLX_OFFLINE=true cargo build --release

FROM debian:bookworm-slim

RUN useradd -m appuser && \
    apt-get update && apt-get install -y ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/app/target/release/library-api /app/library-api
COPY migrations ./migrations

RUN mkdir -p /app/uploads && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

ENV RUST_LOG=info
ENV SERVER_PORT=8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["./library-api"]