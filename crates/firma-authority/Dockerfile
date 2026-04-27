# Chef Stage — install cargo-chef once, reused by planner and builder
FROM rust:1.95-slim-trixie AS chef
RUN cargo install cargo-chef
WORKDIR /usr/src/firma

# Planner Stage — compute the dependency recipe from the workspace
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Builder Stage — cook deps (cached layer), then build the binary
FROM chef AS builder

RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=planner /usr/src/firma/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release -p firma-authority

# Runtime Stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m firma

WORKDIR /app

COPY --from=builder /usr/src/firma/target/release/firma-authority /usr/local/bin/firma-authority

RUN mkdir -p /app/policies /app/data && chown -R firma:firma /app

COPY --from=builder /usr/src/firma/crates/firma-authority/policies /app/policies

USER firma

ENV FIRMA_AUTHORITY_LISTEN_ADDR=0.0.0.0:50051
ENV FIRMA_AUTHORITY_POLICY_DIR=/app/policies
ENV FIRMA_AUTHORITY_REVOCATION_FILE=/app/data/revocations.txt
ENV FIRMA_AUTHORITY_KEY_FILE=/app/data/firma-authority.key

EXPOSE 50051

ENTRYPOINT ["firma-authority"]
