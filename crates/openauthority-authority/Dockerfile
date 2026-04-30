# Chef Stage — install cargo-chef once, reused by planner and builder
FROM rust:1.95-slim-trixie AS chef
RUN cargo install cargo-chef
WORKDIR /usr/src/openauthority

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

COPY --from=planner /usr/src/openauthority/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release -p openauthority-authority

# Runtime Stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m openauthority

WORKDIR /app

COPY --from=builder /usr/src/openauthority/target/release/openauthority-authority /usr/local/bin/openauthority-authority

RUN mkdir -p /app/policies /app/data && chown -R openauthority:openauthority /app

# /app/policies is the default policy_dir — mount or COPY your .cedar files here.
# The schema is embedded in the binary; no schema.cedarschema is required unless
# you want to override it via FIRMA_AUTHORITY_SCHEMA_PATH.

USER openauthority

ENV FIRMA_AUTHORITY_LISTEN_ADDR=0.0.0.0:50051
ENV FIRMA_AUTHORITY_POLICY_DIR=/app/policies
ENV FIRMA_AUTHORITY_REVOCATION_FILE=/app/data/revocations.txt
ENV OPENAUTHORITY_KEY_FILE=/app/data/openauthority-authority.key

EXPOSE 50051

ENTRYPOINT ["openauthority-authority"]
