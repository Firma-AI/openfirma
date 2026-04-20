# Build Stage
FROM rust:1.86-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/firma

# Copy the entire workspace to resolve relative paths in Cargo.toml
COPY . .

# Build only the firma-authority binary
RUN cargo build --release -p firma-authority

# Runtime Stage
FROM debian:bookworm-slim

# Install runtime dependencies (OpenSSL is required by many Rust crates)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /usr/src/firma/target/release/firma-authority /usr/local/bin/firma-authority

# Create default directories for policies and revocations
RUN mkdir -p /app/policies /app/data

# Copy default policies if they exist (optional, can be overridden by volume)
COPY --from=builder /usr/src/firma/crates/firma-authority/policies /app/policies

# Set environment variables for container use
ENV FIRMA_AUTHORITY_LISTEN_ADDR=0.0.0.0:50051
ENV FIRMA_AUTHORITY_POLICY_DIR=/app/policies
ENV FIRMA_AUTHORITY_REVOCATION_FILE=/app/data/revocations.txt
ENV FIRMA_AUTHORITY_KEY_FILE=/app/data/firma-authority.key

# Expose the gRPC port
EXPOSE 50051

# Run the authority
ENTRYPOINT ["firma-authority"]
CMD ["serve"]
