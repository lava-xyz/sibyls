# Stage 1: Build the Rust executable
FROM rust:latest as builder
RUN apt-get update && \
    apt-get install -y \
    libssl-dev \
    pkg-config \
    gcc \
    build-essential \
    openssl 
    
WORKDIR /usr/src/sibyls
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release 

# Stage 2: Create a minimal Debian-based image with the Rust executable
  # (ubuntu:22.04 image size is 69.2 MB)
FROM ubuntu:22.04

# Install necessary runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root/
COPY --from=builder /usr/src/sibyls/target/release/sibyls .

ENTRYPOINT ["./sibyls"]
CMD ["--help"]
