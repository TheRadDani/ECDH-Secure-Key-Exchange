# Multi-stage Dockerfile for Cryptography Programs
# Optimized for size, security, and production deployment

# ============================================================================
# Stage 1: Builder - Compile the C++ applications
# ============================================================================
FROM ubuntu:22.04 AS builder

# Metadata
ARG MAINTAINER 
LABEL maintainer=$MAINTAINER
LABEL description="Build stage for cryptography demonstration programs"
LABEL stage="builder"

# Set build arguments
ARG DEBIAN_FRONTEND=noninteractive
ARG BUILD_DATE
ARG VCS_REF

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    g++ \
    make \
    libssl-dev \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create build directory
WORKDIR /build

# Copy source files (using .dockerignore to exclude unnecessary files)
COPY crypto_core.cpp .
COPY secure_transfer.cpp .
COPY Makefile .

# Build the applications with optimizations
RUN make clean && make all \
    && strip crypto_core secure_transfer \
    && chmod +x crypto_core secure_transfer

# Verify builds
RUN ls -lh crypto_core secure_transfer

# ============================================================================
# Stage 2: Runtime - Minimal production image
# ============================================================================
FROM ubuntu:22.04 AS runtime

# Metadata
LABEL maintainer="crypto-team@example.com"
LABEL description="Production runtime for cryptography programs"
LABEL version="1.0.0"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.title="Secure Crypto Transfer"
LABEL org.opencontainers.image.description="High-performance cryptography"

# Install only runtime dependencies (no build tools)
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r cryptoapp --gid=1000 && \
    useradd -r -g cryptoapp --uid=1000 --home-dir=/app --shell=/bin/bash cryptoapp && \
    mkdir -p /app /tmp/sockets && \
    chown -R cryptoapp:cryptoapp /app /tmp/sockets

# Set working directory
WORKDIR /app

# Copy compiled binaries from builder stage
COPY --from=builder --chown=cryptoapp:cryptoapp /build/crypto_core /app/
COPY --from=builder --chown=cryptoapp:cryptoapp /build/secure_transfer /app/

# Copy additional files (scripts, docs)
COPY --chown=cryptoapp:cryptoapp README.md /app/
COPY --chown=cryptoapp:cryptoapp QUICK_REFERENCE.md /app/

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Function to handle signals\n\
cleanup() {\n\
    echo "Received shutdown signal, cleaning up..."\n\
    rm -f /tmp/sockets/secure_transfer.sock\n\
    exit 0\n\
}\n\
\n\
trap cleanup SIGTERM SIGINT\n\
\n\
# Default to receiver mode if no arguments\n\
MODE="${MODE:-receive}"\n\
MESSAGE="${MESSAGE:-Hello from container}"\n\
\n\
case "$MODE" in\n\
    receive)\n\
        echo "Starting in RECEIVER mode..."\n\
        exec /app/secure_transfer receive\n\
        ;;\n\
    send)\n\
        echo "Starting in SENDER mode..."\n\
        echo "Message: $MESSAGE"\n\
        exec /app/secure_transfer send "$MESSAGE"\n\
        ;;\n\
    demo)\n\
        echo "Running DEMO mode..."\n\
        exec /app/crypto_core\n\
        ;;\n\
    *)\n\
        echo "Unknown mode: $MODE"\n\
        echo "Valid modes: receive, send, demo"\n\
        exit 1\n\
        ;;\n\
esac' > /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh && \
    chown cryptoapp:cryptoapp /app/entrypoint.sh

# Switch to non-root user
USER cryptoapp

# Environment variables
ENV MODE=receive \
    MESSAGE="Default message from container" \
    SOCKET_PATH=/tmp/sockets/secure_transfer.sock

# Expose socket directory as volume
VOLUME ["/tmp/sockets"]

# Health check (for Kubernetes probes)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD test -f /app/secure_transfer || exit 1

# Default entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command (can be overridden)
CMD []

# ============================================================================
# Stage 3: Debug - For development and troubleshooting
# ============================================================================
FROM runtime AS debug

USER root

# Install debugging tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb \
    strace \
    valgrind \
    vim \
    curl \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Switch back to app user
USER cryptoapp

# ============================================================================
# Usage Examples:
# ============================================================================
# Build production image:
#   docker build --target runtime -t crypto-app:latest .
#
# Build debug image:
#   docker build --target debug -t crypto-app:debug .
#
# Run receiver:
#   docker run -e MODE=receive crypto-app:latest
#
# Run sender:
#   docker run -e MODE=send -e MESSAGE="Hello" crypto-app:latest
#
# Run demo:
#   docker run -e MODE=demo crypto-app:latest
# ============================================================================