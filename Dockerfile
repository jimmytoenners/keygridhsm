# KeyGrid HSM - Multi-stage Dockerfile
# This Dockerfile builds a secure, minimal container image for the KeyGrid HSM service

# Build stage
FROM golang:1.23-alpine AS builder

# Install necessary packages for building
RUN apk add --no-cache \
    ca-certificates \
    git \
    gcc \
    musl-dev \
    postgresql-dev

# Create non-root user for building
RUN adduser -D -s /bin/sh -u 1001 builder

# Set working directory
WORKDIR /app

# Copy go mod files first for better Docker layer caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Change ownership to builder user
RUN chown -R builder:builder /app
USER builder

# Build the binary with security flags
RUN CGO_ENABLED=1 go build \
    -ldflags '-w -s' \
    -o keygrid-hsm \
    ./cmd/server/main.go

# Runtime stage - using distroless for minimal attack surface
FROM gcr.io/distroless/static-debian11:nonroot AS runtime

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /app/keygrid-hsm /usr/local/bin/keygrid-hsm

# Copy configuration templates
COPY --from=builder /app/deployments/docker/configs /etc/keygrid-hsm/configs

# Use nonroot user from distroless (uid 65532)
USER nonroot:nonroot

# Expose default port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/keygrid-hsm", "health"]

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/keygrid-hsm"]

# Default command
CMD ["server", "--config", "/etc/keygrid-hsm/configs/production.yaml"]

# Metadata
LABEL maintainer="KeyGrid HSM Team" \
      version="1.0.0" \
      description="KeyGrid HSM - Enterprise Hardware Security Module" \
      org.opencontainers.image.source="https://github.com/jimmy/keygridhsm" \
      org.opencontainers.image.documentation="https://github.com/jimmy/keygridhsm/docs" \
      org.opencontainers.image.vendor="KeyGrid" \
      org.opencontainers.image.licenses="MIT"