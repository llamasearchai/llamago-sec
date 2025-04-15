# Adding Dockerfile

# syntax=docker/dockerfile:1

# Stage 1: Build the application
FROM golang:1.20-alpine AS builder

# Install dependencies and build tools
RUN apk add --no-cache gcc musl-dev git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application with optimization flags
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/yourusername/llamasec/internal/version.Version=1.0.0 -X github.com/yourusername/llamasec/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X github.com/yourusername/llamasec/internal/version.Commit=$(git rev-parse --short HEAD || echo 'unknown')" \
    -o llamasec ./cmd/llamasec

# Stage 2: Create the runtime image
FROM alpine:3.18

# Install required runtime packages
RUN apk add --no-cache ca-certificates tzdata

# Set working directory
WORKDIR /app

# Create non-root user for security
RUN addgroup -S llamasec && adduser -S llamasec -G llamasec

# Copy the executable from the builder stage
COPY --from=builder /app/llamasec /usr/local/bin/

# Copy default configurations
COPY --from=builder /app/config /app/config

# Create volume mount points
RUN mkdir -p /app/reports /app/data && \
    chown -R llamasec:llamasec /app

# Set environment variables
ENV LLAMASEC_CONFIG=/app/config/config.yaml \
    LLAMASEC_SIGNATURES=/app/config/signatures.yaml \
    OPENAI_API_KEY=""

# Switch to non-root user
USER llamasec

# Document exposed ports (if the web server is used)
EXPOSE 8080

# Set volume for reports and data
VOLUME ["/app/reports", "/app/data"]

# Set working directory for the user
WORKDIR /app

# Set the entrypoint to the llamasec binary
ENTRYPOINT ["llamasec"]

# Default command if no arguments are passed
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="LlamaSec"
LABEL org.opencontainers.image.description="Concurrent URL vulnerability scanner"
LABEL org.opencontainers.image.url="https://github.com/yourusername/llamasec"
LABEL org.opencontainers.image.source="https://github.com/yourusername/llamasec"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.author="Your Name <your.email@example.com>"
LABEL org.opencontainers.image.licenses="MIT"
