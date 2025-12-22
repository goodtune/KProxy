# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o kproxy ./cmd/kproxy

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates openssl

# Create kproxy user
RUN addgroup -g 1000 kproxy && \
    adduser -D -u 1000 -G kproxy kproxy

# Create directories
RUN mkdir -p /etc/kproxy/ca /var/lib/kproxy && \
    chown -R kproxy:kproxy /etc/kproxy /var/lib/kproxy

# Copy binary and scripts
COPY --from=builder /build/kproxy /usr/local/bin/kproxy
COPY --from=builder /build/scripts/generate-ca.sh /usr/local/bin/generate-ca.sh
COPY --from=builder /build/configs/config.example.yaml /etc/kproxy/config.yaml

RUN chmod +x /usr/local/bin/kproxy /usr/local/bin/generate-ca.sh

# Switch to kproxy user
USER kproxy

# Expose ports
EXPOSE 53/udp 53/tcp 80/tcp 443/tcp 8443/tcp 9090/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:9090/health || exit 1

# Run
ENTRYPOINT ["/usr/local/bin/kproxy"]
CMD ["-config", "/etc/kproxy/config.yaml"]
