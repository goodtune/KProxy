# Playwright test container for kproxy admin UI
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Install build deps
RUN apk add --no-cache git make

# Copy go module files and download deps
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build binary
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/kproxy ./cmd/kproxy

FROM alpine:3.19 AS runtime

WORKDIR /app

RUN apk add --no-cache ca-certificates openssl curl bash

# Create directories and users
RUN mkdir -p /etc/kproxy/ca /var/lib/kproxy && \
    addgroup -g 1000 kproxy && adduser -D -u 1000 -G kproxy kproxy

# Copy binary and scripts
COPY --from=builder /out/kproxy /usr/local/bin/kproxy
COPY scripts/generate-ca.sh /usr/local/bin/generate-ca.sh
COPY tests/docker/config.yaml /etc/kproxy/config.yaml

RUN chmod +x /usr/local/bin/kproxy /usr/local/bin/generate-ca.sh

# Generate certificates for admin TLS
RUN CA_DIR=/etc/kproxy/ca /usr/local/bin/generate-ca.sh && rm -f /etc/kproxy/ca/*.srl

RUN chown -R kproxy:kproxy /etc/kproxy /var/lib/kproxy

USER kproxy

EXPOSE 8444/tcp

ENTRYPOINT ["/usr/local/bin/kproxy"]
CMD ["-config", "/etc/kproxy/config.yaml"]
