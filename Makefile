.PHONY: all build test lint clean docker run generate-ca install help

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -X main.version=$(VERSION)
BINARY := kproxy

all: build

## build: Build the kproxy binary
build:
	@echo "Building kproxy $(VERSION)..."
	@CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/kproxy
	@echo "Built bin/$(BINARY)"

## test: Run tests
test:
	@echo "Running tests..."
	@go test -v -race -cover ./...

## lint: Run linters
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install from https://golangci-lint.run/"; \
	fi

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@echo "Clean complete"

## docker: Build Docker image
docker:
	@echo "Building Docker image..."
	@docker build -t kproxy:$(VERSION) -f deployments/docker/Dockerfile .
	@docker tag kproxy:$(VERSION) kproxy:latest
	@echo "Built kproxy:$(VERSION) and kproxy:latest"

## run: Run kproxy locally
run:
	@go run ./cmd/kproxy -config configs/config.example.yaml

## generate-ca: Generate CA certificates
generate-ca:
	@echo "Generating CA certificates..."
	@./scripts/generate-ca.sh

## install: Install kproxy binary and systemd service
install: build
	@echo "Installing kproxy..."
	@sudo install -m 755 bin/$(BINARY) /usr/local/bin/
	@sudo install -m 644 deployments/systemd/kproxy.service /etc/systemd/system/
	@sudo systemctl daemon-reload
	@echo "Installation complete. Enable with: sudo systemctl enable kproxy"

## tidy: Run go mod tidy
tidy:
	@echo "Running go mod tidy..."
	@go mod tidy

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
