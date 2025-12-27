.PHONY: all build test lint clean docker run generate-ca install tidy help build-ui clean-ui

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -X main.version=$(VERSION)
BINARY := kproxy

all: build

## build: Build the kproxy binary with embedded React UI
build: tidy build-ui
	@echo "Building kproxy $(VERSION)..."
	@CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/kproxy
	@echo "Built bin/$(BINARY)"

## build-ui: Build the React admin UI
build-ui:
	@echo "Building React admin UI..."
	@if [ -d "admin-ui" ]; then \
		cd admin-ui && npm install --silent && npm run build; \
		echo "React UI built successfully"; \
		cd .. && echo "Copying build to web package..." && \
		rm -rf web/admin-ui && \
		mkdir -p web/admin-ui && \
		cp -r admin-ui/build web/admin-ui/ && \
		echo "UI build copied to web/admin-ui/build"; \
	else \
		echo "Warning: admin-ui directory not found, skipping UI build"; \
	fi

## test: Run tests
test: tidy
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
clean: clean-ui
	@echo "Cleaning..."
	@rm -rf bin/
	@echo "Clean complete"

## clean-ui: Clean React UI build artifacts
clean-ui:
	@echo "Cleaning React UI build..."
	@if [ -d "admin-ui/build" ]; then rm -rf admin-ui/build; fi
	@if [ -d "admin-ui/node_modules" ]; then rm -rf admin-ui/node_modules; fi
	@if [ -d "web/admin-ui" ]; then rm -rf web/admin-ui; fi
	@echo "React UI clean complete"

## docker: Build Docker image
docker:
	@echo "Building Docker image..."
	@docker build -t kproxy:$(VERSION) -f deployments/docker/Dockerfile .
	@docker tag kproxy:$(VERSION) kproxy:latest
	@echo "Built kproxy:$(VERSION) and kproxy:latest"

## run: Run kproxy locally
run: tidy
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
