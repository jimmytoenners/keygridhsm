# KeyGrid HSM Makefile

# Variables
BINARY_NAME=keygrid-hsm
TEST_HSM_BINARY=test-hsm
DOCKER_IMAGE=keygrid-hsm
VERSION?=latest
GO_VERSION=1.23

# Build directories
BUILD_DIR=build
DIST_DIR=dist

# Default target
.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help message
	@echo 'KeyGrid HSM - Build Automation'
	@echo 'Usage:'
	@echo '  make <target>'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: clean
clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@rm -f $(BINARY_NAME) $(TEST_HSM_BINARY)
	@rm -f coverage.out coverage.html
	@echo "✅ Clean complete"

.PHONY: deps
deps: ## Download dependencies
	@echo "📦 Downloading dependencies..."
	@go mod download
	@go mod tidy
	@echo "✅ Dependencies updated"

.PHONY: fmt
fmt: ## Format code
	@echo "🎨 Formatting code..."
	@go fmt ./...
	@echo "✅ Code formatted"

.PHONY: lint
lint: ## Run linter
	@echo "🔍 Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "⚠️  golangci-lint not found, skipping lint"; \
	fi

.PHONY: vet
vet: ## Run go vet
	@echo "🔍 Running go vet..."
	@go vet ./...
	@echo "✅ Vet complete"

.PHONY: build
build: clean deps ## Build the application
	@echo "🏗️  Building KeyGrid HSM..."
	@mkdir -p $(BUILD_DIR)
	@go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server
	@go build -ldflags="-s -w" -o $(BUILD_DIR)/$(TEST_HSM_BINARY) ./cmd/test-hsm
	@echo "✅ Build complete: $(BUILD_DIR)/$(BINARY_NAME), $(BUILD_DIR)/$(TEST_HSM_BINARY)"

.PHONY: build-local
build-local: ## Build for local development (current directory)
	@echo "🏗️  Building for local development..."
	@go build -o $(BINARY_NAME) ./cmd/server
	@go build -o $(TEST_HSM_BINARY) ./cmd/test-hsm
	@echo "✅ Local build complete"

.PHONY: test
test: ## Run unit tests
	@echo "🧪 Running unit tests..."
	@go test -v ./tests/unit/...
	@echo "✅ Unit tests complete"

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "🧪 Running integration tests..."
	@go test -v ./tests/integration/...
	@echo "✅ Integration tests complete"

.PHONY: test-performance
test-performance: ## Run performance tests
	@echo "⚡ Running performance tests..."
	@go test -bench=. -benchmem ./tests/performance/
	@echo "✅ Performance tests complete"

.PHONY: test-all
test-all: test test-integration test-performance ## Run all tests

.PHONY: coverage
coverage: ## Generate test coverage report
	@echo "📊 Generating coverage report..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report generated: coverage.html"

.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "🐳 Building Docker image..."
	@docker build -t $(DOCKER_IMAGE):$(VERSION) .
	@docker tag $(DOCKER_IMAGE):$(VERSION) $(DOCKER_IMAGE):latest
	@echo "✅ Docker image built: $(DOCKER_IMAGE):$(VERSION)"

.PHONY: docker-test
docker-test: ## Run tests in Docker environment
	@echo "🐳 Running tests in Docker..."
	@chmod +x docker-test.sh
	@./docker-test.sh
	@echo "✅ Docker tests complete"

.PHONY: docker-run
docker-run: docker-build ## Build and run Docker container
	@echo "🐳 Running Docker container..."
	@docker run --rm -p 8080:8080 \
		-e KEYGRID_LOG_LEVEL=info \
		--name keygrid-hsm \
		$(DOCKER_IMAGE):latest

.PHONY: docker-compose-up
docker-compose-up: ## Start services with docker-compose
	@echo "🐳 Starting services with docker-compose..."
	@docker-compose -f deployments/docker/docker-compose.yaml up -d
	@echo "✅ Services started"

.PHONY: docker-compose-down
docker-compose-down: ## Stop services with docker-compose
	@echo "🐳 Stopping services with docker-compose..."
	@docker-compose -f deployments/docker/docker-compose.yaml down
	@echo "✅ Services stopped"

.PHONY: k8s-deploy
k8s-deploy: ## Deploy to Kubernetes
	@echo "☸️  Deploying to Kubernetes..."
	@kubectl apply -f deployments/kubernetes/
	@echo "✅ Deployed to Kubernetes"

.PHONY: k8s-delete
k8s-delete: ## Delete from Kubernetes
	@echo "☸️  Deleting from Kubernetes..."
	@kubectl delete -f deployments/kubernetes/
	@echo "✅ Deleted from Kubernetes"

.PHONY: helm-install
helm-install: ## Install with Helm
	@echo "⚓ Installing with Helm..."
	@helm install keygrid-hsm deployments/helm/keygrid-hsm/
	@echo "✅ Installed with Helm"

.PHONY: helm-upgrade
helm-upgrade: ## Upgrade with Helm
	@echo "⚓ Upgrading with Helm..."
	@helm upgrade keygrid-hsm deployments/helm/keygrid-hsm/
	@echo "✅ Upgraded with Helm"

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall with Helm
	@echo "⚓ Uninstalling with Helm..."
	@helm uninstall keygrid-hsm
	@echo "✅ Uninstalled with Helm"

.PHONY: dev
dev: build-local ## Build and run for development
	@echo "🚀 Starting KeyGrid HSM in development mode..."
	@./$(BINARY_NAME) --config=deployments/docker/configs/development.yaml

.PHONY: demo
demo: build-local ## Build and run the demo/test program
	@echo "🎭 Running KeyGrid HSM demo..."
	@./$(TEST_HSM_BINARY)

.PHONY: install
install: build ## Install binaries to system
	@echo "📦 Installing binaries..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@sudo cp $(BUILD_DIR)/$(TEST_HSM_BINARY) /usr/local/bin/
	@echo "✅ Binaries installed to /usr/local/bin/"

.PHONY: uninstall
uninstall: ## Uninstall binaries from system
	@echo "🗑️  Uninstalling binaries..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@sudo rm -f /usr/local/bin/$(TEST_HSM_BINARY)
	@echo "✅ Binaries uninstalled"

.PHONY: release
release: clean test-all docker-build ## Build release artifacts
	@echo "🚀 Building release artifacts..."
	@mkdir -p $(DIST_DIR)
	@GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/server
	@GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/server
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/server
	@GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/server
	@GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/server
	@echo "✅ Release artifacts built in $(DIST_DIR)/"

.PHONY: check
check: fmt vet lint test ## Run all code quality checks

.PHONY: ci
ci: deps check test-all docker-build ## Run full CI pipeline

.PHONY: status
status: ## Show project status
	@echo "📊 KeyGrid HSM Project Status"
	@echo "=============================="
	@echo "Go version: $(shell go version)"
	@echo "Dependencies: $(shell go list -m all | wc -l) modules"
	@echo "Source files: $(shell find . -name '*.go' -not -path './vendor/*' | wc -l) files"
	@echo "Test files: $(shell find . -name '*_test.go' -not -path './vendor/*' | wc -l) files"
	@echo "Docker image: $(DOCKER_IMAGE):$(VERSION)"
	@echo ""
	@echo "Available providers:"
	@echo "  • Mock HSM (development/testing)"
	@echo "  • Azure KeyVault (production)"
	@echo "  • Custom Storage (flexible backend)"
	@echo ""
	@echo "Deployment options:"
	@echo "  • Standalone binary"
	@echo "  • Docker container"
	@echo "  • Kubernetes deployment"
	@echo "  • Helm chart"

# Security
.PHONY: security security-scan security-audit security-clean
security: security-scan ## Run security checks

security-scan: ## Run basic security scans
	@echo "🔒 Running security scans..."
	@command -v gosec >/dev/null || go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@gosec -quiet ./...
	@echo "✅ Security scan completed"

security-audit: ## Run comprehensive security audit
	@echo "🛡️  Running comprehensive security audit..."
	@chmod +x scripts/security-audit.sh
	@./scripts/security-audit.sh
	@echo "✅ Security audit completed"

security-clean: ## Clean security reports
	@echo "🧹 Cleaning security reports..."
	@rm -rf security-reports
