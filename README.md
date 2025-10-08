# KeyGrid HSM 🔐

[![Go Version](https://img.shields.io/badge/Go-1.23+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](Dockerfile)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Ready-blue.svg)](deployments/kubernetes)

**KeyGrid HSM** is an enterprise-ready Hardware Security Module (HSM) implementation with a pluggable provider architecture. It provides a unified interface for cryptographic operations while supporting multiple backends including Azure KeyVault, custom storage solutions, and mock implementations for development.

## 🚀 Features

### 🏗️ Core Architecture
- **Pluggable HSM Providers**: Support multiple HSM backends through a provider pattern
- **Enterprise Ready**: Production-grade security, monitoring, and reliability
- **Cloud Native**: Kubernetes-ready with comprehensive observability
- **Developer Friendly**: Mock implementations and comprehensive testing tools

### 🔐 HSM Providers
- **Azure KeyVault**: Production-ready integration with enterprise authentication
- **Custom Storage**: Multi-backend storage (filesystem, database, memory) with encryption
- **Mock HSM**: Development-focused mock with testing scenarios and persistence

### ⚡ Cryptographic Operations
- **Key Generation**: RSA (1024, 2048, 4096-bit), ECDSA (P-256, P-384, P-521), Ed25519
- **Digital Signing**: RS256, ES256, ES384, ES512, Ed25519
- **Encryption/Decryption**: RSA-OAEP, RSA-PKCS1v15
- **Key Management**: Import, export, lifecycle management
- **Key Wrapping**: Enterprise key protection and transport

### 📊 Enterprise Features
- **Health Monitoring**: Comprehensive health checks and status reporting
- **Metrics Collection**: Prometheus metrics for all operations
- **Audit Logging**: Security event logging and compliance reporting
- **Configuration Management**: Flexible YAML configuration with environment variables
- **Error Handling**: Comprehensive error types and recovery mechanisms

## 🏃‍♂️ Quick Start

### Prerequisites
- Go 1.23 or later
- Docker (optional, for containerized deployment)
- Azure KeyVault (optional, for Azure provider)

### Installation

```bash
# Clone the repository
git clone https://github.com/jimmytoenners/keygridhsm.git
cd keygridhsm

# Download dependencies
go mod download

# Build the project
go build ./cmd/server
go build ./cmd/test-hsm
```

### Basic Usage

1. **Run the test program** to verify installation:
```bash
./test-hsm
```

2. **Start the HSM server**:
```bash
./server
```

3. **Test with curl**:
```bash
# Health check
curl http://localhost:8080/health

# List providers
curl http://localhost:8080/api/v1/providers

# Generate a key
curl -X POST http://localhost:8080/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "mock-hsm",
    "key_spec": {
      "key_type": "RSA",
      "key_size": 2048,
      "algorithm": "RSA-PSS"
    },
    "name": "my-test-key"
  }'
```

## 🔧 Configuration

### YAML Configuration Example

```yaml
# config.yaml
server:
  port: 8080
  host: "0.0.0.0"
  log_level: "info"

providers:
  # Mock HSM for development
  mock-hsm:
    enabled: true
    config:
      persistent_storage: false
      max_keys: 1000

  # Azure KeyVault for production
  azure-keyvault:
    enabled: true
    config:
      vault_url: "https://your-vault.vault.azure.net/"
      use_system_msi: true  # For Azure resources
      # Or use service principal:
      # client_id: "your-client-id"
      # client_secret: "your-client-secret"
      # tenant_id: "your-tenant-id"

  # Custom storage provider
  custom-storage:
    enabled: true
    config:
      storage_type: "filesystem"
      encrypt_at_rest: true
      base_path: "/var/lib/keygrid-hsm/keys"

logging:
  level: "info"
  format: "json"

metrics:
  enabled: true
  prometheus:
    enabled: true
```

### Environment Variables

```bash
# Server configuration
KEYGRID_PORT=8080
KEYGRID_HOST=0.0.0.0
KEYGRID_LOG_LEVEL=info

# Azure KeyVault
AZURE_KEYVAULT_URL=https://your-vault.vault.azure.net/
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_TENANT_ID=your-tenant-id

# Custom storage encryption
KEYGRID_ENCRYPTION_KEY=your-encryption-key
```

## 🐳 Docker Deployment

### Build and Run

```bash
# Build the Docker image
docker build -t keygrid-hsm .

# Run with docker-compose
docker-compose -f deployments/docker/docker-compose.yaml up
```

### Docker Compose (Production)

```yaml
version: '3.8'
services:
  keygrid-hsm:
    image: keygrid-hsm:latest
    ports:
      - "8080:8080"
    environment:
      - KEYGRID_LOG_LEVEL=info
      - AZURE_KEYVAULT_URL=${AZURE_KEYVAULT_URL}
    volumes:
      - ./config.yaml:/app/config.yaml
      - hsm-data:/var/lib/keygrid-hsm
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  hsm-data:
```

## ☸️ Kubernetes Deployment

### Quick Deploy

```bash
# Deploy to Kubernetes
kubectl apply -f deployments/kubernetes/

# Or use Helm
helm install keygrid-hsm deployments/helm/keygrid-hsm/
```

### Kubernetes Manifests

The project includes production-ready Kubernetes manifests:
- `00-namespace.yaml` - Namespace creation
- `10-config.yaml` - Configuration and secrets
- `20-deployment.yaml` - Application deployment
- `30-service.yaml` - Service and ingress

## 🧪 Testing

### Run Tests

```bash
# Unit tests
go test -v ./tests/unit/...

# Integration tests (requires running services)
go test -v ./tests/integration/...

# Performance benchmarks
go test -bench=. ./tests/performance/

# Docker-based testing
./docker-test.sh
```

### Test Coverage

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## 📚 API Documentation

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/ready` | Readiness check |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/api/v1/providers` | List HSM providers |
| `GET` | `/api/v1/providers/{provider}/health` | Provider health |
| `POST` | `/api/v1/keys` | Generate key |
| `GET` | `/api/v1/keys` | List keys |
| `GET` | `/api/v1/keys/{keyId}` | Get key details |
| `POST` | `/api/v1/keys/{keyId}/sign` | Sign data |
| `POST` | `/api/v1/keys/{keyId}/encrypt` | Encrypt data |
| `POST` | `/api/v1/keys/{keyId}/decrypt` | Decrypt data |

### Example API Calls

#### Generate RSA Key
```bash
curl -X POST http://localhost:8080/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "azure-keyvault",
    "key_spec": {
      "key_type": "RSA",
      "key_size": 2048,
      "algorithm": "RS256",
      "usage": ["sign", "verify"]
    },
    "name": "production-signing-key"
  }'
```

#### Sign Data
```bash
curl -X POST http://localhost:8080/api/v1/keys/key-id/sign \
  -H "Content-Type: application/json" \
  -d '{
    "data": "SGVsbG8gS2V5R3JpZCBIU00h",
    "algorithm": "RS256"
  }'
```

## 🔐 Azure KeyVault Integration

### Authentication Methods

1. **Service Principal** (Production)
```bash
export AZURE_KEYVAULT_URL="https://your-vault.vault.azure.net/"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_TENANT_ID="your-tenant-id"
```

2. **Managed Service Identity** (Azure Resources)
```bash
export AZURE_KEYVAULT_URL="https://your-vault.vault.azure.net/"
export AZURE_USE_MSI="true"
```

3. **Azure CLI** (Development)
```bash
az login
export AZURE_KEYVAULT_URL="https://your-vault.vault.azure.net/"
```

### Supported Operations
- ✅ RSA key generation (1024, 2048, 4096-bit)
- ✅ ECDSA key generation (P-256, P-384, P-521)
- ✅ Digital signing (RS256, ES256, ES384, ES512)
- ✅ Signature verification
- ✅ Data encryption/decryption
- ✅ Key wrapping/unwrapping
- ✅ Key lifecycle management

## 📊 Monitoring & Observability

### Prometheus Metrics

KeyGrid HSM exposes comprehensive metrics:

```
# Key operations
keygrid_hsm_key_operations_total{provider, operation, status}
keygrid_hsm_key_operation_duration_seconds{provider, operation}

# Provider health
keygrid_hsm_provider_health_status{provider}
keygrid_hsm_provider_response_time_seconds{provider}

# HTTP metrics
keygrid_hsm_http_requests_total{method, endpoint, status}
keygrid_hsm_http_request_duration_seconds{method, endpoint}
```

### Health Checks

- **Liveness**: `/health` - Basic service health
- **Readiness**: `/ready` - Service readiness including provider health
- **Provider Health**: `/api/v1/providers/{provider}/health` - Individual provider status

### Audit Logging

All cryptographic operations are logged with:
- Timestamp and operation type
- Provider and key information
- Success/failure status
- Error details (if applicable)
- Request duration and metadata

## 🏗️ Architecture

### Component Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HTTP Server   │    │   HSM Manager   │    │ Provider Registry│
│                 │    │                 │    │                 │
│ • REST API      │───▶│ • Orchestration │───▶│ • Provider Mgmt │
│ • Health Checks │    │ • Audit Logging │    │ • Client Factory│
│ • Metrics       │    │ • Metrics       │    │ • Validation    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
            ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
            │Azure KeyVault│ │Custom Storage│ │  Mock HSM   │
            │             │ │             │ │             │
            │• Enterprise │ │• Filesystem │ │• Development│
            │• HSM Backed │ │• Database   │ │• Testing    │
            │• Multi-Auth │ │• Memory     │ │• Scenarios  │
            └─────────────┘ └─────────────┘ └─────────────┘
```

### Provider Architecture

Each HSM provider implements the `HSMProvider` and `HSMClient` interfaces:

```go
type HSMProvider interface {
    Name() string
    Version() string
    Capabilities() []string
    ValidateConfig(config map[string]interface{}) error
    CreateClient(config map[string]interface{}) (HSMClient, error)
}

type HSMClient interface {
    Health(ctx context.Context) (*HealthStatus, error)
    GenerateKey(ctx context.Context, spec KeySpec, name string) (*KeyHandle, error)
    Sign(ctx context.Context, request SigningRequest) (*SigningResponse, error)
    Encrypt(ctx context.Context, request EncryptionRequest) (*EncryptionResponse, error)
    Decrypt(ctx context.Context, request DecryptionRequest) (*DecryptionResponse, error)
    GetPublicKey(ctx context.Context, keyHandle string) (crypto.PublicKey, error)
    ListKeys(ctx context.Context) ([]*KeyHandle, error)
    Close() error
}
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone and setup
git clone https://github.com/jimmytoenners/keygridhsm.git
cd keygridhsm
go mod download

# Run tests
go test ./...

# Run with development config
./server --config=deployments/docker/configs/development.yaml
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the `/docs` directory for detailed guides
- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Join conversations in GitHub Discussions

## 🎯 Roadmap

- [ ] Additional HSM provider integrations (AWS KMS, HashiCorp Vault)
- [ ] Enhanced audit logging with external integrations
- [ ] Web UI for key management and monitoring
- [ ] Advanced key policies and access controls
- [ ] Multi-tenancy support
- [ ] Key backup and disaster recovery

---

**KeyGrid HSM** - Enterprise-grade cryptographic key management made simple. 🔐✨