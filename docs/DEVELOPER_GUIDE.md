# KeyGrid HSM - Developer Guide

This comprehensive guide helps developers integrate and use KeyGrid HSM in their applications.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [API Usage](#api-usage)
5. [Provider Integration](#provider-integration)
6. [Authentication](#authentication)
7. [Error Handling](#error-handling)
8. [Best Practices](#best-practices)
9. [Examples](#examples)
10. [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Run with Docker

```bash
# Using Mock HSM (development)
docker run -p 8080:8080 keygrid-hsm:latest

# Using Azure KeyVault (production)
docker run -p 8080:8080 \
  -e AZURE_KEYVAULT_URL=https://your-keyvault.vault.azure.net/ \
  -e AZURE_CLIENT_ID=your-client-id \
  -e AZURE_CLIENT_SECRET=your-client-secret \
  -e AZURE_TENANT_ID=your-tenant-id \
  keygrid-hsm:latest
```

### 2. Basic API Usage

```bash
# Check health
curl http://localhost:8080/health

# List providers
curl http://localhost:8080/api/v1/providers

# Generate a key
curl -X POST http://localhost:8080/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "mock-hsm",
    "name": "my-test-key",
    "key_spec": {
      "key_type": "RSA",
      "key_size": 2048,
      "key_usage": ["sign", "encrypt"]
    }
  }'
```

## Installation

### Binary Installation

```bash
# Download latest release
wget https://github.com/jimmytoenners/keygridhsm/releases/latest/download/keygrid-hsm-linux-amd64.tar.gz

# Extract and install
tar -xzf keygrid-hsm-linux-amd64.tar.gz
sudo mv keygrid-hsm /usr/local/bin/
sudo chmod +x /usr/local/bin/keygrid-hsm
```

### Docker Installation

```bash
# Pull the image
docker pull keygrid-hsm:latest

# Or build from source
git clone https://github.com/jimmytoenners/keygridhsm.git
cd keygridhsm
make docker-build
```

### Kubernetes Installation

```bash
# Using Helm (recommended)
helm repo add keygrid https://charts.keygrid.com
helm install my-hsm keygrid/keygrid-hsm

# Using kubectl
kubectl apply -f https://raw.githubusercontent.com/jimmytoenners/keygridhsm/main/deployments/kubernetes/
```

## Configuration

KeyGrid HSM supports multiple configuration methods:

### 1. YAML Configuration

Create a `config.yaml` file:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls_enabled: false

providers:
  # Azure KeyVault Provider
  azure-keyvault:
    type: "azure-keyvault"
    enabled: true
    config:
      vault_url: "${AZURE_KEYVAULT_URL}"
      use_system_msi: false
      client_id: "${AZURE_CLIENT_ID}"
      client_secret: "${AZURE_CLIENT_SECRET}"
      tenant_id: "${AZURE_TENANT_ID}"

  # Mock HSM Provider (development)
  mock-hsm:
    type: "mock-hsm"
    enabled: true
    config:
      persistent_storage: false
      simulate_errors: false
      max_keys: 1000

logging:
  level: "info"
  format: "json"
  output: "stdout"

metrics:
  enabled: true
  port: 9091
  prometheus:
    enabled: true

security:
  jwt_auth:
    enabled: false
  rate_limiting:
    enabled: true
    requests_per_second: 100
```

### 2. Environment Variables

All configuration values can be set via environment variables:

```bash
# Server configuration
export KEYGRID_HSM_SERVER_HOST=0.0.0.0
export KEYGRID_HSM_SERVER_PORT=8080

# Azure KeyVault configuration
export AZURE_KEYVAULT_URL=https://your-keyvault.vault.azure.net/
export AZURE_CLIENT_ID=your-client-id
export AZURE_CLIENT_SECRET=your-client-secret
export AZURE_TENANT_ID=your-tenant-id

# Logging
export KEYGRID_HSM_LOG_LEVEL=info
export KEYGRID_HSM_LOG_FORMAT=json
```

### 3. Configuration Precedence

1. Command line flags (highest priority)
2. Environment variables
3. Configuration file
4. Default values (lowest priority)

## API Usage

### Health Checks

```bash
# Basic health check
curl http://localhost:8080/health

# Readiness check (includes provider health)
curl http://localhost:8080/ready

# Prometheus metrics
curl http://localhost:8080/metrics
```

### Provider Management

```bash
# List all providers
curl http://localhost:8080/api/v1/providers

# Get provider info
curl http://localhost:8080/api/v1/providers/azure-keyvault/info

# Check provider health
curl http://localhost:8080/api/v1/providers/azure-keyvault/health
```

### Key Management

```bash
# Generate RSA key
curl -X POST http://localhost:8080/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "azure-keyvault",
    "name": "rsa-signing-key",
    "key_spec": {
      "key_type": "RSA",
      "key_size": 2048,
      "key_usage": ["sign", "verify"]
    },
    "config": {
      "vault_url": "https://your-keyvault.vault.azure.net/"
    }
  }'

# Generate ECDSA key
curl -X POST http://localhost:8080/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "mock-hsm",
    "name": "ecdsa-key",
    "key_spec": {
      "key_type": "ECDSA",
      "curve": "P-256",
      "key_usage": ["sign"]
    }
  }'

# List keys
curl http://localhost:8080/api/v1/keys?provider=azure-keyvault&limit=10

# Get key information
curl http://localhost:8080/api/v1/keys/{key-id}

# Delete key
curl -X DELETE http://localhost:8080/api/v1/keys/{key-id}
```

### Cryptographic Operations

```bash
# Sign data
curl -X POST http://localhost:8080/api/v1/keys/{key-id}/sign \
  -H "Content-Type: application/json" \
  -d '{
    "data": "SGVsbG8gV29ybGQ=",
    "algorithm": "RS256"
  }'

# Verify signature
curl -X POST http://localhost:8080/api/v1/keys/{key-id}/verify \
  -H "Content-Type: application/json" \
  -d '{
    "data": "SGVsbG8gV29ybGQ=",
    "signature": "signature-data-here",
    "algorithm": "RS256"
  }'

# Encrypt data
curl -X POST http://localhost:8080/api/v1/keys/{key-id}/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "data": "U2VjcmV0IG1lc3NhZ2U=",
    "algorithm": "RSA-OAEP"
  }'

# Decrypt data
curl -X POST http://localhost:8080/api/v1/keys/{key-id}/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "encrypted-data-here",
    "algorithm": "RSA-OAEP"
  }'
```

## Provider Integration

### Azure KeyVault

```yaml
providers:
  azure-keyvault:
    type: "azure-keyvault"
    enabled: true
    config:
      vault_url: "https://your-keyvault.vault.azure.net/"
      
      # Option 1: Service Principal Authentication
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      tenant_id: "your-tenant-id"
      
      # Option 2: Managed Service Identity
      # use_system_msi: true
      
      # Option 3: Azure CLI Authentication
      # use_cli: true
```

#### Required Azure Permissions

Your service principal or managed identity needs these Key Vault permissions:

- **Keys**: Get, List, Create, Update, Delete, Sign, Verify, Encrypt, Decrypt
- **Certificates**: Get, List (if using certificate-based keys)

### Custom Storage

```yaml
providers:
  custom-storage:
    type: "custom-storage"
    enabled: true
    config:
      storage_type: "filesystem"  # or "database", "memory"
      encrypt_at_rest: true
      encryption_key: "your-32-byte-encryption-key"
      
      # Filesystem storage
      storage_config:
        base_path: "/var/lib/keygrid-hsm/keys"
        
      # Database storage (PostgreSQL)
      # storage_config:
      #   dsn: "postgres://user:pass@localhost/keygrid_hsm"
      #   table_name: "hsm_keys"
```

### Mock HSM (Development)

```yaml
providers:
  mock-hsm:
    type: "mock-hsm"
    enabled: true
    config:
      persistent_storage: false
      simulate_errors: false
      simulate_latency_ms: 0
      max_keys: 1000
      test_scenarios: []  # ["network-error", "timeout", "rate-limit"]
```

## Authentication

KeyGrid HSM supports multiple authentication methods:

### 1. API Key Authentication

```bash
# Add API key header
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/v1/providers
```

Configuration:
```yaml
security:
  api_key_auth: true
```

### 2. JWT Authentication

```bash
# Add Bearer token
curl -H "Authorization: Bearer your-jwt-token" \
  http://localhost:8080/api/v1/providers
```

Configuration:
```yaml
security:
  jwt_auth:
    enabled: true
    secret: "your-jwt-secret"
    algorithm: "HS256"
    expiration: "24h"
```

### 3. Mutual TLS

Configuration:
```yaml
server:
  tls_enabled: true
  tls_cert_file: "/path/to/server.crt"
  tls_key_file: "/path/to/server.key"

security:
  enable_tls: true
  tls_min_version: "1.2"
```

## Error Handling

KeyGrid HSM provides comprehensive error responses:

### Error Response Format

```json
{
  "error": "Key not found",
  "status": 404,
  "timestamp": "2024-12-09T18:35:45Z",
  "details": "Key with ID '123e4567-e89b-12d3-a456-426614174000' does not exist"
}
```

### Common Error Codes

- `400 Bad Request`: Invalid request format or parameters
- `401 Unauthorized`: Authentication required or failed
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server-side error
- `503 Service Unavailable`: Service temporarily unavailable

### Error Handling in Code

```python
import requests
import json

def create_key(provider, name, key_spec):
    try:
        response = requests.post(
            "http://localhost:8080/api/v1/keys",
            headers={"Content-Type": "application/json"},
            json={
                "provider": provider,
                "name": name,
                "key_spec": key_spec
            }
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        error_data = e.response.json()
        print(f"API Error: {error_data['error']}")
        print(f"Details: {error_data.get('details', 'N/A')}")
        raise
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        raise
```

## Best Practices

### 1. Security

- **Use HTTPS in production** with valid TLS certificates
- **Enable authentication** (JWT or API keys)
- **Implement rate limiting** to prevent abuse
- **Rotate keys regularly** for production workloads
- **Monitor and audit** all cryptographic operations

### 2. High Availability

- **Deploy multiple instances** behind a load balancer
- **Use health checks** for automatic failover
- **Monitor provider health** and implement circuit breakers
- **Configure appropriate timeouts** and retry logic

### 3. Performance

- **Cache public keys** to avoid repeated API calls
- **Use appropriate key sizes** (2048-bit RSA, P-256 ECDSA)
- **Implement connection pooling** for high-throughput scenarios
- **Monitor response times** and set up alerts

### 4. Monitoring

```yaml
# Enable comprehensive monitoring
metrics:
  enabled: true
  prometheus:
    enabled: true

audit:
  enabled: true
  backend: "file"
  config:
    file_path: "/var/log/keygrid-hsm/audit.log"
```

## Examples

### Python Integration

```python
import requests
import base64
import json

class KeyGridHSMClient:
    def __init__(self, base_url, api_key=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        if api_key:
            self.session.headers['X-API-Key'] = api_key
    
    def create_key(self, provider, name, key_type, key_size=2048):
        """Create a new key"""
        payload = {
            "provider": provider,
            "name": name,
            "key_spec": {
                "key_type": key_type,
                "key_size": key_size,
                "key_usage": ["sign", "verify", "encrypt", "decrypt"]
            }
        }
        
        response = self.session.post(
            f"{self.base_url}/api/v1/keys",
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    def sign_data(self, key_id, data, algorithm="RS256"):
        """Sign data with a key"""
        # Encode data as base64
        data_b64 = base64.b64encode(data.encode()).decode()
        
        payload = {
            "data": data_b64,
            "algorithm": algorithm
        }
        
        response = self.session.post(
            f"{self.base_url}/api/v1/keys/{key_id}/sign",
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    def verify_signature(self, key_id, data, signature, algorithm="RS256"):
        """Verify a signature"""
        data_b64 = base64.b64encode(data.encode()).decode()
        
        payload = {
            "data": data_b64,
            "signature": signature,
            "algorithm": algorithm
        }
        
        response = self.session.post(
            f"{self.base_url}/api/v1/keys/{key_id}/verify",
            json=payload
        )
        response.raise_for_status()
        return response.json()

# Usage example
client = KeyGridHSMClient("http://localhost:8080", api_key="your-key")

# Create a key
key_response = client.create_key(
    provider="mock-hsm",
    name="my-signing-key",
    key_type="RSA"
)
key_id = key_response["id"]

# Sign some data
message = "Hello, World!"
sign_response = client.sign_data(key_id, message)
signature = sign_response["signature"]

# Verify the signature
verify_response = client.verify_signature(key_id, message, signature)
print(f"Signature valid: {verify_response['valid']}")
```

### Go Integration

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type HSMClient struct {
    BaseURL string
    APIKey  string
    Client  *http.Client
}

func NewHSMClient(baseURL, apiKey string) *HSMClient {
    return &HSMClient{
        BaseURL: baseURL,
        APIKey:  apiKey,
        Client: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

func (c *HSMClient) CreateKey(provider, name, keyType string, keySize int) (map[string]interface{}, error) {
    payload := map[string]interface{}{
        "provider": provider,
        "name":     name,
        "key_spec": map[string]interface{}{
            "key_type": keyType,
            "key_size": keySize,
            "key_usage": []string{"sign", "verify", "encrypt", "decrypt"},
        },
    }
    
    return c.makeRequest("POST", "/api/v1/keys", payload)
}

func (c *HSMClient) SignData(keyID, data, algorithm string) (map[string]interface{}, error) {
    payload := map[string]interface{}{
        "data":      data,
        "algorithm": algorithm,
    }
    
    return c.makeRequest("POST", fmt.Sprintf("/api/v1/keys/%s/sign", keyID), payload)
}

func (c *HSMClient) makeRequest(method, path string, payload interface{}) (map[string]interface{}, error) {
    var body *bytes.Buffer
    if payload != nil {
        jsonData, err := json.Marshal(payload)
        if err != nil {
            return nil, err
        }
        body = bytes.NewBuffer(jsonData)
    }
    
    req, err := http.NewRequest(method, c.BaseURL+path, body)
    if err != nil {
        return nil, err
    }
    
    if c.APIKey != "" {
        req.Header.Set("X-API-Key", c.APIKey)
    }
    req.Header.Set("Content-Type", "application/json")
    
    resp, err := c.Client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    
    if resp.StatusCode >= 400 {
        return nil, fmt.Errorf("API error: %s", result["error"])
    }
    
    return result, nil
}

func main() {
    client := NewHSMClient("http://localhost:8080", "your-api-key")
    
    // Create a key
    key, err := client.CreateKey("mock-hsm", "test-key", "RSA", 2048)
    if err != nil {
        panic(err)
    }
    
    keyID := key["id"].(string)
    fmt.Printf("Created key: %s\n", keyID)
    
    // Sign data
    signature, err := client.SignData(keyID, "SGVsbG8gV29ybGQ=", "RS256")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Signature: %s\n", signature["signature"])
}
```

## Troubleshooting

### Common Issues

#### 1. Connection Refused

**Problem**: Can't connect to KeyGrid HSM server

**Solutions**:
- Check if the server is running: `curl http://localhost:8080/health`
- Verify the correct port and host configuration
- Check firewall rules and network connectivity

#### 2. Authentication Errors

**Problem**: 401 Unauthorized responses

**Solutions**:
- Verify API key or JWT token is correct
- Check if authentication is properly configured
- Ensure the token hasn't expired

#### 3. Provider Errors

**Problem**: Provider-specific errors (Azure KeyVault, etc.)

**Solutions**:
- Check provider configuration and credentials
- Verify network connectivity to provider
- Check provider health: `curl http://localhost:8080/api/v1/providers/{provider}/health`

#### 4. Key Generation Failures

**Problem**: Keys fail to generate

**Solutions**:
- Verify provider is healthy and accessible
- Check key specification is valid for the provider
- Review audit logs for detailed error information

### Debug Mode

Enable debug logging for troubleshooting:

```yaml
logging:
  level: "debug"
  format: "text"  # More readable for debugging
  output: "stdout"

development:
  enabled: true
  debug_mode: true
```

### Log Analysis

KeyGrid HSM provides structured logging. Key log fields:

- `level`: Log level (debug, info, warn, error)
- `msg`: Log message
- `provider`: HSM provider name
- `operation`: API operation being performed
- `duration`: Operation duration
- `error`: Error details (if any)

### Health Monitoring

Set up monitoring for these endpoints:

- `/health`: Basic service health
- `/ready`: Readiness for traffic (includes provider health)
- `/metrics`: Prometheus metrics for detailed monitoring

### Support

For additional support:

1. Check the [GitHub Issues](https://github.com/jimmytoenners/keygridhsm/issues)
2. Review the [API documentation](./openapi.yaml)
3. Enable debug logging and check audit logs
4. Contact support at support@keygrid.com

---

**Next Steps**: 
- Try the [Quick Start](#quick-start) examples
- Review the [OpenAPI specification](./openapi.yaml) for complete API details
- Check out example configurations in the `/config` directory