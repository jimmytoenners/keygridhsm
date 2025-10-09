# KeyGrid HSM Security Guide

This document provides comprehensive security guidance for deploying and operating KeyGrid HSM in production environments.

## Table of Contents

1. [Security Overview](#security-overview)
2. [Architecture Security](#architecture-security)
3. [Authentication & Authorization](#authentication--authorization)
4. [Network Security](#network-security)
5. [Container Security](#container-security)
6. [Configuration Security](#configuration-security)
7. [Monitoring & Auditing](#monitoring--auditing)
8. [Incident Response](#incident-response)
9. [Compliance](#compliance)
10. [Security Checklist](#security-checklist)

## Security Overview

KeyGrid HSM implements multiple layers of security to protect cryptographic keys and operations:

- **Defense in Depth**: Multiple security controls at different layers
- **Zero Trust Architecture**: No implicit trust, verify everything
- **Principle of Least Privilege**: Minimal required permissions
- **Secure by Default**: Security-first configuration defaults

### Threat Model

KeyGrid HSM is designed to protect against:

- **External Attackers**: Unauthorized access attempts
- **Insider Threats**: Malicious internal users
- **Data Breaches**: Exposure of sensitive cryptographic material
- **Service Disruption**: Denial of service attacks
- **Supply Chain Attacks**: Compromised dependencies

## Architecture Security

### Component Isolation

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │    │   API Gateway   │    │  KeyGrid HSM    │
│                 │    │                 │    │                 │
│  • TLS Term     │───▶│  • Rate Limit   │───▶│  • Crypto Ops   │
│  • WAF          │    │  • AuthN/AuthZ  │    │  • Audit Log    │
│  • DDoS Protect│    │  • Request Log  │    │  • Provider Mgmt│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Provider Security

Each HSM provider implements specific security measures:

#### Azure KeyVault
- Hardware Security Module (FIPS 140-2 Level 2)
- Azure Active Directory integration
- Network isolation (VNet/Private Endpoints)
- Audit logging and monitoring

#### Custom Storage
- Encryption at rest (AES-256)
- Secure key derivation (PBKDF2/Argon2)
- Access control lists
- Tamper detection

#### Mock HSM
- Development use only
- No production deployment
- Test scenario simulation

## Authentication & Authorization

### Authentication Methods

#### 1. API Key Authentication

```yaml
security:
  api_key_auth: true
  api_keys:
    - name: "service-account-1"
      key: "ak_1234567890abcdef"
      permissions: ["read", "write"]
    - name: "monitoring"
      key: "ak_monitoring_readonly"
      permissions: ["read"]
```

**Implementation:**
```http
GET /api/v1/keys
X-API-Key: ak_1234567890abcdef
```

#### 2. JWT Authentication

```yaml
security:
  jwt_auth:
    enabled: true
    secret: "${JWT_SECRET}"
    algorithm: "RS256"  # Use RS256 for production
    expiration: "1h"
    issuer: "keygrid-hsm"
    audience: "keygrid-api"
```

**Token Structure:**
```json
{
  "iss": "keygrid-hsm",
  "aud": "keygrid-api",
  "sub": "user@example.com",
  "exp": 1640995200,
  "iat": 1640991600,
  "permissions": ["read", "write"],
  "provider_access": ["azure-keyvault", "mock-hsm"]
}
```

#### 3. Mutual TLS (mTLS)

```yaml
server:
  tls_enabled: true
  tls_cert_file: "/etc/ssl/certs/server.crt"
  tls_key_file: "/etc/ssl/private/server.key"
  client_ca_file: "/etc/ssl/ca/client-ca.crt"
  require_client_cert: true
```

### Authorization Framework

```go
type Permission struct {
    Resource string   // "keys", "providers", "health"
    Action   string   // "read", "write", "delete", "admin"
    Provider string   // "azure-keyvault", "mock-hsm", "*"
}

type Role struct {
    Name        string
    Permissions []Permission
}

// Example roles
var DefaultRoles = map[string]Role{
    "viewer": {
        Name: "viewer",
        Permissions: []Permission{
            {Resource: "keys", Action: "read", Provider: "*"},
            {Resource: "providers", Action: "read", Provider: "*"},
            {Resource: "health", Action: "read", Provider: "*"},
        },
    },
    "operator": {
        Name: "operator",
        Permissions: []Permission{
            {Resource: "keys", Action: "*", Provider: "*"},
            {Resource: "providers", Action: "read", Provider: "*"},
        },
    },
    "admin": {
        Name: "admin",
        Permissions: []Permission{
            {Resource: "*", Action: "*", Provider: "*"},
        },
    },
}
```

## Network Security

### TLS Configuration

**Production TLS Settings:**
```yaml
server:
  tls_enabled: true
  tls_cert_file: "/etc/ssl/certs/keygrid-hsm.crt"
  tls_key_file: "/etc/ssl/private/keygrid-hsm.key"

security:
  enable_tls: true
  tls_min_version: "1.2"
  tls_cipher_suites:
    - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    - "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
    - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
  tls_prefer_server_ciphers: true
```

**Certificate Management:**
```bash
# Generate CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout keygrid-hsm.key \
  -out keygrid-hsm.csr \
  -subj "/CN=keygrid-hsm.example.com"

# Set proper permissions
chmod 600 keygrid-hsm.key
chmod 644 keygrid-hsm.crt
```

### Firewall Rules

**Inbound Rules:**
```bash
# Allow HTTPS only
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow metrics (internal only)
iptables -A INPUT -p tcp --dport 9091 -s 10.0.0.0/8 -j ACCEPT

# Allow health checks (load balancer)
iptables -A INPUT -p tcp --dport 8080 -s 10.0.1.0/24 -j ACCEPT

# Drop all other traffic
iptables -A INPUT -j DROP
```

### Network Segmentation

```
┌─────────────────────────────────────────────────────────┐
│                    DMZ Network                          │
│  ┌─────────────┐    ┌─────────────┐                    │
│  │Load Balancer│    │   WAF/Proxy │                    │
│  │10.0.1.10    │    │10.0.1.20    │                    │
│  └─────────────┘    └─────────────┘                    │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────┐
│                App Network                              │
│  ┌─────────────┐    ┌─────────────┐                    │
│  │KeyGrid HSM  │    │KeyGrid HSM  │                    │
│  │10.0.2.10    │    │10.0.2.20    │                    │
│  └─────────────┘    └─────────────┘                    │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────┐
│                Data Network                             │
│  ┌─────────────┐    ┌─────────────┐                    │
│  │   Database  │    │  Azure KV   │                    │
│  │10.0.3.10    │    │  Endpoint   │                    │
│  └─────────────┘    └─────────────┘                    │
└─────────────────────────────────────────────────────────┘
```

## Container Security

### Docker Hardening

**Dockerfile Security Best Practices:**
```dockerfile
# Use minimal base image
FROM gcr.io/distroless/base-debian11

# Create non-root user
RUN useradd -r -u 1000 -s /bin/false keygrid

# Copy binary only
COPY --from=builder /app/keygrid-hsm /usr/local/bin/

# Set security labels
LABEL \
  org.opencontainers.image.title="KeyGrid HSM" \
  org.opencontainers.image.description="Enterprise Hardware Security Module" \
  org.opencontainers.image.vendor="KeyGrid Security" \
  security.scan="enabled"

# Run as non-root
USER 1000:1000

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/keygrid-hsm"]
```

**Runtime Security:**
```bash
# Run with security options
docker run -d \
  --name keygrid-hsm \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --security-opt=no-new-privileges:true \
  --security-opt=apparmor:docker-default \
  --user 1000:1000 \
  -p 443:8080 \
  keygrid-hsm:latest
```

### Kubernetes Security

**Security Context:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keygrid-hsm
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: keygrid-hsm
        image: keygrid-hsm:latest
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
        resources:
          limits:
            cpu: 500m
            memory: 256Mi
          requests:
            cpu: 100m
            memory: 128Mi
```

**Network Policies:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: keygrid-hsm-policy
spec:
  podSelector:
    matchLabels:
      app: keygrid-hsm
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-system
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 443  # HTTPS outbound
    - protocol: TCP
      port: 53   # DNS
    - protocol: UDP
      port: 53   # DNS
```

## Configuration Security

### Secrets Management

**Environment Variables:**
```bash
# Never store secrets in plain text
export KEYGRID_HSM_JWT_SECRET="$(openssl rand -base64 32)"
export AZURE_CLIENT_SECRET="$(az keyvault secret show --vault-name secrets --name client-secret --query value -o tsv)"
```

**Kubernetes Secrets:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: keygrid-hsm-secrets
type: Opaque
data:
  jwt-secret: <base64-encoded-secret>
  azure-client-secret: <base64-encoded-secret>
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: keygrid-hsm
        env:
        - name: KEYGRID_HSM_JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: keygrid-hsm-secrets
              key: jwt-secret
```

**HashiCorp Vault Integration:**
```bash
# Store secrets in Vault
vault kv put secret/keygrid-hsm \
  jwt_secret="$(openssl rand -base64 32)" \
  azure_client_secret="$AZURE_CLIENT_SECRET"

# Retrieve at runtime
export KEYGRID_HSM_JWT_SECRET="$(vault kv get -field=jwt_secret secret/keygrid-hsm)"
```

### Configuration Validation

```yaml
# config/production.yaml
server:
  host: "*******"  # Bind to all interfaces in container
  port: 8080
  tls_enabled: true  # REQUIRED in production

security:
  jwt_auth:
    enabled: true    # REQUIRED
    algorithm: "RS256"  # Use asymmetric for production
  rate_limiting:
    enabled: true    # REQUIRED
    requests_per_second: 1000
    burst_size: 2000
  cors:
    enabled: false   # Disable unless needed

logging:
  level: "info"      # Never use "debug" in production
  format: "json"     # Structured logging
  output: "stdout"   # For container log aggregation

development:
  enabled: false     # MUST be false in production
  debug_mode: false  # MUST be false in production
```

## Monitoring & Auditing

### Audit Logging

**Audit Events:**
```json
{
  "id": "audit-123456789",
  "timestamp": "2024-12-09T18:35:45Z",
  "event_type": "key_generated",
  "user_id": "service-account-1",
  "session_id": "sess-abcdef123456",
  "source_ip": "10.0.2.15",
  "user_agent": "KeyGrid-CLI/1.0.0",
  "provider": "azure-keyvault",
  "resource_id": "key-123e4567-e89b-12d3-a456-426614174000",
  "action": "generate_key",
  "result": "success",
  "metadata": {
    "key_type": "RSA",
    "key_size": 2048,
    "key_usage": ["sign", "verify"]
  },
  "risk_score": 2
}
```

**Audit Configuration:**
```yaml
audit:
  enabled: true
  buffer_size: 10000
  flush_interval: "5s"
  backend: "elasticsearch"
  config:
    endpoints: ["https://elastic.example.com:9200"]
    index: "keygrid-audit"
    username: "${ELASTIC_USERNAME}"
    password: "${ELASTIC_PASSWORD}"
```

### Metrics & Monitoring

**Key Metrics:**
```yaml
metrics:
  enabled: true
  prometheus:
    enabled: true
    namespace: "keygrid"
    subsystem: "hsm"
    
# Example metrics
keygrid_hsm_requests_total{method="POST",endpoint="/api/v1/keys",status="200"} 1234
keygrid_hsm_request_duration_seconds{method="POST",endpoint="/api/v1/keys"} 0.025
keygrid_hsm_keys_total{provider="azure-keyvault",type="RSA"} 156
keygrid_hsm_provider_health{provider="azure-keyvault"} 1
keygrid_hsm_auth_failures_total{reason="invalid_token"} 5
```

**Alerting Rules:**
```yaml
# Prometheus alerting rules
groups:
- name: keygrid-hsm
  rules:
  - alert: HighErrorRate
    expr: rate(keygrid_hsm_requests_total{status=~"5.."}[5m]) > 0.1
    for: 2m
    annotations:
      summary: "High error rate detected"
      
  - alert: AuthenticationFailures
    expr: rate(keygrid_hsm_auth_failures_total[5m]) > 0.5
    for: 1m
    annotations:
      summary: "Multiple authentication failures"
      
  - alert: ProviderDown
    expr: keygrid_hsm_provider_health == 0
    for: 30s
    annotations:
      summary: "HSM provider is unhealthy"
```

### SIEM Integration

**Log Forwarding:**
```yaml
logging:
  output: "file"
  file_path: "/var/log/keygrid-hsm/app.log"
  
# Fluent Bit configuration
[INPUT]
    Name tail
    Path /var/log/keygrid-hsm/*.log
    Tag keygrid-hsm
    Parser json
    
[FILTER]
    Name modify
    Match keygrid-hsm
    Add source keygrid-hsm
    Add environment production
    
[OUTPUT]
    Name es
    Match *
    Host elasticsearch.security.internal
    Port 9200
    Index keygrid-logs
    Type _doc
    tls On
    tls.verify Off
```

## Incident Response

### Security Incident Types

1. **Unauthorized Access**
   - Failed authentication attempts
   - Privilege escalation
   - Suspicious API usage

2. **Data Breach**
   - Key material exposure
   - Configuration data leak
   - Audit log tampering

3. **Service Disruption**
   - DDoS attacks
   - Resource exhaustion
   - Provider outages

### Response Procedures

#### 1. Immediate Response (0-15 minutes)
```bash
# Identify the incident
tail -f /var/log/keygrid-hsm/audit.log | grep "CRITICAL\|ERROR"

# Isolate affected systems
kubectl scale deployment keygrid-hsm --replicas=0

# Preserve evidence
cp -r /var/log/keygrid-hsm /tmp/incident-$(date +%Y%m%d-%H%M%S)
```

#### 2. Assessment (15-60 minutes)
- Determine scope and impact
- Identify root cause
- Document timeline
- Notify stakeholders

#### 3. Containment (1-4 hours)
```bash
# Rotate compromised credentials
kubectl delete secret keygrid-hsm-secrets
kubectl create secret generic keygrid-hsm-secrets \
  --from-literal=jwt-secret="$(openssl rand -base64 32)"

# Update firewall rules
iptables -A INPUT -s <attacker-ip> -j DROP

# Scale up clean instances
kubectl scale deployment keygrid-hsm --replicas=3
```

#### 4. Recovery & Lessons Learned
- Restore normal operations
- Implement additional controls
- Update incident response plan
- Conduct post-incident review

### Emergency Contacts

```yaml
incident_response:
  team:
    - name: "Security Team"
      email: "security@example.com"
      phone: "+1-555-0123"
      role: "primary"
    - name: "DevOps Team"
      email: "devops@example.com"
      phone: "+1-555-0124"
      role: "technical"
    - name: "Management"
      email: "ciso@example.com"
      phone: "+1-555-0125"
      role: "escalation"
```

## Compliance

### Regulatory Frameworks

#### SOC 2 Type II
**Control Objectives:**
- Security: Logical and physical access controls
- Availability: System availability for operation and use
- Processing Integrity: System processing is complete, accurate, timely
- Confidentiality: Information designated as confidential is protected
- Privacy: Personal information is collected, used, retained, disclosed

**Implementation:**
```yaml
compliance:
  soc2:
    enabled: true
    controls:
      - id: "CC6.1"
        description: "Logical and physical access controls"
        implementation: "Multi-factor authentication, role-based access"
      - id: "CC7.1"
        description: "System monitoring"
        implementation: "Comprehensive logging, real-time monitoring"
```

#### FIPS 140-2
**Requirements:**
- Cryptographic module specification
- Cryptographic module ports and interfaces
- Roles, services, and authentication
- Finite state machine
- Physical security
- Operational environment
- Cryptographic key management
- EMI/EMC
- Self-tests
- Design assurance
- Mitigation of other attacks

**Azure KeyVault Compliance:**
- FIPS 140-2 Level 2 validated HSMs
- Hardware-based key storage
- Tamper evidence and response

### Data Protection

#### GDPR Compliance
```yaml
data_protection:
  gdpr:
    enabled: true
    data_controller: "Example Corp"
    data_protection_officer: "dpo@example.com"
    lawful_basis: "legitimate_interest"
    retention_period: "7_years"
    
  data_types:
    - type: "audit_logs"
      contains_pii: false
      retention: "7_years"
    - type: "user_sessions"
      contains_pii: true
      retention: "30_days"
    - type: "error_logs"
      contains_pii: false
      retention: "1_year"
```

## Security Checklist

### Pre-Deployment

- [ ] Security architecture review completed
- [ ] Threat model documented and reviewed
- [ ] Security controls implemented and tested
- [ ] Penetration testing performed
- [ ] Security documentation complete

### Deployment

- [ ] TLS enabled with valid certificates
- [ ] Authentication configured and tested
- [ ] Authorization policies implemented
- [ ] Rate limiting configured
- [ ] Audit logging enabled
- [ ] Monitoring and alerting configured
- [ ] Secrets properly managed
- [ ] Network security implemented
- [ ] Container security hardening applied

### Post-Deployment

- [ ] Security monitoring operational
- [ ] Incident response procedures tested
- [ ] Regular security assessments scheduled
- [ ] Compliance audits planned
- [ ] Security training completed
- [ ] Vulnerability management process active

### Ongoing Maintenance

- [ ] Regular security updates applied
- [ ] Certificates rotated before expiration
- [ ] Access reviews conducted quarterly
- [ ] Security logs reviewed regularly
- [ ] Incident response plan updated
- [ ] Compliance reporting current
- [ ] Security metrics tracked and analyzed

---

## Support and Updates

This security guide is maintained alongside the KeyGrid HSM project. For security-related questions or to report vulnerabilities:

- **Security Email**: security@keygrid.com
- **PGP Key**: Available at https://keygrid.com/pgp
- **Security Advisories**: https://github.com/jimmytoenners/keygridhsm/security/advisories

**Last Updated**: December 2024  
**Next Review**: March 2025