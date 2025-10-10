# AWS CloudHSM PKCS#11 Integration Guide

## Overview

To make AWS CloudHSM fully production-ready, we need to integrate with the PKCS#11 standard, which is how applications communicate with Hardware Security Modules. This document outlines the complete integration requirements.

## PKCS#11 Architecture

```
KeyGrid HSM Server
      ↓
   Go PKCS#11 Library
      ↓
AWS CloudHSM Client Library (libcloudhsm_pkcs11.so)
      ↓ (Network/SSL)
AWS CloudHSM Cluster (Dedicated Hardware)
```

---

## 1. Prerequisites & Infrastructure

### AWS CloudHSM Cluster Setup
```bash
# 1. Create CloudHSM cluster
aws cloudhsmv2 create-cluster \
    --hsm-type hsm1.medium \
    --subnet-ids subnet-12345678 subnet-87654321

# 2. Create HSM instances
aws cloudhsmv2 create-hsm \
    --cluster-id cluster-123456789abcdef0 \
    --availability-zone us-west-2a

# 3. Initialize cluster (one-time setup)
aws cloudhsmv2 initialize-cluster \
    --cluster-id cluster-123456789abcdef0 \
    --signed-cert file://customerCA.crt \
    --trust-anchor file://customerRoot.crt
```

### Network Setup
```bash
# VPC configuration for CloudHSM access
# - CloudHSM cluster in private subnets
# - KeyGrid server needs network access to HSM cluster
# - Security groups: Port 2223-2225 for HSM communication
```

---

## 2. AWS CloudHSM Client Software

### Installation (Linux/EC2)
```bash
# Install CloudHSM client
sudo yum install cloudhsm-client

# Configure client
sudo /opt/cloudhsm/bin/configure -a <cluster-ip>

# Start cloudhsm client daemon
sudo service cloudhsm-client start

# Verify connectivity
/opt/cloudhsm/bin/cloudhsm_mgmt_util
```

### Client Configuration
```bash
# /opt/cloudhsm/etc/cloudhsm_client.cfg
{
  "libpath": "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
  "slot": 0,
  "library_config": {
    "cluster_id": "cluster-123456789abcdef0"
  }
}
```

---

## 3. Go PKCS#11 Integration

### Required Dependencies
```go
// go.mod additions needed
require (
    github.com/miekg/pkcs11 v1.1.1
    github.com/pkg/errors v0.9.1
)
```

### PKCS#11 Wrapper Structure
```go
// internal/providers/pkcs11/wrapper.go
package pkcs11

import (
    "crypto"
    "github.com/miekg/pkcs11"
)

type CloudHSMPKCS11 struct {
    ctx     *pkcs11.Ctx
    session pkcs11.SessionHandle
    slot    uint
    config  *PKCS11Config
}

type PKCS11Config struct {
    LibraryPath string // "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
    SlotID      uint   // Usually 0 for CloudHSM
    PIN         string // HSM partition password
    TokenLabel  string // CloudHSM partition name
}
```

---

## 4. Core PKCS#11 Operations Implementation

### Session Management
```go
func (p *CloudHSMPKCS11) Initialize() error {
    // Load PKCS#11 library
    p.ctx = pkcs11.New(p.config.LibraryPath)
    if p.ctx == nil {
        return errors.New("failed to load PKCS#11 library")
    }

    // Initialize PKCS#11
    err := p.ctx.Initialize()
    if err != nil {
        return errors.Wrap(err, "failed to initialize PKCS#11")
    }

    // Find HSM slot
    slots, err := p.ctx.GetSlotList(true)
    if err != nil || len(slots) == 0 {
        return errors.New("no HSM slots available")
    }
    p.slot = slots[0] // Use first available slot

    // Open session
    session, err := p.ctx.OpenSession(p.slot, 
        pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
    if err != nil {
        return errors.Wrap(err, "failed to open HSM session")
    }
    p.session = session

    // Login to HSM partition
    err = p.ctx.Login(session, pkcs11.CKU_USER, p.config.PIN)
    if err != nil {
        return errors.Wrap(err, "failed to login to HSM partition")
    }

    return nil
}
```

### Key Generation
```go
func (p *CloudHSMPKCS11) GenerateRSAKeyPair(keySize int, label string) (crypto.PublicKey, string, error) {
    // RSA key generation template
    publicKeyTemplate := []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
        pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
        pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
        pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
        pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
        pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, keySize),
        pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
        pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(label)),
        pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}), // 65537
    }

    privateKeyTemplate := []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
        pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
        pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
        pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
        pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
        pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
        pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
        pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
        pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
        pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(label)),
    }

    // Generate key pair
    publicKey, privateKey, err := p.ctx.GenerateKeyPair(
        p.session,
        []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
        publicKeyTemplate,
        privateKeyTemplate,
    )
    if err != nil {
        return nil, "", errors.Wrap(err, "failed to generate RSA key pair")
    }

    // Extract public key for return
    pubKey, err := p.extractPublicKey(publicKey)
    if err != nil {
        return nil, "", errors.Wrap(err, "failed to extract public key")
    }

    // Return public key and private key handle
    keyHandle := fmt.Sprintf("pkcs11:%d", privateKey)
    return pubKey, keyHandle, nil
}
```

### Digital Signing
```go
func (p *CloudHSMPKCS11) Sign(keyHandle string, digest []byte, mechanism uint) ([]byte, error) {
    // Parse PKCS#11 key handle
    privateKeyHandle, err := parseKeyHandle(keyHandle)
    if err != nil {
        return nil, errors.Wrap(err, "invalid key handle")
    }

    // Initialize signing operation
    err = p.ctx.SignInit(p.session, 
        []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, nil)}, 
        privateKeyHandle)
    if err != nil {
        return nil, errors.Wrap(err, "failed to initialize signing")
    }

    // Perform signing
    signature, err := p.ctx.Sign(p.session, digest)
    if err != nil {
        return nil, errors.Wrap(err, "signing operation failed")
    }

    return signature, nil
}

// Algorithm mapping
func (p *CloudHSMPKCS11) GetSigningMechanism(algorithm string) (uint, error) {
    switch algorithm {
    case "RS256":
        return pkcs11.CKM_RSA_PKCS, nil
    case "RS384":
        return pkcs11.CKM_RSA_PKCS, nil
    case "RS512":
        return pkcs11.CKM_RSA_PKCS, nil
    case "PS256":
        return pkcs11.CKM_RSA_PKCS_PSS, nil
    case "ES256":
        return pkcs11.CKM_ECDSA, nil
    case "ES384":
        return pkcs11.CKM_ECDSA, nil
    default:
        return 0, errors.New("unsupported signing algorithm")
    }
}
```

---

## 5. Integration with CloudHSM Provider

### Updated AWS CloudHSM Provider
```go
// internal/providers/aws_cloudhsm.go (Updated)
import (
    "github.com/jimmy/keygridhsm/internal/providers/pkcs11"
)

type AWSCloudHSMClient struct {
    client    *cloudhsmv2.Client  // For cluster management
    p11       *pkcs11.CloudHSMPKCS11  // For crypto operations
    region    string
    clusterID string
    logger    *logrus.Logger
    config    *AWSCloudHSMConfig
}

func (c *AWSCloudHSMClient) GenerateKey(ctx context.Context, spec models.KeySpec, name string) (*models.KeyHandle, error) {
    // Use PKCS#11 for actual key generation
    switch spec.KeyType {
    case models.KeyTypeRSA:
        publicKey, keyHandle, err := c.p11.GenerateRSAKeyPair(spec.KeySize, name)
        if err != nil {
            return nil, err
        }
        
        return &models.KeyHandle{
            ID:            keyHandle,
            Name:          name,
            KeyType:       spec.KeyType,
            KeySize:       spec.KeySize,
            Algorithm:     spec.Algorithm,
            Usage:         spec.Usage,
            State:         models.KeyStateActive,
            CreatedAt:     time.Now(),
            UpdatedAt:     time.Now(),
            ProviderID:    AWSCloudHSMProviderName,
            ProviderKeyID: keyHandle,
            Metadata: map[string]string{
                "hsm_backed": "true",
                "fips_140_2": "level_3",
                "cluster_id": c.clusterID,
            },
        }, nil
        
    case models.KeyTypeECDSA:
        // Similar implementation for ECDSA
        return c.p11.GenerateECDSAKeyPair(spec.KeySize, name)
    }
}

func (c *AWSCloudHSMClient) Sign(ctx context.Context, request models.SigningRequest) (*models.SigningResponse, error) {
    mechanism, err := c.p11.GetSigningMechanism(request.Algorithm)
    if err != nil {
        return nil, err
    }
    
    signature, err := c.p11.Sign(request.KeyHandle, request.Data, mechanism)
    if err != nil {
        return nil, err
    }
    
    return &models.SigningResponse{
        Signature: signature,
        Algorithm: request.Algorithm,
        KeyID:     request.KeyHandle,
        Metadata: map[string]string{
            "provider":   AWSCloudHSMProviderName,
            "hsm_backed": "true",
        },
    }, nil
}
```

---

## 6. Configuration & Deployment

### Enhanced Configuration
```yaml
providers:
  aws-cloudhsm:
    enabled: true
    config:
      region: "us-west-2"
      cluster_id: "cluster-123456789abcdef0"
      use_instance_role: true
      
      # PKCS#11 specific configuration
      pkcs11:
        library_path: "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
        slot_id: 0
        token_label: "keygrid-partition"
        pin_env: "CLOUDHSM_PIN"  # Environment variable for HSM PIN
```

### Environment Variables
```bash
# HSM Authentication
export CLOUDHSM_PIN="your-hsm-partition-pin"

# AWS Authentication (for cluster management)
export AWS_REGION="us-west-2"
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
```

---

## 7. Error Handling & Recovery

### PKCS#11 Error Mapping
```go
func mapPKCS11Error(err error) *models.HSMError {
    if err == nil {
        return nil
    }
    
    errorString := err.Error()
    
    switch {
    case strings.Contains(errorString, "CKR_PIN_INCORRECT"):
        return models.NewHSMError(models.ErrCodeAuthenticationFailed,
            "HSM PIN incorrect").WithProvider(AWSCloudHSMProviderName)
            
    case strings.Contains(errorString, "CKR_TOKEN_NOT_PRESENT"):
        return models.NewHSMError(models.ErrCodeServiceUnavailable,
            "HSM token not present").WithProvider(AWSCloudHSMProviderName)
            
    case strings.Contains(errorString, "CKR_SESSION_CLOSED"):
        return models.NewHSMError(models.ErrCodeConnectionFailed,
            "HSM session closed, reconnection needed").WithProvider(AWSCloudHSMProviderName)
            
    default:
        return models.NewHSMError(models.ErrCodeUnknown,
            fmt.Sprintf("PKCS#11 error: %s", errorString)).WithProvider(AWSCloudHSMProviderName)
    }
}
```

---

## 8. Testing & Validation

### Unit Tests with Mock PKCS#11
```go
// internal/providers/pkcs11/mock.go
type MockPKCS11 struct {
    keys map[string]crypto.PrivateKey
}

func (m *MockPKCS11) GenerateRSAKeyPair(keySize int, label string) (crypto.PublicKey, string, error) {
    // Generate in-memory key for testing
    privateKey, _ := rsa.GenerateKey(rand.Reader, keySize)
    keyHandle := fmt.Sprintf("mock:%s", label)
    m.keys[keyHandle] = privateKey
    return &privateKey.PublicKey, keyHandle, nil
}
```

### Integration Testing
```bash
# Test with real CloudHSM cluster
go test -tags=integration ./internal/providers/...

# Mock testing (no real HSM needed)
go test ./internal/providers/...
```

---

## 9. Production Deployment Checklist

### Infrastructure Requirements
- [ ] AWS CloudHSM cluster running and initialized
- [ ] VPC connectivity configured
- [ ] Security groups allow HSM communication (ports 2223-2225)
- [ ] HSM partition created and PIN configured

### Software Requirements
- [ ] AWS CloudHSM client software installed
- [ ] PKCS#11 library accessible at expected path
- [ ] Go PKCS#11 bindings integrated
- [ ] HSM client daemon running

### Security Requirements
- [ ] HSM PIN stored securely (environment variable/secrets manager)
- [ ] IAM roles configured for cluster management
- [ ] Network encryption enabled
- [ ] Audit logging configured

### Operational Requirements
- [ ] Health monitoring for HSM connectivity
- [ ] Session management and reconnection logic
- [ ] Backup procedures for key metadata
- [ ] Monitoring for HSM performance and availability

---

## 10. Estimated Development Effort

### Implementation Phases

**Phase 1: PKCS#11 Wrapper (2-3 weeks)**
- Go PKCS#11 library integration
- Session management
- Basic key operations (generate, sign)

**Phase 2: CloudHSM Integration (1-2 weeks)**
- Update CloudHSM provider
- Configuration management
- Error handling

**Phase 3: Testing & Validation (1-2 weeks)**
- Unit tests with mocking
- Integration tests with real HSM
- Performance testing

**Phase 4: Production Hardening (1 week)**
- Error recovery
- Session reconnection
- Health monitoring

**Total Estimated Effort: 5-8 weeks**

---

## Summary

The PKCS#11 integration layer is **technically feasible** but requires:

1. **Infrastructure**: Running AWS CloudHSM cluster
2. **Client Software**: AWS CloudHSM client installed 
3. **Go Integration**: PKCS#11 library bindings
4. **Network Setup**: VPC connectivity to HSM cluster
5. **Security Setup**: HSM partitions and authentication

The current "Framework Ready" implementation gives you 80% of what's needed. The remaining 20% is the PKCS#11 integration layer, which is well-defined but requires the additional infrastructure and client software components.

Would you like me to start implementing any specific part of this PKCS#11 integration?