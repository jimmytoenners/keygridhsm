# AWS KMS Quick Start Guide for KeyGrid HSM

## 🚀 **AWS KMS is Production Ready!**

AWS KMS provider is fully implemented and ready for immediate deployment. This guide shows you how to get started in minutes.

---

## Prerequisites

- ✅ AWS Account with KMS permissions
- ✅ AWS credentials configured (IAM role, access keys, or AWS CLI)
- ✅ KeyGrid HSM server (already includes AWS KMS provider)

---

## 1. AWS Setup (5 minutes)

### Option A: Use AWS CLI (Recommended)
```bash
# Configure AWS CLI with your credentials
aws configure
# AWS Access Key ID: [Your Access Key]
# AWS Secret Access Key: [Your Secret Key] 
# Default region: us-west-2
# Default output format: json

# Test connectivity
aws kms list-keys --region us-west-2
```

### Option B: Use Environment Variables
```bash
# Set AWS credentials
export AWS_REGION="us-west-2"
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

# Optional: For temporary credentials
export AWS_SESSION_TOKEN="..."
```

### Option C: Use IAM Role (EC2/EKS)
```bash
# If running on EC2/EKS, just set region
export AWS_REGION="us-west-2"
# IAM role will be used automatically
```

---

## 2. KeyGrid Configuration (2 minutes)

### Update Configuration File
```yaml
# config.yaml or production.yaml
providers:
  # Enable AWS KMS provider
  aws-kms:
    enabled: true
    config:
      region: "us-west-2"  # Your preferred AWS region
      
      # Authentication options (choose one):
      # Option 1: Use AWS CLI profile
      profile: "default"
      
      # Option 2: Use environment variables (no additional config needed)
      
      # Option 3: Use explicit credentials (not recommended for production)
      # access_key_id: "AKIA..."
      # secret_access_key: "..."
      
      # Option 4: Use EC2 instance role
      # use_instance_role: true

  # Keep other providers as needed
  mock-hsm:
    enabled: true  # For testing alongside AWS KMS
    config:
      persistent_storage: false
```

---

## 3. Start KeyGrid HSM (1 minute)

```bash
# Start the server
./keygrid-hsm -config config.yaml

# You should see:
# INFO[0000] Starting KeyGrid HSM Server
# INFO[0000] Registered provider: aws-kms (v1.0.0)
# INFO[0000] AWS KMS provider initialized successfully
# INFO[0000] Server listening on :8080
```

---

## 4. Test AWS KMS Integration (2 minutes)

### Health Check
```bash
# Check if AWS KMS is healthy
curl http://localhost:8080/health

# Expected response:
{
  "status": "healthy",
  "providers": {
    "aws-kms": {
      "status": "healthy",
      "provider": "aws-kms",
      "response_time": "145ms",
      "details": {
        "region": "us-west-2"
      }
    }
  }
}
```

### Generate Your First Key
```bash
# Create an RSA key in AWS KMS
curl -X POST http://localhost:8080/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws-kms",
    "key_spec": {
      "key_type": "RSA",
      "key_size": 2048,
      "algorithm": "RS256",
      "usage": ["sign", "verify"]
    },
    "name": "my-first-aws-key"
  }'

# Expected response:
{
  "id": "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
  "name": "my-first-aws-key",
  "key_type": "RSA",
  "key_size": 2048,
  "algorithm": "RS256",
  "state": "active",
  "provider_id": "aws-kms",
  "metadata": {
    "region": "us-west-2",
    "arn": "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
    "managed": "true"
  }
}
```

### Sign Data with AWS KMS
```bash
# Sign some data (base64 encoded)
curl -X POST "http://localhost:8080/api/v1/keys/{KEY_ID}/sign" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "SGVsbG8gV29ybGQ=",
    "algorithm": "RS256"
  }'

# Expected response:
{
  "signature": "base64-encoded-signature...",
  "algorithm": "RS256",
  "key_id": "arn:aws:kms:us-west-2:123456789012:key/...",
  "metadata": {
    "provider": "aws-kms",
    "region": "us-west-2"
  }
}
```

---

## 5. Production Deployment

### Docker Deployment
```yaml
# docker-compose.yml
version: '3.8'
services:
  keygrid-hsm:
    image: keygrid-hsm:latest
    environment:
      - AWS_REGION=us-west-2
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
    volumes:
      - ./production.yaml:/etc/keygrid-hsm/config.yaml
    ports:
      - "8080:8080"
```

### Kubernetes Deployment
```yaml
# kubernetes-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keygrid-hsm
spec:
  replicas: 3
  selector:
    matchLabels:
      app: keygrid-hsm
  template:
    metadata:
      labels:
        app: keygrid-hsm
    spec:
      serviceAccount: keygrid-hsm  # With IAM role binding
      containers:
      - name: keygrid-hsm
        image: keygrid-hsm:latest
        env:
        - name: AWS_REGION
          value: "us-west-2"
        ports:
        - containerPort: 8080
```

---

## 6. AWS KMS Best Practices

### IAM Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:CreateKey",
        "kms:CreateAlias",
        "kms:DescribeKey",
        "kms:ListKeys",
        "kms:GetPublicKey",
        "kms:Sign",
        "kms:Verify",
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:EnableKey",
        "kms:DisableKey",
        "kms:ScheduleKeyDeletion"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:Via": "kms.us-west-2.amazonaws.com"
        }
      }
    }
  ]
}
```

### Security Recommendations
- ✅ Use IAM roles instead of access keys when possible
- ✅ Enable AWS CloudTrail for audit logging
- ✅ Use resource-based policies for fine-grained access control
- ✅ Enable key rotation for long-term keys
- ✅ Use least-privilege IAM policies

### Cost Optimization
- ✅ Use key aliases for easier management
- ✅ Monitor key usage with CloudWatch metrics
- ✅ Delete unused keys (after scheduling deletion period)
- ✅ Use appropriate key types for your use case

---

## 7. Supported Operations

### ✅ **Key Management**
- Key generation (RSA 2048/3072/4096, ECDSA P-256/P-384/P-521)
- Key listing and metadata retrieval
- Key activation/deactivation
- Key deletion scheduling

### ✅ **Cryptographic Operations**
- Digital signing (RS256, RS384, RS512, PS256, PS384, PS512)
- ECDSA signing (ES256, ES384, ES512)
- Signature verification
- Encryption/decryption
- Key wrapping/unwrapping

### ✅ **Enterprise Features**
- Multi-region support
- High availability (99.999% SLA)
- Automatic key rotation
- CloudTrail audit logging
- Cost-effective pay-per-use pricing

---

## 8. Troubleshooting

### Common Issues

**❌ "AWS KMS health check failed"**
```bash
# Check AWS credentials
aws kms list-keys --region us-west-2

# Verify IAM permissions
aws iam get-user
```

**❌ "region is required for AWS KMS provider"**
```yaml
# Ensure region is specified in config
providers:
  aws-kms:
    config:
      region: "us-west-2"  # Required!
```

**❌ "Failed to load AWS configuration"**
```bash
# Set up AWS credentials properly
aws configure
# Or use environment variables
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
```

### Debug Mode
```bash
# Start with debug logging
./keygrid-hsm -config config.yaml -log-level debug

# Check specific provider health
curl http://localhost:8080/api/v1/providers/aws-kms/health
```

---

## 9. Next Steps

### ✅ **You're Ready for Production!**
With AWS KMS integration, you now have:
- Enterprise-grade HSM capabilities
- Scalable key management
- High availability and compliance
- Cost-effective managed service

### 🔮 **Future Enhancements**
- **AWS CloudHSM**: Framework ready, PKCS#11 integration planned
- **Multi-Cloud**: Azure KeyVault already supported
- **Advanced Features**: Cross-region key replication, custom key policies

### 📚 **Additional Resources**
- [AWS KMS Developer Guide](https://docs.aws.amazon.com/kms/)
- [KeyGrid HSM OpenAPI Spec](../openapi.yaml)
- [Enterprise Security Documentation](../SECURITY.md)

---

## Success! 🎉

You now have a production-ready HSM service with AWS KMS integration. Your KeyGrid HSM server can:

- ✅ Generate cryptographic keys in AWS KMS
- ✅ Sign and verify data using hardware-backed keys  
- ✅ Scale to handle enterprise workloads
- ✅ Provide audit logging and compliance features
- ✅ Support multiple AWS regions and availability zones

**Total setup time: ~10 minutes** ⚡