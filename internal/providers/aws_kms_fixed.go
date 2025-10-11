// Package providers contains HSM provider implementations for various
// backends including AWS KMS, Azure Key Vault, custom storage, and mock HSM.
package providers

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/sirupsen/logrus"

	"github.com/jimmy/keygridhsm/pkg/models"
)

const (
	AWSKMSProviderName    = "aws-kms"
	AWSKMSProviderVersion = "1.0.0"
)

// AWSKMSProvider implements the HSMProvider interface for AWS KMS
type AWSKMSProvider struct {
	logger *logrus.Logger
}

// AWSKMSClient implements the HSMClient interface for AWS KMS
type AWSKMSClient struct {
	client *kms.Client
	region string
	logger *logrus.Logger
	config *AWSKMSConfig
}

// AWSKMSConfig holds configuration for AWS KMS
type AWSKMSConfig struct {
	Region          string `json:"region"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SessionToken    string `json:"session_token,omitempty"`
	Profile         string `json:"profile,omitempty"`
	RoleARN         string `json:"role_arn,omitempty"`
	UseInstanceRole bool   `json:"use_instance_role"`
}

// NewAWSKMSProvider creates a new AWS KMS provider
func NewAWSKMSProvider(logger *logrus.Logger) *AWSKMSProvider {
	if logger == nil {
		logger = logrus.New()
	}

	return &AWSKMSProvider{
		logger: logger,
	}
}

// Provider interface implementation
func (p *AWSKMSProvider) Name() string {
	return AWSKMSProviderName
}

func (p *AWSKMSProvider) Version() string {
	return AWSKMSProviderVersion
}

func (p *AWSKMSProvider) Capabilities() []string {
	return []string{
		"key_generation",
		"signing",
		"encryption",
		"decryption",
		"key_rotation",
		"managed_service",
		"high_availability",
		"enterprise_grade",
		"compliance_ready",
	}
}

func (p *AWSKMSProvider) ValidateConfig(config map[string]interface{}) error {
	awsConfig, err := parseAWSKMSConfig(config)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeInvalidConfig,
			"Invalid AWS KMS configuration", err).
			WithProvider(AWSKMSProviderName)
	}

	if awsConfig.Region == "" {
		return models.NewHSMError(models.ErrCodeInvalidConfig,
			"region is required for AWS KMS provider").
			WithProvider(AWSKMSProviderName)
	}

	return nil
}

func (p *AWSKMSProvider) CreateClient(config map[string]interface{}) (models.HSMClient, error) {
	awsConfig, err := parseAWSKMSConfig(config)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeInvalidConfig,
			"Failed to parse AWS KMS configuration", err).
			WithProvider(AWSKMSProviderName)
	}

	if validationErr := p.ValidateConfig(config); validationErr != nil {
		return nil, validationErr
	}

	// Load AWS configuration
	cfg, err := p.loadAWSConfig(context.Background(), awsConfig)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeAuthenticationFailed,
			"Failed to load AWS configuration", err).
			WithProvider(AWSKMSProviderName)
	}

	// Create KMS client
	client := kms.NewFromConfig(cfg)

	return &AWSKMSClient{
		client: client,
		region: awsConfig.Region,
		logger: p.logger,
		config: awsConfig,
	}, nil
}

func (p *AWSKMSProvider) Initialize(config map[string]interface{}) error {
	// AWS KMS provider doesn't need global initialization
	return nil
}

func (p *AWSKMSProvider) Shutdown() error {
	// AWS KMS provider doesn't need cleanup
	return nil
}

// Client interface implementation
func (c *AWSKMSClient) Health(ctx context.Context) (*models.HealthStatus, error) {
	start := time.Now()

	// Test connection by listing keys (with limit to make it lightweight)
	input := &kms.ListKeysInput{
		Limit: ptrInt32(1),
	}

	_, err := c.client.ListKeys(ctx, input)
	if err != nil {
		return &models.HealthStatus{
			Status:       "unhealthy",
			Provider:     AWSKMSProviderName,
			LastCheck:    time.Now(),
			Error:        err.Error(),
			ResponseTime: time.Since(start),
			Details: map[string]string{
				"region": c.region,
			},
		}, models.NewHSMErrorWithCause(models.ErrCodeServiceUnavailable,
			"AWS KMS health check failed", err).
			WithProvider(AWSKMSProviderName)
	}

	return &models.HealthStatus{
		Status:       "healthy",
		Provider:     AWSKMSProviderName,
		LastCheck:    time.Now(),
		ResponseTime: time.Since(start),
		Details: map[string]string{
			"region": c.region,
		},
	}, nil
}

func (c *AWSKMSClient) GetProviderInfo(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"provider":   AWSKMSProviderName,
		"version":    AWSKMSProviderVersion,
		"region":     c.region,
		"managed":    true,
		"enterprise": true,
		"compliant":  true,
	}, nil
}

func (c *AWSKMSClient) GenerateKey(ctx context.Context, spec models.KeySpec, name string) (*models.KeyHandle, error) {
	// Convert KeyGrid spec to AWS KMS parameters
	keyUsage, keySpec, err := c.convertKeySpecToAWS(spec)
	if err != nil {
		return nil, err
	}

	// Create key parameters
	input := &kms.CreateKeyInput{
		KeyUsage:    keyUsage,
		KeySpec:     keySpec,
		Description: ptrString(fmt.Sprintf("KeyGrid HSM key: %s", name)),
		Tags: []types.Tag{
			{
				TagKey:   ptrString("KeyGrid-Name"),
				TagValue: ptrString(name),
			},
			{
				TagKey:   ptrString("KeyGrid-Type"),
				TagValue: ptrString(string(spec.KeyType)),
			},
			{
				TagKey:   ptrString("KeyGrid-Algorithm"),
				TagValue: ptrString(spec.Algorithm),
			},
		},
	}

	// Generate the key
	result, err := c.client.CreateKey(ctx, input)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyGenerationFailed,
			"Failed to generate key in AWS KMS", err).
			WithProvider(AWSKMSProviderName).
			WithOperation("generate_key").
			WithDetails(map[string]interface{}{
				"key_name": name,
				"key_type": spec.KeyType,
			})
	}

	// Create alias for the key
	aliasName := fmt.Sprintf("alias/keygrid-%s", name)
	aliasInput := &kms.CreateAliasInput{
		AliasName:   ptrString(aliasName),
		TargetKeyId: result.KeyMetadata.KeyId,
	}

	_, err = c.client.CreateAlias(ctx, aliasInput)
	if err != nil {
		c.logger.WithFields(logrus.Fields{
			"key_id": *result.KeyMetadata.KeyId,
			"alias":  aliasName,
			"error":  err,
		}).Warn("Failed to create alias for key, continuing without alias")
	}

	// Convert AWS result to KeyGrid KeyHandle
	keyHandle := &models.KeyHandle{
		ID:            *result.KeyMetadata.KeyId,
		Name:          name,
		KeyType:       spec.KeyType,
		KeySize:       spec.KeySize,
		Algorithm:     spec.Algorithm,
		Usage:         spec.Usage,
		State:         models.KeyStateActive,
		CreatedAt:     *result.KeyMetadata.CreationDate,
		UpdatedAt:     *result.KeyMetadata.CreationDate,
		ProviderID:    AWSKMSProviderName,
		ProviderKeyID: *result.KeyMetadata.KeyId,
		Metadata: map[string]string{
			"region":     c.region,
			"arn":        *result.KeyMetadata.Arn,
			"managed":    "true",
			"key_usage":  string(result.KeyMetadata.KeyUsage),
			"alias":      aliasName,
		},
	}

	c.logger.WithFields(logrus.Fields{
		"key_id":   keyHandle.ID,
		"key_name": name,
		"key_type": spec.KeyType,
		"region":   c.region,
	}).Info("Key generated successfully in AWS KMS")

	return keyHandle, nil
}

func (c *AWSKMSClient) ImportKey(ctx context.Context, keyData []byte, spec models.KeySpec, name string) (*models.KeyHandle, error) {
	// TODO: Implement key import functionality using ImportKeyMaterial API
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"Key import not yet implemented for AWS KMS provider").
		WithProvider(AWSKMSProviderName).
		WithOperation("import_key")
}

func (c *AWSKMSClient) GetKey(ctx context.Context, keyHandle string) (*models.KeyHandle, error) {
	input := &kms.DescribeKeyInput{
		KeyId: ptrString(keyHandle),
	}

	result, err := c.client.DescribeKey(ctx, input)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyNotFound,
			"Failed to get key from AWS KMS", err).
			WithProvider(AWSKMSProviderName).
			WithOperation("get_key").
			WithDetails(map[string]interface{}{
				"key_handle": keyHandle,
			})
	}

	// Convert AWS result to KeyGrid KeyHandle
	keyHandleResult := c.convertAWSKeyToHandle(*result.KeyMetadata)
	return keyHandleResult, nil
}

func (c *AWSKMSClient) ListKeys(ctx context.Context) ([]*models.KeyHandle, error) {
	var keys []*models.KeyHandle

	input := &kms.ListKeysInput{}
	paginator := kms.NewListKeysPaginator(c.client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, models.NewHSMErrorWithCause(models.ErrCodeUnknown,
				"Failed to list keys from AWS KMS", err).
				WithProvider(AWSKMSProviderName).
				WithOperation("list_keys")
		}

		for _, item := range page.Keys {
			// Get full key details
			fullKey, err := c.client.DescribeKey(ctx, &kms.DescribeKeyInput{
				KeyId: item.KeyId,
			})
			if err != nil {
				c.logger.WithFields(logrus.Fields{
					"key_id": *item.KeyId,
					"error":  err,
				}).Warn("Failed to get full key details, skipping")
				continue
			}

			// Only include customer-managed keys
			if fullKey.KeyMetadata.KeyManager == types.KeyManagerTypeCustomer {
				keyHandle := c.convertAWSKeyToHandle(*fullKey.KeyMetadata)
				keys = append(keys, keyHandle)
			}
		}
	}

	return keys, nil
}

func (c *AWSKMSClient) DeleteKey(ctx context.Context, keyHandle string) error {
	input := &kms.ScheduleKeyDeletionInput{
		KeyId:               ptrString(keyHandle),
		PendingWindowInDays: ptrInt32(7), // Minimum allowed by AWS
	}

	_, err := c.client.ScheduleKeyDeletion(ctx, input)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeKeyDeletionFailed,
			"Failed to schedule key deletion in AWS KMS", err).
			WithProvider(AWSKMSProviderName).
			WithOperation("delete_key").
			WithDetails(map[string]interface{}{
				"key_handle": keyHandle,
			})
	}

	return nil
}

func (c *AWSKMSClient) ActivateKey(ctx context.Context, keyHandle string) error {
	input := &kms.EnableKeyInput{
		KeyId: ptrString(keyHandle),
	}

	_, err := c.client.EnableKey(ctx, input)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to activate key in AWS KMS", err).
			WithProvider(AWSKMSProviderName).
			WithOperation("activate_key")
	}

	return nil
}

func (c *AWSKMSClient) DeactivateKey(ctx context.Context, keyHandle string) error {
	input := &kms.DisableKeyInput{
		KeyId: ptrString(keyHandle),
	}

	_, err := c.client.DisableKey(ctx, input)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to deactivate key in AWS KMS", err).
			WithProvider(AWSKMSProviderName).
			WithOperation("deactivate_key")
	}

	return nil
}

func (c *AWSKMSClient) SetKeyExpiration(ctx context.Context, keyHandle string, expiration time.Time) error {
	// AWS KMS doesn't support setting key expiration after creation
	return models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS KMS does not support setting key expiration after creation").
		WithProvider(AWSKMSProviderName).
		WithOperation("set_key_expiration")
}

func (c *AWSKMSClient) GetPublicKey(ctx context.Context, keyHandle string) (crypto.PublicKey, error) {
	input := &kms.GetPublicKeyInput{
		KeyId: ptrString(keyHandle),
	}

	result, err := c.client.GetPublicKey(ctx, input)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyNotFound,
			"Failed to get public key from AWS KMS", err).
			WithProvider(AWSKMSProviderName).
			WithOperation("get_public_key")
	}

	// Parse the DER-encoded public key
	publicKey, err := parsePublicKeyFromDER(result.PublicKey)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to parse public key", err).
			WithProvider(AWSKMSProviderName).
			WithOperation("get_public_key")
	}

	return publicKey, nil
}

func (c *AWSKMSClient) Sign(ctx context.Context, request models.SigningRequest) (*models.SigningResponse, error) {
	// Convert algorithm to AWS KMS signing algorithm
	signingAlgorithm, err := c.convertAlgorithmToAWS(request.Algorithm)
	if err != nil {
		return nil, err
	}

	input := &kms.SignInput{
		KeyId:            ptrString(request.KeyHandle),
		Message:          request.Data,
		SigningAlgorithm: signingAlgorithm,
		MessageType:      types.MessageTypeDigest,
	}

	result, err := c.client.Sign(ctx, input)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeSigningFailed,
			"Failed to sign data with AWS KMS", err).
			WithProvider(AWSKMSProviderName).
			WithOperation("sign").
			WithDetails(map[string]interface{}{
				"key_handle": request.KeyHandle,
				"algorithm":  request.Algorithm,
			})
	}

	return &models.SigningResponse{
		Signature: result.Signature,
		Algorithm: request.Algorithm,
		KeyID:     request.KeyHandle,
		Metadata: map[string]string{
			"provider": AWSKMSProviderName,
			"region":   c.region,
		},
	}, nil
}

func (c *AWSKMSClient) Verify(ctx context.Context, keyHandle string, data, signature []byte, algorithm string) (bool, error) {
	// Convert algorithm to AWS KMS signing algorithm
	signingAlgorithm, err := c.convertAlgorithmToAWS(algorithm)
	if err != nil {
		return false, err
	}

	input := &kms.VerifyInput{
		KeyId:            ptrString(keyHandle),
		Message:          data,
		Signature:        signature,
		SigningAlgorithm: signingAlgorithm,
		MessageType:      types.MessageTypeDigest,
	}

	result, err := c.client.Verify(ctx, input)
	if err != nil {
		return false, models.NewHSMErrorWithCause(models.ErrCodeVerificationFailed,
			"Failed to verify signature with AWS KMS", err).
			WithProvider(AWSKMSProviderName).
			WithOperation("verify")
	}

	return result.SignatureValid, nil
}

func (c *AWSKMSClient) Encrypt(ctx context.Context, request models.EncryptionRequest) (*models.EncryptionResponse, error) {
	input := &kms.EncryptInput{
		KeyId:     ptrString(request.KeyHandle),
		Plaintext: request.Plaintext,
	}

	result, err := c.client.Encrypt(ctx, input)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeEncryptionFailed,
			"Failed to encrypt data with AWS KMS", err).
			WithProvider(AWSKMSProviderName).
			WithOperation("encrypt")
	}

	return &models.EncryptionResponse{
		Ciphertext: result.CiphertextBlob,
		Algorithm:  "AWS-KMS",
		KeyID:      request.KeyHandle,
		Metadata: map[string]string{
			"provider": AWSKMSProviderName,
			"region":   c.region,
		},
	}, nil
}

func (c *AWSKMSClient) Decrypt(ctx context.Context, request models.DecryptionRequest) (*models.DecryptionResponse, error) {
	input := &kms.DecryptInput{
		CiphertextBlob: request.Ciphertext,
		KeyId:          ptrString(request.KeyHandle),
	}

	result, err := c.client.Decrypt(ctx, input)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeDecryptionFailed,
			"Failed to decrypt data with AWS KMS", err).
			WithProvider(AWSKMSProviderName).
			WithOperation("decrypt")
	}

	return &models.DecryptionResponse{
		Plaintext: result.Plaintext,
		Algorithm: "AWS-KMS",
		KeyID:     request.KeyHandle,
		Metadata: map[string]string{
			"provider": AWSKMSProviderName,
			"region":   c.region,
		},
	}, nil
}

func (c *AWSKMSClient) WrapKey(ctx context.Context, request models.KeyWrapRequest) (*models.KeyWrapResponse, error) {
	// AWS KMS uses GenerateDataKey for key wrapping
	input := &kms.GenerateDataKeyInput{
		KeyId:   ptrString(request.KEKHandle),
		KeySpec: types.DataKeySpecAes256,
	}

	result, err := c.client.GenerateDataKey(ctx, input)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to wrap key with AWS KMS", err).
			WithProvider(AWSKMSProviderName).
			WithOperation("wrap_key")
	}

	return &models.KeyWrapResponse{
		WrappedKey: result.CiphertextBlob,
		Algorithm:  request.Algorithm,
		KEKId:      request.KEKHandle,
		Metadata: map[string]string{
			"provider": AWSKMSProviderName,
			"region":   c.region,
		},
	}, nil
}

func (c *AWSKMSClient) UnwrapKey(ctx context.Context, request models.KeyUnwrapRequest) (*models.KeyUnwrapResponse, error) {
	input := &kms.DecryptInput{
		CiphertextBlob: request.WrappedKey,
		KeyId:          ptrString(request.KEKHandle),
	}

	result, err := c.client.Decrypt(ctx, input)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to unwrap key with AWS KMS", err).
			WithProvider(AWSKMSProviderName).
			WithOperation("unwrap_key")
	}

	return &models.KeyUnwrapResponse{
		UnwrappedKey: result.Plaintext,
		Algorithm:    request.Algorithm,
		KEKId:        request.KEKHandle,
		Metadata: map[string]string{
			"provider": AWSKMSProviderName,
			"region":   c.region,
		},
	}, nil
}

func (c *AWSKMSClient) Close() error {
	// AWS KMS client doesn't need explicit closing
	return nil
}

// Helper functions
func (p *AWSKMSProvider) loadAWSConfig(ctx context.Context, awsConfig *AWSKMSConfig) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error

	opts = append(opts, config.WithRegion(awsConfig.Region))

	if awsConfig.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(awsConfig.Profile))
	}

	return config.LoadDefaultConfig(ctx, opts...)
}

func (c *AWSKMSClient) convertKeySpecToAWS(spec models.KeySpec) (types.KeyUsageType, types.KeySpec, error) {
	var keyUsage types.KeyUsageType
	var keySpec types.KeySpec

	// Determine key usage based on KeyGrid usage
	if len(spec.Usage) == 0 {
		keyUsage = types.KeyUsageTypeSignVerify // Default
	} else if containsUsage(spec.Usage, models.KeyUsageSign) || containsUsage(spec.Usage, models.KeyUsageVerify) {
		keyUsage = types.KeyUsageTypeSignVerify
	} else if containsUsage(spec.Usage, models.KeyUsageEncrypt) || containsUsage(spec.Usage, models.KeyUsageDecrypt) {
		keyUsage = types.KeyUsageTypeEncryptDecrypt
	} else {
		keyUsage = types.KeyUsageTypeSignVerify // Default fallback
	}

	// Convert key type and size to AWS key spec
	switch spec.KeyType {
	case models.KeyTypeRSA:
		switch spec.KeySize {
		case 2048:
			keySpec = types.KeySpecRsa2048
		case 3072:
			keySpec = types.KeySpecRsa3072
		case 4096:
			keySpec = types.KeySpecRsa4096
		default:
			return "", "", models.NewHSMError(models.ErrCodeInvalidInput,
				"Unsupported RSA key size for AWS KMS").
				WithProvider(AWSKMSProviderName).
				WithDetails(map[string]interface{}{
					"key_size": spec.KeySize,
				})
		}
	case models.KeyTypeECDSA:
		switch spec.KeySize {
		case 256:
			keySpec = types.KeySpecEccNistP256
		case 384:
			keySpec = types.KeySpecEccNistP384
		case 521:
			keySpec = types.KeySpecEccNistP521
		default:
			return "", "", models.NewHSMError(models.ErrCodeInvalidInput,
				"Unsupported ECDSA key size for AWS KMS").
				WithProvider(AWSKMSProviderName).
				WithDetails(map[string]interface{}{
					"key_size": spec.KeySize,
				})
		}
	default:
		return "", "", models.NewHSMError(models.ErrCodeInvalidInput,
			"Unsupported key type for AWS KMS").
			WithProvider(AWSKMSProviderName).
			WithDetails(map[string]interface{}{
				"key_type": spec.KeyType,
			})
	}

	return keyUsage, keySpec, nil
}

func (c *AWSKMSClient) convertAlgorithmToAWS(algorithm string) (types.SigningAlgorithmSpec, error) {
	switch strings.ToUpper(algorithm) {
	case "RS256":
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
	case "RS384":
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
	case "RS512":
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
	case "PS256":
		return types.SigningAlgorithmSpecRsassaPssSha256, nil
	case "PS384":
		return types.SigningAlgorithmSpecRsassaPssSha384, nil
	case "PS512":
		return types.SigningAlgorithmSpecRsassaPssSha512, nil
	case "ES256":
		return types.SigningAlgorithmSpecEcdsaSha256, nil
	case "ES384":
		return types.SigningAlgorithmSpecEcdsaSha384, nil
	case "ES512":
		return types.SigningAlgorithmSpecEcdsaSha512, nil
	default:
		return "", models.NewHSMError(models.ErrCodeInvalidInput,
			"Unsupported algorithm for AWS KMS").
			WithProvider(AWSKMSProviderName).
			WithDetails(map[string]interface{}{
				"algorithm": algorithm,
			})
	}
}

func (c *AWSKMSClient) convertAWSKeyToHandle(metadata types.KeyMetadata) *models.KeyHandle {
	var keyType models.KeyType
	var keySize int
	var algorithm string

	// Convert AWS key spec to KeyGrid types
	switch metadata.KeySpec {
	case types.KeySpecRsa2048:
		keyType = models.KeyTypeRSA
		keySize = 2048
		algorithm = "RS256"
	case types.KeySpecRsa3072:
		keyType = models.KeyTypeRSA
		keySize = 3072
		algorithm = "RS256"
	case types.KeySpecRsa4096:
		keyType = models.KeyTypeRSA
		keySize = 4096
		algorithm = "RS256"
	case types.KeySpecEccNistP256:
		keyType = models.KeyTypeECDSA
		keySize = 256
		algorithm = "ES256"
	case types.KeySpecEccNistP384:
		keyType = models.KeyTypeECDSA
		keySize = 384
		algorithm = "ES384"
	case types.KeySpecEccNistP521:
		keyType = models.KeyTypeECDSA
		keySize = 521
		algorithm = "ES512"
	default:
		keyType = models.KeyTypeRSA
		keySize = 2048
		algorithm = "RS256"
	}

	var usage []models.KeyUsage
	switch metadata.KeyUsage {
	case types.KeyUsageTypeSignVerify:
		usage = []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify}
	case types.KeyUsageTypeEncryptDecrypt:
		usage = []models.KeyUsage{models.KeyUsageEncrypt, models.KeyUsageDecrypt}
	default:
		usage = []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify}
	}

	var state models.KeyState
	switch metadata.KeyState {
	case types.KeyStateEnabled:
		state = models.KeyStateActive
	case types.KeyStateDisabled:
		state = models.KeyStateInactive
	case types.KeyStatePendingDeletion:
		state = models.KeyStateDestroyed
	default:
		state = models.KeyStateActive
	}

	// Extract name from tags
	name := *metadata.KeyId // Default to key ID
	// Note: In a real implementation, you'd want to lookup tags to get the original name

	return &models.KeyHandle{
		ID:            *metadata.KeyId,
		Name:          name,
		KeyType:       keyType,
		KeySize:       keySize,
		Algorithm:     algorithm,
		Usage:         usage,
		State:         state,
		CreatedAt:     *metadata.CreationDate,
		UpdatedAt:     *metadata.CreationDate,
		ProviderID:    AWSKMSProviderName,
		ProviderKeyID: *metadata.KeyId,
		Metadata: map[string]string{
			"region":      c.region,
			"arn":         *metadata.Arn,
			"managed":     "true",
			"key_usage":   string(metadata.KeyUsage),
			"key_manager": string(metadata.KeyManager),
		},
	}
}

// Utility functions
func parseAWSKMSConfig(config map[string]interface{}) (*AWSKMSConfig, error) {
	awsConfig := &AWSKMSConfig{}

	if region, ok := config["region"].(string); ok {
		awsConfig.Region = region
	}

	if accessKey, ok := config["access_key_id"].(string); ok {
		awsConfig.AccessKeyID = accessKey
	}

	if secretKey, ok := config["secret_access_key"].(string); ok {
		awsConfig.SecretAccessKey = secretKey
	}

	if sessionToken, ok := config["session_token"].(string); ok {
		awsConfig.SessionToken = sessionToken
	}

	if profile, ok := config["profile"].(string); ok {
		awsConfig.Profile = profile
	}

	if roleARN, ok := config["role_arn"].(string); ok {
		awsConfig.RoleARN = roleARN
	}

	if useInstanceRole, ok := config["use_instance_role"].(bool); ok {
		awsConfig.UseInstanceRole = useInstanceRole
	}

	return awsConfig, nil
}

func containsUsage(slice []models.KeyUsage, item models.KeyUsage) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Pointer helper functions
func ptrString(s string) *string {
	return &s
}

func ptrInt32(i int32) *int32 {
	return &i
}

// parsePublicKeyFromDER parses a DER-encoded public key
func parsePublicKeyFromDER(derBytes []byte) (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(derBytes)
}