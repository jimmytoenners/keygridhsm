// Package providers contains HSM provider implementations for various
// backends including Azure Key Vault, custom storage, and mock HSM.
package providers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/sirupsen/logrus"

	"github.com/jimmy/keygridhsm/pkg/models"
)

const (
	AzureKeyVaultProviderName    = "azure-keyvault"
	AzureKeyVaultProviderVersion = "1.0.0"
)

// AzureKeyVaultProvider implements the HSMProvider interface for Azure Key Vault
type AzureKeyVaultProvider struct {
	logger *logrus.Logger
}

// AzureKeyVaultClient implements the HSMClient interface for Azure Key Vault
type AzureKeyVaultClient struct {
	client   *azkeys.Client
	vaultURL string
	logger   *logrus.Logger
	config   *AzureKeyVaultConfig
}

// AzureKeyVaultConfig holds configuration for Azure Key Vault
type AzureKeyVaultConfig struct {
	VaultURL     string `json:"vault_url"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
	UseSystemMSI bool   `json:"use_system_msi"`
	UseCLI       bool   `json:"use_cli"`
}

// NewAzureKeyVaultProvider creates a new Azure Key Vault provider
func NewAzureKeyVaultProvider(logger *logrus.Logger) *AzureKeyVaultProvider {
	if logger == nil {
		logger = logrus.New()
	}

	return &AzureKeyVaultProvider{
		logger: logger,
	}
}

// Provider interface implementation
func (p *AzureKeyVaultProvider) Name() string {
	return AzureKeyVaultProviderName
}

func (p *AzureKeyVaultProvider) Version() string {
	return AzureKeyVaultProviderVersion
}

func (p *AzureKeyVaultProvider) Capabilities() []string {
	return []string{
		"key_generation",
		"key_import",
		"signing",
		"encryption",
		"decryption",
		"key_wrapping",
		"key_unwrapping",
		"hsm_backed",
		"high_availability",
		"enterprise_grade",
	}
}

func (p *AzureKeyVaultProvider) ValidateConfig(config map[string]interface{}) error {
	azConfig, err := parseAzureConfig(config)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeInvalidConfig,
			"Invalid Azure Key Vault configuration", err).
			WithProvider(AzureKeyVaultProviderName)
	}

	if azConfig.VaultURL == "" {
		return models.NewHSMError(models.ErrCodeInvalidConfig,
			"vault_url is required for Azure Key Vault provider").
			WithProvider(AzureKeyVaultProviderName)
	}

	if !azConfig.UseSystemMSI && !azConfig.UseCLI &&
		(azConfig.ClientID == "" || azConfig.ClientSecret == "" || azConfig.TenantID == "") {
		return models.NewHSMError(models.ErrCodeInvalidConfig,
			"Either use_system_msi/use_cli must be true or client_id, client_secret, and tenant_id must be provided").
			WithProvider(AzureKeyVaultProviderName)
	}

	return nil
}

func (p *AzureKeyVaultProvider) CreateClient(config map[string]interface{}) (models.HSMClient, error) {
	azConfig, err := parseAzureConfig(config)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeInvalidConfig,
			"Failed to parse Azure Key Vault configuration", err).
			WithProvider(AzureKeyVaultProviderName)
	}

	if validationErr := p.ValidateConfig(config); validationErr != nil {
		return nil, validationErr
	}

	// Create Azure credential
	var cred azcore.TokenCredential
	if azConfig.UseSystemMSI {
		cred, err = azidentity.NewManagedIdentityCredential(nil)
	} else if azConfig.UseCLI {
		cred, err = azidentity.NewAzureCLICredential(nil)
	} else {
		cred, err = azidentity.NewClientSecretCredential(
			azConfig.TenantID,
			azConfig.ClientID,
			azConfig.ClientSecret,
			nil,
		)
	}

	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeAuthenticationFailed,
			"Failed to create Azure credentials", err).
			WithProvider(AzureKeyVaultProviderName)
	}

	// Create Key Vault client
	client, err := azkeys.NewClient(azConfig.VaultURL, cred, nil)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeConnectionFailed,
			"Failed to create Azure Key Vault client", err).
			WithProvider(AzureKeyVaultProviderName)
	}

	return &AzureKeyVaultClient{
		client:   client,
		vaultURL: azConfig.VaultURL,
		logger:   p.logger,
		config:   azConfig,
	}, nil
}

func (p *AzureKeyVaultProvider) Initialize(config map[string]interface{}) error {
	// Azure Key Vault provider doesn't need global initialization
	return nil
}

func (p *AzureKeyVaultProvider) Shutdown() error {
	// Azure Key Vault provider doesn't need cleanup
	return nil
}

// Client interface implementation
func (c *AzureKeyVaultClient) Health(ctx context.Context) (*models.HealthStatus, error) {
	start := time.Now()

	// Test connection by listing keys (with limit to make it lightweight)
	pager := c.client.NewListKeyPropertiesPager(nil)
	if pager.More() {
		_, err := pager.NextPage(ctx)
		if err != nil {
			return &models.HealthStatus{
					Status:       "unhealthy",
					Provider:     AzureKeyVaultProviderName,
					LastCheck:    time.Now(),
					Error:        err.Error(),
					ResponseTime: time.Since(start),
					Details: map[string]string{
						"vault_url": c.vaultURL,
					},
				}, models.NewHSMErrorWithCause(models.ErrCodeServiceUnavailable,
					"Azure Key Vault health check failed", err).
					WithProvider(AzureKeyVaultProviderName)
		}
	}

	return &models.HealthStatus{
		Status:       "healthy",
		Provider:     AzureKeyVaultProviderName,
		LastCheck:    time.Now(),
		ResponseTime: time.Since(start),
		Details: map[string]string{
			"vault_url": c.vaultURL,
		},
	}, nil
}

func (c *AzureKeyVaultClient) GetProviderInfo(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"provider":   AzureKeyVaultProviderName,
		"version":    AzureKeyVaultProviderVersion,
		"vault_url":  c.vaultURL,
		"hsm_backed": true,
		"enterprise": true,
	}, nil
}

func (c *AzureKeyVaultClient) GenerateKey(ctx context.Context, spec models.KeySpec, name string) (*models.KeyHandle, error) {
	// Convert KeyGrid spec to Azure Key Vault parameters
	keyType, keySize, err := c.convertKeySpecToAzure(spec)
	if err != nil {
		return nil, err
	}

	// Set key operations based on usage
	operations := c.convertUsageToOperations(spec.Usage)

	// Create key parameters
	params := azkeys.CreateKeyParameters{
		Kty:     &keyType,
		KeySize: &keySize,
		KeyOps:  operations,
		KeyAttributes: &azkeys.KeyAttributes{
			Enabled: ptrBool(true),
		},
	}

	// Set expiration if specified
	if spec.KeyExpiration != nil {
		params.KeyAttributes.Expires = ptrTime(*spec.KeyExpiration)
	}

	// Generate the key
	result, err := c.client.CreateKey(ctx, name, params, nil)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyGenerationFailed,
			"Failed to generate key in Azure Key Vault", err).
			WithProvider(AzureKeyVaultProviderName).
			WithOperation("generate_key").
			WithDetails(map[string]interface{}{
				"key_name": name,
				"key_type": spec.KeyType,
			})
	}

	// Convert Azure result to KeyGrid KeyHandle
	keyHandle := &models.KeyHandle{
		ID:            extractKeyID((*string)(result.Key.KID)),
		Name:          name,
		KeyType:       spec.KeyType,
		KeySize:       spec.KeySize,
		Algorithm:     spec.Algorithm,
		Usage:         spec.Usage,
		State:         models.KeyStateActive,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ProviderID:    AzureKeyVaultProviderName,
		ProviderKeyID: string(*result.Key.KID),
		Metadata: map[string]string{
			"vault_url":  c.vaultURL,
			"hsm_backed": "true",
		},
	}

	if result.Attributes != nil && result.Attributes.Expires != nil {
		keyHandle.ExpiresAt = result.Attributes.Expires
	}

	c.logger.WithFields(logrus.Fields{
		"key_id":    keyHandle.ID,
		"key_name":  name,
		"key_type":  spec.KeyType,
		"vault_url": c.vaultURL,
	}).Info("Key generated successfully in Azure Key Vault")

	return keyHandle, nil
}

func (c *AzureKeyVaultClient) ImportKey(ctx context.Context, keyData []byte, spec models.KeySpec, name string) (*models.KeyHandle, error) {
	// TODO: Implement key import functionality
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"Key import not yet implemented for Azure Key Vault provider").
		WithProvider(AzureKeyVaultProviderName).
		WithOperation("import_key")
}

func (c *AzureKeyVaultClient) GetKey(ctx context.Context, keyHandle string) (*models.KeyHandle, error) {
	keyName := extractKeyNameFromID(keyHandle)

	result, err := c.client.GetKey(ctx, keyName, "", nil)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyNotFound,
			"Failed to get key from Azure Key Vault", err).
			WithProvider(AzureKeyVaultProviderName).
			WithOperation("get_key").
			WithDetails(map[string]interface{}{
				"key_handle": keyHandle,
				"key_name":   keyName,
			})
	}

	// Convert Azure result to KeyGrid KeyHandle
	key := c.convertAzureKeyToHandle(*result.Key, keyName)
	return key, nil
}

func (c *AzureKeyVaultClient) ListKeys(ctx context.Context) ([]*models.KeyHandle, error) {
	var keys []*models.KeyHandle

	pager := c.client.NewListKeyPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, models.NewHSMErrorWithCause(models.ErrCodeUnknown,
				"Failed to list keys from Azure Key Vault", err).
				WithProvider(AzureKeyVaultProviderName).
				WithOperation("list_keys")
		}

		for _, item := range page.Value {
			// Get full key details
			keyName := extractKeyNameFromKID(string(*item.KID))
			fullKey, err := c.client.GetKey(ctx, keyName, "", nil)
			if err != nil {
				c.logger.WithFields(logrus.Fields{
					"key_name": keyName,
					"error":    err,
				}).Warn("Failed to get full key details, skipping")
				continue
			}

			keyHandle := c.convertAzureKeyToHandle(*fullKey.Key, keyName)
			keys = append(keys, keyHandle)
		}
	}

	return keys, nil
}

func (c *AzureKeyVaultClient) DeleteKey(ctx context.Context, keyHandle string) error {
	keyName := extractKeyNameFromID(keyHandle)

	_, err := c.client.DeleteKey(ctx, keyName, nil)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeKeyDeletionFailed,
			"Failed to delete key from Azure Key Vault", err).
			WithProvider(AzureKeyVaultProviderName).
			WithOperation("delete_key").
			WithDetails(map[string]interface{}{
				"key_handle": keyHandle,
				"key_name":   keyName,
			})
	}

	return nil
}

func (c *AzureKeyVaultClient) ActivateKey(ctx context.Context, keyHandle string) error {
	keyName := extractKeyNameFromID(keyHandle)

	params := azkeys.UpdateKeyParameters{
		KeyAttributes: &azkeys.KeyAttributes{
			Enabled: ptrBool(true),
		},
	}

	_, err := c.client.UpdateKey(ctx, keyName, "", params, nil)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to activate key in Azure Key Vault", err).
			WithProvider(AzureKeyVaultProviderName).
			WithOperation("activate_key")
	}

	return nil
}

func (c *AzureKeyVaultClient) DeactivateKey(ctx context.Context, keyHandle string) error {
	keyName := extractKeyNameFromID(keyHandle)

	params := azkeys.UpdateKeyParameters{
		KeyAttributes: &azkeys.KeyAttributes{
			Enabled: ptrBool(false),
		},
	}

	_, err := c.client.UpdateKey(ctx, keyName, "", params, nil)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to deactivate key in Azure Key Vault", err).
			WithProvider(AzureKeyVaultProviderName).
			WithOperation("deactivate_key")
	}

	return nil
}

func (c *AzureKeyVaultClient) SetKeyExpiration(ctx context.Context, keyHandle string, expiration time.Time) error {
	keyName := extractKeyNameFromID(keyHandle)

	params := azkeys.UpdateKeyParameters{
		KeyAttributes: &azkeys.KeyAttributes{
			Expires: &expiration,
		},
	}

	_, err := c.client.UpdateKey(ctx, keyName, "", params, nil)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to set key expiration in Azure Key Vault", err).
			WithProvider(AzureKeyVaultProviderName).
			WithOperation("set_key_expiration")
	}

	return nil
}

func (c *AzureKeyVaultClient) GetPublicKey(ctx context.Context, keyHandle string) (crypto.PublicKey, error) {
	keyName := extractKeyNameFromID(keyHandle)

	result, err := c.client.GetKey(ctx, keyName, "", nil)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyNotFound,
			"Failed to get key from Azure Key Vault", err).
			WithProvider(AzureKeyVaultProviderName).
			WithOperation("get_public_key")
	}

	return c.convertAzureKeyToPublicKey(*result.Key)
}

func (c *AzureKeyVaultClient) Sign(ctx context.Context, request models.SigningRequest) (*models.SigningResponse, error) {
	keyName := extractKeyNameFromID(request.KeyHandle)

	// Convert algorithm and prepare parameters
	algorithmInterface, err := c.convertAlgorithmToAzure(request.Algorithm, "sign")
	if err != nil {
		return nil, err
	}
	algorithm := algorithmInterface.(azkeys.SignatureAlgorithm)

	// Create signing parameters
	params := azkeys.SignParameters{
		Algorithm: &algorithm,
		Value:     request.Data,
	}

	result, err := c.client.Sign(ctx, keyName, "", params, nil)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeSigningFailed,
			"Failed to sign data with Azure Key Vault", err).
			WithProvider(AzureKeyVaultProviderName).
			WithOperation("sign").
			WithDetails(map[string]interface{}{
				"key_handle": request.KeyHandle,
				"algorithm":  request.Algorithm,
			})
	}

	return &models.SigningResponse{
		Signature: result.Result,
		Algorithm: request.Algorithm,
		KeyID:     request.KeyHandle,
		Metadata: map[string]string{
			"azure_algorithm": string(algorithm),
			"vault_url":       c.vaultURL,
		},
	}, nil
}

func (c *AzureKeyVaultClient) Verify(ctx context.Context, keyHandle string, data, signature []byte, algorithm string) (bool, error) {
	keyName := extractKeyNameFromID(keyHandle)

	azAlgorithmInterface, err := c.convertAlgorithmToAzure(algorithm, "verify")
	if err != nil {
		return false, err
	}
	azAlgorithm := azAlgorithmInterface.(azkeys.SignatureAlgorithm)

	params := azkeys.VerifyParameters{
		Algorithm: &azAlgorithm,
		Digest:    data,
		Signature: signature,
	}

	result, err := c.client.Verify(ctx, keyName, "", params, nil)
	if err != nil {
		return false, models.NewHSMErrorWithCause(models.ErrCodeVerificationFailed,
			"Failed to verify signature with Azure Key Vault", err).
			WithProvider(AzureKeyVaultProviderName).
			WithOperation("verify")
	}

	return *result.Value, nil
}

func (c *AzureKeyVaultClient) Encrypt(ctx context.Context, request models.EncryptionRequest) (*models.EncryptionResponse, error) {
	keyName := extractKeyNameFromID(request.KeyHandle)

	algorithmInterface, err := c.convertAlgorithmToAzure(request.Algorithm, "encrypt")
	if err != nil {
		return nil, err
	}
	algorithm := algorithmInterface.(azkeys.EncryptionAlgorithm)

	params := azkeys.KeyOperationParameters{
		Algorithm: &algorithm,
		Value:     request.Plaintext,
	}

	result, err := c.client.Encrypt(ctx, keyName, "", params, nil)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeEncryptionFailed,
			"Failed to encrypt data with Azure Key Vault", err).
			WithProvider(AzureKeyVaultProviderName).
			WithOperation("encrypt")
	}

	return &models.EncryptionResponse{
		Ciphertext: result.Result,
		Algorithm:  request.Algorithm,
		KeyID:      request.KeyHandle,
		Metadata: map[string]string{
			"azure_algorithm": string(algorithm),
			"vault_url":       c.vaultURL,
		},
	}, nil
}

func (c *AzureKeyVaultClient) Decrypt(ctx context.Context, request models.DecryptionRequest) (*models.DecryptionResponse, error) {
	keyName := extractKeyNameFromID(request.KeyHandle)

	algorithmInterface, err := c.convertAlgorithmToAzure(request.Algorithm, "decrypt")
	if err != nil {
		return nil, err
	}
	algorithm := algorithmInterface.(azkeys.EncryptionAlgorithm)

	params := azkeys.KeyOperationParameters{
		Algorithm: &algorithm,
		Value:     request.Ciphertext,
	}

	result, err := c.client.Decrypt(ctx, keyName, "", params, nil)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeDecryptionFailed,
			"Failed to decrypt data with Azure Key Vault", err).
			WithProvider(AzureKeyVaultProviderName).
			WithOperation("decrypt")
	}

	return &models.DecryptionResponse{
		Plaintext: result.Result,
		Algorithm: request.Algorithm,
		KeyID:     request.KeyHandle,
		Metadata: map[string]string{
			"azure_algorithm": string(algorithm),
			"vault_url":       c.vaultURL,
		},
	}, nil
}

func (c *AzureKeyVaultClient) WrapKey(ctx context.Context, request models.KeyWrapRequest) (*models.KeyWrapResponse, error) {
	keyName := extractKeyNameFromID(request.KEKHandle)

	algorithmInterface, err := c.convertAlgorithmToAzure(request.Algorithm, "wrapKey")
	if err != nil {
		return nil, err
	}
	algorithm := algorithmInterface.(azkeys.EncryptionAlgorithm)

	params := azkeys.KeyOperationParameters{
		Algorithm: &algorithm,
		Value:     request.KeyToWrap,
	}

	result, err := c.client.WrapKey(ctx, keyName, "", params, nil)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyWrapFailed,
			"Failed to wrap key with Azure Key Vault", err).
			WithProvider(AzureKeyVaultProviderName).
			WithOperation("wrap_key")
	}

	return &models.KeyWrapResponse{
		WrappedKey: result.Result,
		Algorithm:  request.Algorithm,
		KEKId:      request.KEKHandle,
		Metadata: map[string]string{
			"azure_algorithm": string(algorithm),
			"vault_url":       c.vaultURL,
		},
	}, nil
}

func (c *AzureKeyVaultClient) UnwrapKey(ctx context.Context, request models.KeyUnwrapRequest) (*models.KeyUnwrapResponse, error) {
	keyName := extractKeyNameFromID(request.KEKHandle)

	algorithmInterface, err := c.convertAlgorithmToAzure(request.Algorithm, "unwrapKey")
	if err != nil {
		return nil, err
	}
	algorithm := algorithmInterface.(azkeys.EncryptionAlgorithm)

	params := azkeys.KeyOperationParameters{
		Algorithm: &algorithm,
		Value:     request.WrappedKey,
	}

	result, err := c.client.UnwrapKey(ctx, keyName, "", params, nil)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyUnwrapFailed,
			"Failed to unwrap key with Azure Key Vault", err).
			WithProvider(AzureKeyVaultProviderName).
			WithOperation("unwrap_key")
	}

	return &models.KeyUnwrapResponse{
		UnwrappedKey: result.Result,
		Algorithm:    request.Algorithm,
		KEKId:        request.KEKHandle,
		Metadata: map[string]string{
			"azure_algorithm": string(algorithm),
			"vault_url":       c.vaultURL,
		},
	}, nil
}

func (c *AzureKeyVaultClient) Close() error {
	// Azure Key Vault client doesn't need explicit cleanup
	return nil
}

// Helper functions
func parseAzureConfig(config map[string]interface{}) (*AzureKeyVaultConfig, error) {
	azConfig := &AzureKeyVaultConfig{}

	if vaultURL, ok := config["vault_url"].(string); ok {
		azConfig.VaultURL = vaultURL
	}

	if clientID, ok := config["client_id"].(string); ok {
		azConfig.ClientID = clientID
	}

	if clientSecret, ok := config["client_secret"].(string); ok {
		azConfig.ClientSecret = clientSecret
	}

	if tenantID, ok := config["tenant_id"].(string); ok {
		azConfig.TenantID = tenantID
	}

	if useSystemMSI, ok := config["use_system_msi"].(bool); ok {
		azConfig.UseSystemMSI = useSystemMSI
	}

	if useCLI, ok := config["use_cli"].(bool); ok {
		azConfig.UseCLI = useCLI
	}

	return azConfig, nil
}

func (c *AzureKeyVaultClient) convertKeySpecToAzure(spec models.KeySpec) (azkeys.KeyType, int32, error) {
	switch spec.KeyType {
	case models.KeyTypeRSA:
		// Validate key size to prevent integer overflow and ensure valid RSA key sizes
		if spec.KeySize < 1024 || spec.KeySize > 4096 {
			return "", 0, models.NewHSMError(models.ErrCodeInvalidKeySpec,
				fmt.Sprintf("Invalid RSA key size: %d. Must be between 1024 and 4096 bits", spec.KeySize)).
				WithProvider(AzureKeyVaultProviderName)
		}
		// Safe conversion after validation
		return azkeys.KeyTypeRSA, int32(spec.KeySize), nil
	case models.KeyTypeECDSA:
		switch spec.KeySize {
		case 256:
			return azkeys.KeyTypeEC, int32(256), nil
		case 384:
			return azkeys.KeyTypeEC, int32(384), nil
		case 521:
			return azkeys.KeyTypeEC, int32(521), nil
		default:
			return "", 0, models.NewHSMError(models.ErrCodeInvalidKeySpec,
				fmt.Sprintf("Unsupported ECDSA key size: %d", spec.KeySize)).
				WithProvider(AzureKeyVaultProviderName)
		}
	default:
		return "", 0, models.NewHSMError(models.ErrCodeInvalidKeySpec,
			fmt.Sprintf("Unsupported key type: %s", spec.KeyType)).
			WithProvider(AzureKeyVaultProviderName)
	}
}

func (c *AzureKeyVaultClient) convertUsageToOperations(usage []models.KeyUsage) []*azkeys.KeyOperation {
	var operations []*azkeys.KeyOperation

	for _, u := range usage {
		switch u {
		case models.KeyUsageSign:
			operations = append(operations, to.Ptr(azkeys.KeyOperationSign))
		case models.KeyUsageVerify:
			operations = append(operations, to.Ptr(azkeys.KeyOperationVerify))
		case models.KeyUsageEncrypt:
			operations = append(operations, to.Ptr(azkeys.KeyOperationEncrypt))
		case models.KeyUsageDecrypt:
			operations = append(operations, to.Ptr(azkeys.KeyOperationDecrypt))
		case models.KeyUsageWrap:
			operations = append(operations, to.Ptr(azkeys.KeyOperationWrapKey))
		case models.KeyUsageUnwrap:
			operations = append(operations, to.Ptr(azkeys.KeyOperationUnwrapKey))
		}
	}

	if len(operations) == 0 {
		// Default to sign/verify for asymmetric keys
		operations = []*azkeys.KeyOperation{
			to.Ptr(azkeys.KeyOperationSign),
			to.Ptr(azkeys.KeyOperationVerify),
		}
	}

	return operations
}

func (c *AzureKeyVaultClient) convertAlgorithmToAzure(algorithm, operation string) (interface{}, error) {
	// This is a simplified conversion - in production, you'd want more comprehensive mapping
	switch operation {
	case "sign", "verify":
		switch strings.ToUpper(algorithm) {
		case "RS256", "RSA-PSS":
			return azkeys.SignatureAlgorithmRS256, nil
		case "ES256":
			return azkeys.SignatureAlgorithmES256, nil
		case "ES384":
			return azkeys.SignatureAlgorithmES384, nil
		case "ES512":
			return azkeys.SignatureAlgorithmES512, nil
		default:
			return "", models.NewHSMError(models.ErrCodeInvalidAlgorithm,
				fmt.Sprintf("Unsupported signing algorithm: %s", algorithm)).
				WithProvider(AzureKeyVaultProviderName)
		}
	case "encrypt", "decrypt":
		switch strings.ToUpper(algorithm) {
		case "RSA-OAEP", "RSA1_5":
			return azkeys.EncryptionAlgorithmRSAOAEP, nil
		default:
			return "", models.NewHSMError(models.ErrCodeInvalidAlgorithm,
				fmt.Sprintf("Unsupported encryption algorithm: %s", algorithm)).
				WithProvider(AzureKeyVaultProviderName)
		}
	case "wrapKey", "unwrapKey":
		switch strings.ToUpper(algorithm) {
		case "RSA-OAEP", "RSA1_5":
			return azkeys.EncryptionAlgorithmRSAOAEP, nil
		default:
			return "", models.NewHSMError(models.ErrCodeInvalidAlgorithm,
				fmt.Sprintf("Unsupported key wrap algorithm: %s", algorithm)).
				WithProvider(AzureKeyVaultProviderName)
		}
	default:
		return "", models.NewHSMError(models.ErrCodeInvalidAlgorithm,
			fmt.Sprintf("Unsupported operation: %s", operation)).
			WithProvider(AzureKeyVaultProviderName)
	}
}

func (c *AzureKeyVaultClient) convertAzureKeyToHandle(key azkeys.JSONWebKey, name string) *models.KeyHandle {
	// Convert Azure Key to KeyGrid KeyHandle
	// This is a simplified conversion - production code would be more comprehensive
	handle := &models.KeyHandle{
		ID:            extractKeyID((*string)(key.KID)),
		Name:          name,
		ProviderID:    AzureKeyVaultProviderName,
		ProviderKeyID: string(*key.KID),
		State:         models.KeyStateActive,
		CreatedAt:     time.Now(), // Azure doesn't provide created timestamp in key
		UpdatedAt:     time.Now(),
		Metadata: map[string]string{
			"vault_url":  c.vaultURL,
			"hsm_backed": "true",
		},
	}

	// Map Azure key type to KeyGrid key type
	if key.Kty != nil {
		switch *key.Kty {
		case azkeys.KeyTypeRSA:
			handle.KeyType = models.KeyTypeRSA
			if len(key.N) > 0 {
				// Calculate key size from modulus
				handle.KeySize = len(key.N) * 8
			}
		case azkeys.KeyTypeEC:
			handle.KeyType = models.KeyTypeECDSA
			if key.Crv != nil {
				switch *key.Crv {
				case azkeys.CurveNameP256:
					handle.KeySize = 256
				case azkeys.CurveNameP384:
					handle.KeySize = 384
				case azkeys.CurveNameP521:
					handle.KeySize = 521
				}
			}
		}
	}

	return handle
}

func (c *AzureKeyVaultClient) convertAzureKeyToPublicKey(key azkeys.JSONWebKey) (crypto.PublicKey, error) {
	if key.Kty == nil {
		return nil, models.NewHSMError(models.ErrCodeUnknown,
			"Key type not specified in Azure Key Vault key").
			WithProvider(AzureKeyVaultProviderName)
	}

	switch *key.Kty {
	case azkeys.KeyTypeRSA:
		if len(key.N) == 0 || len(key.E) == 0 {
			return nil, models.NewHSMError(models.ErrCodeUnknown,
				"RSA key parameters missing").
				WithProvider(AzureKeyVaultProviderName)
		}

		nBytes := key.N
		eBytes := key.E

		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}, nil

	case azkeys.KeyTypeEC:
		if key.Crv == nil || len(key.X) == 0 || len(key.Y) == 0 {
			return nil, models.NewHSMError(models.ErrCodeUnknown,
				"ECDSA key parameters missing").
				WithProvider(AzureKeyVaultProviderName)
		}

		var curve elliptic.Curve
		switch *key.Crv {
		case azkeys.CurveNameP256:
			curve = elliptic.P256()
		case azkeys.CurveNameP384:
			curve = elliptic.P384()
		case azkeys.CurveNameP521:
			curve = elliptic.P521()
		default:
			return nil, models.NewHSMError(models.ErrCodeUnknown,
				fmt.Sprintf("Unsupported curve: %s", *key.Crv)).
				WithProvider(AzureKeyVaultProviderName)
		}

		xBytes := key.X
		yBytes := key.Y

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil

	default:
		return nil, models.NewHSMError(models.ErrCodeUnknown,
			fmt.Sprintf("Unsupported key type: %s", *key.Kty)).
			WithProvider(AzureKeyVaultProviderName)
	}
}

// Utility functions
func extractKeyID(kid *string) string {
	if kid == nil {
		return ""
	}

	// Extract key name from full Key Vault URL
	parts := strings.Split(*kid, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2] // Get the key name part
	}
	return *kid
}

func extractKeyNameFromID(keyHandle string) string {
	// In this implementation, key handle can be either the key name or full KID
	if strings.Contains(keyHandle, "/") {
		return extractKeyID(&keyHandle)
	}
	return keyHandle
}

func extractKeyNameFromKID(kid string) string {
	return extractKeyID(&kid)
}

// Helper functions to create pointers (similar to Azure SDK's to package)
func ptrBool(v bool) *bool {
	return &v
}

func ptrTime(v time.Time) *time.Time {
	return &v
}
