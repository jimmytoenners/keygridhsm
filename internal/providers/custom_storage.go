package providers

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	cryptoutils "github.com/jimmy/keygridhsm/internal/crypto"
	"github.com/jimmy/keygridhsm/pkg/models"
	"golang.org/x/crypto/pbkdf2"
)

const (
	CustomStorageProviderName    = "custom-storage"
	CustomStorageProviderVersion = "1.0.0"
)

// StorageBackend defines the interface for storage backends
type StorageBackend interface {
	// Store saves data with the given key
	Store(ctx context.Context, key string, data []byte) error

	// Retrieve gets data for the given key
	Retrieve(ctx context.Context, key string) ([]byte, error)

	// Delete removes data for the given key
	Delete(ctx context.Context, key string) error

	// List returns all keys with the given prefix
	List(ctx context.Context, prefix string) ([]string, error)

	// Exists checks if a key exists
	Exists(ctx context.Context, key string) (bool, error)

	// Health checks if the storage backend is healthy
	Health(ctx context.Context) error

	// Close closes the storage backend
	Close() error
}

// CustomStorageProvider implements the HSMProvider interface with pluggable storage
type CustomStorageProvider struct {
	logger *logrus.Logger
}

// CustomStorageClient implements the HSMClient interface with custom storage backend
type CustomStorageClient struct {
	storage       StorageBackend
	encryptionKey []byte
	logger        *logrus.Logger
	config        *CustomStorageConfig
}

// CustomStorageConfig holds configuration for custom storage provider
type CustomStorageConfig struct {
	StorageType   string                 `json:"storage_type"` // "filesystem", "database", "s3", etc.
	StorageConfig map[string]interface{} `json:"storage_config"`
	EncryptionKey string                 `json:"encryption_key"`
	KeyPrefix     string                 `json:"key_prefix"`
	EncryptAtRest bool                   `json:"encrypt_at_rest"`
}

// StoredKeyData represents encrypted key data stored in the backend
type StoredKeyData struct {
	Handle       *models.KeyHandle `json:"handle"`
	EncryptedKey []byte            `json:"encrypted_key"`
	PublicKeyPEM []byte            `json:"public_key_pem"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	Metadata     map[string]string `json:"metadata"`
	Salt         []byte            `json:"salt,omitempty"`
	Nonce        []byte            `json:"nonce,omitempty"`
}

// NewCustomStorageProvider creates a new custom storage provider
func NewCustomStorageProvider(logger *logrus.Logger) *CustomStorageProvider {
	if logger == nil {
		logger = logrus.New()
	}

	return &CustomStorageProvider{
		logger: logger,
	}
}

// Provider interface implementation
func (p *CustomStorageProvider) Name() string {
	return CustomStorageProviderName
}

func (p *CustomStorageProvider) Version() string {
	return CustomStorageProviderVersion
}

func (p *CustomStorageProvider) Capabilities() []string {
	return []string{
		"key_generation",
		"key_import",
		"signing",
		"verification",
		"encryption",
		"decryption",
		"key_wrapping",
		"key_unwrapping",
		"custom_storage",
		"encryption_at_rest",
		"pluggable_backend",
	}
}

func (p *CustomStorageProvider) ValidateConfig(config map[string]interface{}) error {
	customConfig, err := parseCustomStorageConfig(config)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeInvalidConfig,
			"Invalid custom storage configuration", err).
			WithProvider(CustomStorageProviderName)
	}

	if customConfig.StorageType == "" {
		return models.NewHSMError(models.ErrCodeInvalidConfig,
			"storage_type is required for custom storage provider").
			WithProvider(CustomStorageProviderName)
	}

	if customConfig.EncryptAtRest && customConfig.EncryptionKey == "" {
		return models.NewHSMError(models.ErrCodeInvalidConfig,
			"encryption_key is required when encrypt_at_rest is true").
			WithProvider(CustomStorageProviderName)
	}

	return nil
}

func (p *CustomStorageProvider) CreateClient(config map[string]interface{}) (models.HSMClient, error) {
	customConfig, err := parseCustomStorageConfig(config)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeInvalidConfig,
			"Failed to parse custom storage configuration", err).
			WithProvider(CustomStorageProviderName)
	}

	if validationErr := p.ValidateConfig(config); validationErr != nil {
		return nil, validationErr
	}

	// Create storage backend
	storage, err := p.createStorageBackend(customConfig)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeConnectionFailed,
			"Failed to create storage backend", err).
			WithProvider(CustomStorageProviderName)
	}

	// Derive encryption key if needed
	var encryptionKey []byte
	if customConfig.EncryptAtRest {
		encryptionKey = pbkdf2.Key([]byte(customConfig.EncryptionKey), []byte("keygrid-hsm-salt"), 100000, 32, sha256.New)
	}

	return &CustomStorageClient{
		storage:       storage,
		encryptionKey: encryptionKey,
		logger:        p.logger,
		config:        customConfig,
	}, nil
}

func (p *CustomStorageProvider) Initialize(config map[string]interface{}) error {
	// Custom storage provider doesn't need global initialization
	return nil
}

func (p *CustomStorageProvider) Shutdown() error {
	// Custom storage provider doesn't need cleanup
	return nil
}

func (p *CustomStorageProvider) createStorageBackend(config *CustomStorageConfig) (StorageBackend, error) {
	switch config.StorageType {
	case "filesystem":
		return NewFilesystemStorage(config.StorageConfig, p.logger)
	case "database":
		return NewDatabaseStorage(config.StorageConfig, p.logger)
	case "memory":
		return NewMemoryStorage(config.StorageConfig, p.logger)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", config.StorageType)
	}
}

// Client interface implementation
func (c *CustomStorageClient) Health(ctx context.Context) (*models.HealthStatus, error) {
	start := time.Now()

	err := c.storage.Health(ctx)
	if err != nil {
		return &models.HealthStatus{
				Status:       "unhealthy",
				Provider:     CustomStorageProviderName,
				LastCheck:    time.Now(),
				Error:        err.Error(),
				ResponseTime: time.Since(start),
				Details: map[string]string{
					"storage_type": c.config.StorageType,
				},
			}, models.NewHSMErrorWithCause(models.ErrCodeServiceUnavailable,
				"Custom storage health check failed", err).
				WithProvider(CustomStorageProviderName)
	}

	return &models.HealthStatus{
		Status:       "healthy",
		Provider:     CustomStorageProviderName,
		LastCheck:    time.Now(),
		ResponseTime: time.Since(start),
		Details: map[string]string{
			"storage_type": c.config.StorageType,
			"encryption":   fmt.Sprintf("%t", c.config.EncryptAtRest),
		},
	}, nil
}

func (c *CustomStorageClient) GetProviderInfo(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"provider":        CustomStorageProviderName,
		"version":         CustomStorageProviderVersion,
		"storage_type":    c.config.StorageType,
		"encrypt_at_rest": c.config.EncryptAtRest,
		"custom_storage":  true,
	}, nil
}

func (c *CustomStorageClient) GenerateKey(ctx context.Context, spec models.KeySpec, name string) (*models.KeyHandle, error) {
	// Generate the key pair
	privateKey, publicKey, err := c.generateKeyPair(spec)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyGenerationFailed,
			"Failed to generate key pair", err).
			WithProvider(CustomStorageProviderName).
			WithOperation("generate_key")
	}

	// Create key handle
	keyID := uuid.New().String()
	handle := &models.KeyHandle{
		ID:            keyID,
		Name:          name,
		KeyType:       spec.KeyType,
		KeySize:       spec.KeySize,
		Algorithm:     spec.Algorithm,
		Usage:         spec.Usage,
		State:         models.KeyStateActive,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ProviderID:    CustomStorageProviderName,
		ProviderKeyID: keyID,
		Metadata: map[string]string{
			"storage_type": c.config.StorageType,
			"encrypted":    fmt.Sprintf("%t", c.config.EncryptAtRest),
		},
	}

	if spec.KeyExpiration != nil {
		handle.ExpiresAt = spec.KeyExpiration
	}

	// Serialize private key
	privateKeyBytes, err := c.serializePrivateKey(privateKey)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyGenerationFailed,
			"Failed to serialize private key", err).
			WithProvider(CustomStorageProviderName)
	}

	// Serialize public key
	publicKeyBytes, err := c.serializePublicKey(publicKey)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyGenerationFailed,
			"Failed to serialize public key", err).
			WithProvider(CustomStorageProviderName)
	}

	// Store the key
	err = c.storeKey(ctx, handle, privateKeyBytes, publicKeyBytes)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyGenerationFailed,
			"Failed to store key", err).
			WithProvider(CustomStorageProviderName)
	}

	c.logger.WithFields(logrus.Fields{
		"key_id":       keyID,
		"key_name":     name,
		"key_type":     spec.KeyType,
		"storage_type": c.config.StorageType,
	}).Info("Key generated successfully in custom storage")

	return handle, nil
}

func (c *CustomStorageClient) ImportKey(ctx context.Context, keyData []byte, spec models.KeySpec, name string) (*models.KeyHandle, error) {
	// Parse the key data
	privateKey, err := c.parsePrivateKey(keyData)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyImportFailed,
			"Failed to parse private key", err).
			WithProvider(CustomStorageProviderName)
	}

	// Get public key from private key
	publicKey, err := c.getPublicKeyFromPrivate(privateKey)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyImportFailed,
			"Failed to extract public key", err).
			WithProvider(CustomStorageProviderName)
	}

	// Create key handle
	keyID := uuid.New().String()
	handle := &models.KeyHandle{
		ID:            keyID,
		Name:          name,
		KeyType:       spec.KeyType,
		KeySize:       spec.KeySize,
		Algorithm:     spec.Algorithm,
		Usage:         spec.Usage,
		State:         models.KeyStateActive,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ProviderID:    CustomStorageProviderName,
		ProviderKeyID: keyID,
		Metadata: map[string]string{
			"storage_type": c.config.StorageType,
			"imported":     "true",
		},
	}

	// Serialize public key
	publicKeyBytes, err := c.serializePublicKey(publicKey)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyImportFailed,
			"Failed to serialize public key", err).
			WithProvider(CustomStorageProviderName)
	}

	// Store the key
	err = c.storeKey(ctx, handle, keyData, publicKeyBytes)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyImportFailed,
			"Failed to store imported key", err).
			WithProvider(CustomStorageProviderName)
	}

	return handle, nil
}

func (c *CustomStorageClient) GetKey(ctx context.Context, keyHandle string) (*models.KeyHandle, error) {
	keyPath := c.getKeyPath(keyHandle)

	data, err := c.storage.Retrieve(ctx, keyPath)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyNotFound,
			"Failed to retrieve key from storage", err).
			WithProvider(CustomStorageProviderName)
	}

	var storedKey StoredKeyData
	if err := json.Unmarshal(data, &storedKey); err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to unmarshal stored key data", err).
			WithProvider(CustomStorageProviderName)
	}

	return storedKey.Handle, nil
}

func (c *CustomStorageClient) ListKeys(ctx context.Context) ([]*models.KeyHandle, error) {
	prefix := c.getKeyPrefix()

	keyPaths, err := c.storage.List(ctx, prefix)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to list keys from storage", err).
			WithProvider(CustomStorageProviderName)
	}

	var handles []*models.KeyHandle
	for _, keyPath := range keyPaths {
		data, err := c.storage.Retrieve(ctx, keyPath)
		if err != nil {
			c.logger.WithFields(logrus.Fields{
				"key_path": keyPath,
				"error":    err,
			}).Warn("Failed to retrieve key, skipping")
			continue
		}

		var storedKey StoredKeyData
		if err := json.Unmarshal(data, &storedKey); err != nil {
			c.logger.WithFields(logrus.Fields{
				"key_path": keyPath,
				"error":    err,
			}).Warn("Failed to unmarshal key data, skipping")
			continue
		}

		handles = append(handles, storedKey.Handle)
	}

	return handles, nil
}

func (c *CustomStorageClient) DeleteKey(ctx context.Context, keyHandle string) error {
	keyPath := c.getKeyPath(keyHandle)

	err := c.storage.Delete(ctx, keyPath)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeKeyDeletionFailed,
			"Failed to delete key from storage", err).
			WithProvider(CustomStorageProviderName)
	}

	return nil
}

func (c *CustomStorageClient) ActivateKey(ctx context.Context, keyHandle string) error {
	return c.updateKeyState(ctx, keyHandle, models.KeyStateActive)
}

func (c *CustomStorageClient) DeactivateKey(ctx context.Context, keyHandle string) error {
	return c.updateKeyState(ctx, keyHandle, models.KeyStateInactive)
}

func (c *CustomStorageClient) SetKeyExpiration(ctx context.Context, keyHandle string, expiration time.Time) error {
	keyPath := c.getKeyPath(keyHandle)

	data, err := c.storage.Retrieve(ctx, keyPath)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeKeyNotFound,
			"Failed to retrieve key for expiration update", err).
			WithProvider(CustomStorageProviderName)
	}

	var storedKey StoredKeyData
	if unmarshalErr := json.Unmarshal(data, &storedKey); unmarshalErr != nil {
		return fmt.Errorf("failed to unmarshal stored key: %w", unmarshalErr)
		return models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to unmarshal stored key data", err).
			WithProvider(CustomStorageProviderName)
	}

	// Update expiration
	storedKey.Handle.ExpiresAt = &expiration
	storedKey.Handle.UpdatedAt = time.Now()
	storedKey.UpdatedAt = time.Now()

	// Store updated key
	updatedData, err := json.Marshal(storedKey)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to marshal updated key data", err).
			WithProvider(CustomStorageProviderName)
	}

	return c.storage.Store(ctx, keyPath, updatedData)
}

func (c *CustomStorageClient) GetPublicKey(ctx context.Context, keyHandle string) (crypto.PublicKey, error) {
	keyPath := c.getKeyPath(keyHandle)

	data, err := c.storage.Retrieve(ctx, keyPath)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyNotFound,
			"Failed to retrieve key from storage", err).
			WithProvider(CustomStorageProviderName)
	}

	var storedKey StoredKeyData
	if unmarshalErr := json.Unmarshal(data, &storedKey); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal stored key: %w", unmarshalErr)
		return nil, models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to unmarshal stored key data", err).
			WithProvider(CustomStorageProviderName)
	}

	// Parse public key from PEM
	block, _ := pem.Decode(storedKey.PublicKeyPEM)
	if block == nil {
		return nil, models.NewHSMError(models.ErrCodeUnknown,
			"Failed to decode public key PEM").
			WithProvider(CustomStorageProviderName)
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to parse public key", err).
			WithProvider(CustomStorageProviderName)
	}

	return publicKey, nil
}

func (c *CustomStorageClient) Sign(ctx context.Context, request models.SigningRequest) (*models.SigningResponse, error) {
	// Get private key
	privateKey, err := c.getPrivateKey(ctx, request.KeyHandle)
	if err != nil {
		return nil, err
	}

	// Perform signing based on key type
	var signature []byte
	hash := sha256.Sum256(request.Data)

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], nil)
		if err != nil {
			return nil, models.NewHSMErrorWithCause(models.ErrCodeSigningFailed,
				"RSA signing failed", err).
				WithProvider(CustomStorageProviderName)
		}
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
		if err != nil {
			return nil, models.NewHSMErrorWithCause(models.ErrCodeSigningFailed,
				"ECDSA signing failed", err).
				WithProvider(CustomStorageProviderName)
		}
		signature, err = marshalECDSASignature(r, s)
		if err != nil {
			return nil, models.NewHSMErrorWithCause(models.ErrCodeSigningFailed,
				"Failed to marshal ECDSA signature", err).
				WithProvider(CustomStorageProviderName)
		}
	case ed25519.PrivateKey:
		signature = ed25519.Sign(key, request.Data)
	default:
		return nil, models.NewHSMError(models.ErrCodeSigningFailed,
			"Unsupported private key type for signing").
			WithProvider(CustomStorageProviderName)
	}

	return &models.SigningResponse{
		Signature: signature,
		Algorithm: request.Algorithm,
		KeyID:     request.KeyHandle,
		Metadata: map[string]string{
			"storage_type": c.config.StorageType,
		},
	}, nil
}

func (c *CustomStorageClient) Verify(ctx context.Context, keyHandle string, data, signature []byte, algorithm string) (bool, error) {
	// Get public key
	publicKey, err := c.GetPublicKey(ctx, keyHandle)
	if err != nil {
		return false, err
	}

	// Perform verification based on key type
	hash := sha256.Sum256(data)

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPSS(key, crypto.SHA256, hash[:], signature, nil)
		return err == nil, nil
	case *ecdsa.PublicKey:
		r, s, err := unmarshalECDSASignature(signature)
		if err != nil {
			return false, models.NewHSMErrorWithCause(models.ErrCodeVerificationFailed,
				"Failed to unmarshal ECDSA signature", err).
				WithProvider(CustomStorageProviderName)
		}
		return ecdsa.Verify(key, hash[:], r, s), nil
	case ed25519.PublicKey:
		return ed25519.Verify(key, data, signature), nil
	default:
		return false, models.NewHSMError(models.ErrCodeVerificationFailed,
			"Unsupported public key type for verification").
			WithProvider(CustomStorageProviderName)
	}
}

func (c *CustomStorageClient) Encrypt(ctx context.Context, request models.EncryptionRequest) (*models.EncryptionResponse, error) {
	// Custom storage provider implements symmetric encryption for now
	// TODO: Implement asymmetric encryption with stored keys
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"Encryption not yet implemented for custom storage provider").
		WithProvider(CustomStorageProviderName)
}

func (c *CustomStorageClient) Decrypt(ctx context.Context, request models.DecryptionRequest) (*models.DecryptionResponse, error) {
	// Custom storage provider implements symmetric decryption for now
	// TODO: Implement asymmetric decryption with stored keys
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"Decryption not yet implemented for custom storage provider").
		WithProvider(CustomStorageProviderName)
}

func (c *CustomStorageClient) WrapKey(ctx context.Context, request models.KeyWrapRequest) (*models.KeyWrapResponse, error) {
	// TODO: Implement key wrapping functionality
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"Key wrapping not yet implemented for custom storage provider").
		WithProvider(CustomStorageProviderName)
}

func (c *CustomStorageClient) UnwrapKey(ctx context.Context, request models.KeyUnwrapRequest) (*models.KeyUnwrapResponse, error) {
	// TODO: Implement key unwrapping functionality
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"Key unwrapping not yet implemented for custom storage provider").
		WithProvider(CustomStorageProviderName)
}

func (c *CustomStorageClient) Close() error {
	return c.storage.Close()
}

// Helper functions
func parseCustomStorageConfig(config map[string]interface{}) (*CustomStorageConfig, error) {
	customConfig := &CustomStorageConfig{}

	if storageType, ok := config["storage_type"].(string); ok {
		customConfig.StorageType = storageType
	}

	if storageConfig, ok := config["storage_config"].(map[string]interface{}); ok {
		customConfig.StorageConfig = storageConfig
	}

	if encryptionKey, ok := config["encryption_key"].(string); ok {
		customConfig.EncryptionKey = encryptionKey
	}

	if keyPrefix, ok := config["key_prefix"].(string); ok {
		customConfig.KeyPrefix = keyPrefix
	} else {
		customConfig.KeyPrefix = "keygrid-hsm"
	}

	if encryptAtRest, ok := config["encrypt_at_rest"].(bool); ok {
		customConfig.EncryptAtRest = encryptAtRest
	}

	return customConfig, nil
}

func (c *CustomStorageClient) generateKeyPair(spec models.KeySpec) (crypto.PrivateKey, crypto.PublicKey, error) {
	return cryptoutils.GenerateKeyPair(spec)
}

func (c *CustomStorageClient) serializePrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(key), nil
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(key)
	case ed25519.PrivateKey:
		return []byte(key), nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

func (c *CustomStorageClient) serializePublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})

	return publicKeyPEM, nil
}

func (c *CustomStorageClient) parsePrivateKey(keyData []byte) (crypto.PrivateKey, error) {
	// Try to parse as PEM first
	block, _ := pem.Decode(keyData)
	if block != nil {
		keyData = block.Bytes
	}

	// Try different key formats
	if key, err := x509.ParsePKCS1PrivateKey(keyData); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(keyData); err == nil {
		return key, nil
	}

	if key, err := x509.ParseECPrivateKey(keyData); err == nil {
		return key, nil
	}

	// Try Ed25519
	if len(keyData) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(keyData), nil
	}

	return nil, fmt.Errorf("unsupported private key format")
}

func (c *CustomStorageClient) getPublicKeyFromPrivate(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PrivateKey:
		return key.Public().(ed25519.PublicKey), nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

func (c *CustomStorageClient) storeKey(ctx context.Context, handle *models.KeyHandle, privateKeyBytes, publicKeyBytes []byte) error {
	// Encrypt private key if required
	encryptedKey := privateKeyBytes
	var salt, nonce []byte

	if c.config.EncryptAtRest && len(c.encryptionKey) > 0 {
		var err error
		encryptedKey, salt, nonce, err = c.encryptData(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}
	}

	storedKey := StoredKeyData{
		Handle:       handle,
		EncryptedKey: encryptedKey,
		PublicKeyPEM: publicKeyBytes,
		CreatedAt:    handle.CreatedAt,
		UpdatedAt:    handle.UpdatedAt,
		Metadata:     handle.Metadata,
		Salt:         salt,
		Nonce:        nonce,
	}

	data, err := json.Marshal(storedKey)
	if err != nil {
		return fmt.Errorf("failed to marshal key data: %w", err)
	}

	keyPath := c.getKeyPath(handle.ID)
	return c.storage.Store(ctx, keyPath, data)
}

func (c *CustomStorageClient) getPrivateKey(ctx context.Context, keyHandle string) (crypto.PrivateKey, error) {
	keyPath := c.getKeyPath(keyHandle)

	data, err := c.storage.Retrieve(ctx, keyPath)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyNotFound,
			"Failed to retrieve key from storage", err).
			WithProvider(CustomStorageProviderName)
	}

	var storedKey StoredKeyData
	if err := json.Unmarshal(data, &storedKey); err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to unmarshal stored key data", err).
			WithProvider(CustomStorageProviderName)
	}

	// Decrypt private key if required
	privateKeyBytes := storedKey.EncryptedKey
	if c.config.EncryptAtRest && len(c.encryptionKey) > 0 {
		decryptedBytes, err := c.decryptData(storedKey.EncryptedKey, storedKey.Salt, storedKey.Nonce)
		if err != nil {
			return nil, models.NewHSMErrorWithCause(models.ErrCodeUnknown,
				"Failed to decrypt private key", err).
				WithProvider(CustomStorageProviderName)
		}
		privateKeyBytes = decryptedBytes
	}

	return c.parsePrivateKey(privateKeyBytes)
}

func (c *CustomStorageClient) updateKeyState(ctx context.Context, keyHandle string, state models.KeyState) error {
	keyPath := c.getKeyPath(keyHandle)

	data, err := c.storage.Retrieve(ctx, keyPath)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeKeyNotFound,
			"Failed to retrieve key for state update", err).
			WithProvider(CustomStorageProviderName)
	}

	var storedKey StoredKeyData
	if unmarshalErr := json.Unmarshal(data, &storedKey); unmarshalErr != nil {
		return fmt.Errorf("failed to unmarshal stored key for signing: %w", unmarshalErr)
		return models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to unmarshal stored key data", err).
			WithProvider(CustomStorageProviderName)
	}

	// Update state
	storedKey.Handle.State = state
	storedKey.Handle.UpdatedAt = time.Now()
	storedKey.UpdatedAt = time.Now()

	// Store updated key
	updatedData, err := json.Marshal(storedKey)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeUnknown,
			"Failed to marshal updated key data", err).
			WithProvider(CustomStorageProviderName)
	}

	return c.storage.Store(ctx, keyPath, updatedData)
}

func (c *CustomStorageClient) encryptData(data []byte) ([]byte, []byte, []byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, nil, err
	}

	block, err := aes.NewCipher(c.encryptionKey)
	if err != nil {
		return nil, nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return ciphertext, salt, nonce, nil
}

func (c *CustomStorageClient) decryptData(ciphertext, salt, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (c *CustomStorageClient) getKeyPath(keyID string) string {
	return fmt.Sprintf("%s/keys/%s", c.config.KeyPrefix, keyID)
}

func (c *CustomStorageClient) getKeyPrefix() string {
	return fmt.Sprintf("%s/keys/", c.config.KeyPrefix)
}

// ECDSA signature marshaling functions
func marshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
}

func unmarshalECDSASignature(signature []byte) (*big.Int, *big.Int, error) {
	var sig struct {
		R, S *big.Int
	}

	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return nil, nil, err
	}

	return sig.R, sig.S, nil
}
