package providers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	cryptoutils "github.com/jimmy/keygridhsm/internal/crypto"
	"github.com/jimmy/keygridhsm/pkg/models"
)

const (
	MockHSMProviderName    = "mock-hsm"
	MockHSMProviderVersion = "1.0.0"
)

// MockHSMProvider implements the HSMProvider interface for testing and development
type MockHSMProvider struct {
	logger *logrus.Logger
}

// MockHSMClient implements the HSMClient interface for testing and development
type MockHSMClient struct {
	keys           map[string]*MockKeyEntry
	keysMutex      sync.RWMutex
	logger         *logrus.Logger
	config         *MockHSMConfig
	simulateErrors bool
	latency        time.Duration
	storageBackend StorageBackend
}

// MockHSMConfig holds configuration for the mock HSM provider
type MockHSMConfig struct {
	PersistentStorage bool                   `json:"persistent_storage"`
	StorageConfig     map[string]interface{} `json:"storage_config"`
	SimulateErrors    bool                   `json:"simulate_errors"`
	SimulateLatency   time.Duration          `json:"simulate_latency"`
	MaxKeys           int                    `json:"max_keys"`
	KeyPrefix         string                 `json:"key_prefix"`
	TestScenarios     []string               `json:"test_scenarios"`
}

// MockKeyEntry stores a key and its metadata in the mock HSM
type MockKeyEntry struct {
	Handle      *models.KeyHandle
	PrivateKey  crypto.PrivateKey
	PublicKey   crypto.PublicKey
	CreatedAt   time.Time
	AccessCount int
	LastAccess  time.Time
}

// TestScenario represents different testing scenarios the mock can simulate
type TestScenario struct {
	Name        string
	Description string
	Handler     func(ctx context.Context, client *MockHSMClient, operation string) error
}

var (
	// Available test scenarios
	TestScenarios = map[string]TestScenario{
		"network-error": {
			Name:        "Network Error",
			Description: "Simulates network connectivity issues",
			Handler: func(ctx context.Context, client *MockHSMClient, operation string) error {
				return models.NewHSMError(models.ErrCodeNetworkError, "Simulated network error").
					WithProvider(MockHSMProviderName)
			},
		},
		"timeout": {
			Name:        "Timeout",
			Description: "Simulates operation timeouts",
			Handler: func(ctx context.Context, client *MockHSMClient, operation string) error {
				time.Sleep(client.latency * 2)
				return models.NewHSMError(models.ErrCodeTimeoutError, "Simulated timeout error").
					WithProvider(MockHSMProviderName)
			},
		},
		"rate-limit": {
			Name:        "Rate Limiting",
			Description: "Simulates rate limiting responses",
			Handler: func(ctx context.Context, client *MockHSMClient, operation string) error {
				return models.NewHSMError(models.ErrCodeRateLimitExceeded, "Simulated rate limit exceeded").
					WithProvider(MockHSMProviderName)
			},
		},
		"auth-error": {
			Name:        "Authentication Error",
			Description: "Simulates authentication failures",
			Handler: func(ctx context.Context, client *MockHSMClient, operation string) error {
				return models.NewHSMError(models.ErrCodeAuthenticationFailed, "Simulated authentication error").
					WithProvider(MockHSMProviderName)
			},
		},
	}
)

// NewMockHSMProvider creates a new mock HSM provider
func NewMockHSMProvider(logger *logrus.Logger) *MockHSMProvider {
	if logger == nil {
		logger = logrus.New()
	}

	return &MockHSMProvider{
		logger: logger,
	}
}

// Provider interface implementation
func (p *MockHSMProvider) Name() string {
	return MockHSMProviderName
}

func (p *MockHSMProvider) Version() string {
	return MockHSMProviderVersion
}

func (p *MockHSMProvider) Capabilities() []string {
	return []string{
		"key_generation",
		"key_import",
		"signing",
		"verification",
		"encryption",
		"decryption",
		"key_wrapping",
		"key_unwrapping",
		"testing",
		"development",
		"scenario_simulation",
		"persistent_storage",
		"performance_testing",
	}
}

func (p *MockHSMProvider) ValidateConfig(config map[string]interface{}) error {
	mockConfig, err := parseMockHSMConfig(config)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeInvalidConfig,
			"Invalid mock HSM configuration", err).
			WithProvider(MockHSMProviderName)
	}

	// Validate test scenarios
	for _, scenario := range mockConfig.TestScenarios {
		if _, exists := TestScenarios[scenario]; !exists {
			return models.NewHSMError(models.ErrCodeInvalidConfig,
				fmt.Sprintf("Unknown test scenario: %s", scenario)).
				WithProvider(MockHSMProviderName)
		}
	}

	return nil
}

func (p *MockHSMProvider) CreateClient(config map[string]interface{}) (models.HSMClient, error) {
	mockConfig, err := parseMockHSMConfig(config)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeInvalidConfig,
			"Failed to parse mock HSM configuration", err).
			WithProvider(MockHSMProviderName)
	}

	if err := p.ValidateConfig(config); err != nil {
		return nil, err
	}

	client := &MockHSMClient{
		keys:           make(map[string]*MockKeyEntry),
		logger:         p.logger,
		config:         mockConfig,
		simulateErrors: mockConfig.SimulateErrors,
		latency:        mockConfig.SimulateLatency,
	}

	// Set up storage backend if persistent storage is enabled
	if mockConfig.PersistentStorage {
		storageConfig := mockConfig.StorageConfig
		if storageConfig == nil {
			// Default to memory storage for testing
			storageConfig = map[string]interface{}{
				"storage_type": "memory",
			}
		}

		// Create storage backend (reusing custom storage backend implementation)
		customProvider := NewCustomStorageProvider(p.logger)
		storage, err := customProvider.createStorageBackend(&CustomStorageConfig{
			StorageType:   "memory", // Default for mock
			StorageConfig: storageConfig,
			KeyPrefix:     mockConfig.KeyPrefix,
		})
		if err != nil {
			return nil, models.NewHSMErrorWithCause(models.ErrCodeConnectionFailed,
				"Failed to create mock HSM storage backend", err).
				WithProvider(MockHSMProviderName)
		}

		client.storageBackend = storage

		// Load existing keys if storage is available
		if err := client.loadKeysFromStorage(context.Background()); err != nil {
			p.logger.WithError(err).Warn("Failed to load keys from persistent storage")
		}
	}

	p.logger.WithFields(logrus.Fields{
		"persistent_storage": mockConfig.PersistentStorage,
		"simulate_errors":    mockConfig.SimulateErrors,
		"latency":            mockConfig.SimulateLatency,
		"test_scenarios":     mockConfig.TestScenarios,
	}).Info("Created mock HSM client")

	return client, nil
}

func (p *MockHSMProvider) Initialize(config map[string]interface{}) error {
	// Mock HSM provider doesn't need global initialization
	return nil
}

func (p *MockHSMProvider) Shutdown() error {
	// Mock HSM provider doesn't need cleanup
	return nil
}

// Client interface implementation
func (c *MockHSMClient) Health(ctx context.Context) (*models.HealthStatus, error) {
	start := time.Now()

	// Simulate latency if configured
	if c.latency > 0 {
		time.Sleep(c.latency)
	}

	// Check for test scenarios that should affect health
	if err := c.checkTestScenarios(ctx, "health"); err != nil {
		return &models.HealthStatus{
			Status:       "unhealthy",
			Provider:     MockHSMProviderName,
			LastCheck:    time.Now(),
			Error:        err.Error(),
			ResponseTime: time.Since(start),
			Details: map[string]string{
				"simulate_errors": fmt.Sprintf("%t", c.simulateErrors),
				"key_count":       fmt.Sprintf("%d", len(c.keys)),
			},
		}, err
	}

	details := map[string]string{
		"mode":            "mock",
		"simulate_errors": fmt.Sprintf("%t", c.simulateErrors),
		"key_count":       fmt.Sprintf("%d", len(c.keys)),
	}

	if c.storageBackend != nil {
		details["persistent_storage"] = "true"
	}

	return &models.HealthStatus{
		Status:       "healthy",
		Provider:     MockHSMProviderName,
		LastCheck:    time.Now(),
		ResponseTime: time.Since(start),
		Details:      details,
	}, nil
}

func (c *MockHSMClient) GetProviderInfo(ctx context.Context) (map[string]interface{}, error) {
	info := map[string]interface{}{
		"provider":           MockHSMProviderName,
		"version":            MockHSMProviderVersion,
		"mode":               "mock",
		"persistent_storage": c.config.PersistentStorage,
		"simulate_errors":    c.simulateErrors,
		"test_scenarios":     c.config.TestScenarios,
		"key_count":          len(c.keys),
	}

	if c.latency > 0 {
		info["simulated_latency"] = c.latency.String()
	}

	return info, nil
}

func (c *MockHSMClient) GenerateKey(ctx context.Context, spec models.KeySpec, name string) (*models.KeyHandle, error) {
	if err := c.checkTestScenarios(ctx, "generate_key"); err != nil {
		return nil, err
	}

	c.simulateLatency()

	// Validate key specification
	if err := c.validateKeySpec(spec); err != nil {
		return nil, err
	}

	// Check key limit
	if c.config.MaxKeys > 0 && len(c.keys) >= c.config.MaxKeys {
		return nil, models.NewHSMError(models.ErrCodeQuotaExceeded,
			fmt.Sprintf("Maximum key limit reached: %d", c.config.MaxKeys)).
			WithProvider(MockHSMProviderName)
	}

	// Generate key pair
	privateKey, publicKey, err := c.generateKeyPair(spec)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeKeyGenerationFailed,
			"Failed to generate key pair", err).
			WithProvider(MockHSMProviderName)
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
		ProviderID:    MockHSMProviderName,
		ProviderKeyID: keyID,
		Metadata: map[string]string{
			"mode":      "mock",
			"simulated": "true",
		},
	}

	if spec.KeyExpiration != nil {
		handle.ExpiresAt = spec.KeyExpiration
	}

	// Store key
	entry := &MockKeyEntry{
		Handle:     handle,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		CreatedAt:  time.Now(),
	}

	c.keysMutex.Lock()
	c.keys[keyID] = entry
	c.keysMutex.Unlock()

	// Save to persistent storage if enabled
	if c.storageBackend != nil {
		if err := c.saveKeyToStorage(ctx, entry); err != nil {
			c.logger.WithError(err).Warn("Failed to save key to persistent storage")
		}
	}

	c.logger.WithFields(logrus.Fields{
		"key_id":   keyID,
		"key_name": name,
		"key_type": spec.KeyType,
		"key_size": spec.KeySize,
	}).Info("Generated mock key")

	return handle, nil
}

func (c *MockHSMClient) ImportKey(ctx context.Context, keyData []byte, spec models.KeySpec, name string) (*models.KeyHandle, error) {
	if err := c.checkTestScenarios(ctx, "import_key"); err != nil {
		return nil, err
	}

	c.simulateLatency()

	// For mock HSM, we'll just generate a new key and pretend it was imported
	return c.GenerateKey(ctx, spec, name)
}

func (c *MockHSMClient) GetKey(ctx context.Context, keyHandle string) (*models.KeyHandle, error) {
	if err := c.checkTestScenarios(ctx, "get_key"); err != nil {
		return nil, err
	}

	c.simulateLatency()

	c.keysMutex.RLock()
	entry, exists := c.keys[keyHandle]
	c.keysMutex.RUnlock()

	if !exists {
		return nil, models.NewHSMError(models.ErrCodeKeyNotFound,
			fmt.Sprintf("Key not found: %s", keyHandle)).
			WithProvider(MockHSMProviderName)
	}

	// Update access tracking
	entry.AccessCount++
	entry.LastAccess = time.Now()

	return entry.Handle, nil
}

func (c *MockHSMClient) ListKeys(ctx context.Context) ([]*models.KeyHandle, error) {
	if err := c.checkTestScenarios(ctx, "list_keys"); err != nil {
		return nil, err
	}

	c.simulateLatency()

	c.keysMutex.RLock()
	defer c.keysMutex.RUnlock()

	handles := make([]*models.KeyHandle, 0, len(c.keys))
	for _, entry := range c.keys {
		handles = append(handles, entry.Handle)
	}

	return handles, nil
}

func (c *MockHSMClient) DeleteKey(ctx context.Context, keyHandle string) error {
	if err := c.checkTestScenarios(ctx, "delete_key"); err != nil {
		return err
	}

	c.simulateLatency()

	c.keysMutex.Lock()
	defer c.keysMutex.Unlock()

	if _, exists := c.keys[keyHandle]; !exists {
		return models.NewHSMError(models.ErrCodeKeyNotFound,
			fmt.Sprintf("Key not found: %s", keyHandle)).
			WithProvider(MockHSMProviderName)
	}

	delete(c.keys, keyHandle)

	// Delete from persistent storage if enabled
	if c.storageBackend != nil {
		keyPath := c.getKeyPath(keyHandle)
		if err := c.storageBackend.Delete(ctx, keyPath); err != nil {
			c.logger.WithError(err).Warn("Failed to delete key from persistent storage")
		}
	}

	return nil
}

func (c *MockHSMClient) ActivateKey(ctx context.Context, keyHandle string) error {
	return c.updateKeyState(ctx, keyHandle, models.KeyStateActive)
}

func (c *MockHSMClient) DeactivateKey(ctx context.Context, keyHandle string) error {
	return c.updateKeyState(ctx, keyHandle, models.KeyStateInactive)
}

func (c *MockHSMClient) SetKeyExpiration(ctx context.Context, keyHandle string, expiration time.Time) error {
	if err := c.checkTestScenarios(ctx, "set_key_expiration"); err != nil {
		return err
	}

	c.simulateLatency()

	c.keysMutex.Lock()
	defer c.keysMutex.Unlock()

	entry, exists := c.keys[keyHandle]
	if !exists {
		return models.NewHSMError(models.ErrCodeKeyNotFound,
			fmt.Sprintf("Key not found: %s", keyHandle)).
			WithProvider(MockHSMProviderName)
	}

	entry.Handle.ExpiresAt = &expiration
	entry.Handle.UpdatedAt = time.Now()

	return nil
}

func (c *MockHSMClient) GetPublicKey(ctx context.Context, keyHandle string) (crypto.PublicKey, error) {
	if err := c.checkTestScenarios(ctx, "get_public_key"); err != nil {
		return nil, err
	}

	c.simulateLatency()

	c.keysMutex.RLock()
	entry, exists := c.keys[keyHandle]
	c.keysMutex.RUnlock()

	if !exists {
		return nil, models.NewHSMError(models.ErrCodeKeyNotFound,
			fmt.Sprintf("Key not found: %s", keyHandle)).
			WithProvider(MockHSMProviderName)
	}

	// Update access tracking
	entry.AccessCount++
	entry.LastAccess = time.Now()

	return entry.PublicKey, nil
}

func (c *MockHSMClient) Sign(ctx context.Context, request models.SigningRequest) (*models.SigningResponse, error) {
	if err := c.checkTestScenarios(ctx, "sign"); err != nil {
		return nil, err
	}

	c.simulateLatency()

	c.keysMutex.RLock()
	entry, exists := c.keys[request.KeyHandle]
	c.keysMutex.RUnlock()

	if !exists {
		return nil, models.NewHSMError(models.ErrCodeKeyNotFound,
			fmt.Sprintf("Key not found: %s", request.KeyHandle)).
			WithProvider(MockHSMProviderName)
	}

	// Check key state
	if entry.Handle.State != models.KeyStateActive {
		return nil, models.NewHSMError(models.ErrCodeKeyInactive,
			"Key is not active").
			WithProvider(MockHSMProviderName)
	}

	// Perform signing
	signature, err := c.performSigning(entry.PrivateKey, request.Data, request.Algorithm)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeSigningFailed,
			"Signing operation failed", err).
			WithProvider(MockHSMProviderName)
	}

	// Update access tracking
	entry.AccessCount++
	entry.LastAccess = time.Now()

	return &models.SigningResponse{
		Signature: signature,
		Algorithm: request.Algorithm,
		KeyID:     request.KeyHandle,
		Metadata: map[string]string{
			"mode":         "mock",
			"access_count": fmt.Sprintf("%d", entry.AccessCount),
		},
	}, nil
}

func (c *MockHSMClient) Verify(ctx context.Context, keyHandle string, data, signature []byte, algorithm string) (bool, error) {
	if err := c.checkTestScenarios(ctx, "verify"); err != nil {
		return false, err
	}

	c.simulateLatency()

	publicKey, err := c.GetPublicKey(ctx, keyHandle)
	if err != nil {
		return false, err
	}

	return c.performVerification(publicKey, data, signature, algorithm)
}

func (c *MockHSMClient) Encrypt(ctx context.Context, request models.EncryptionRequest) (*models.EncryptionResponse, error) {
	if err := c.checkTestScenarios(ctx, "encrypt"); err != nil {
		return nil, err
	}

	c.simulateLatency()

	// For mock HSM, return mock encrypted data
	return &models.EncryptionResponse{
		Ciphertext: append([]byte("MOCK_ENCRYPTED:"), request.Plaintext...),
		Algorithm:  request.Algorithm,
		KeyID:      request.KeyHandle,
		Metadata: map[string]string{
			"mode": "mock",
		},
	}, nil
}

func (c *MockHSMClient) Decrypt(ctx context.Context, request models.DecryptionRequest) (*models.DecryptionResponse, error) {
	if err := c.checkTestScenarios(ctx, "decrypt"); err != nil {
		return nil, err
	}

	c.simulateLatency()

	// For mock HSM, return mock decrypted data
	const prefix = "MOCK_ENCRYPTED:"
	if len(request.Ciphertext) > len(prefix) && string(request.Ciphertext[:len(prefix)]) == prefix {
		return &models.DecryptionResponse{
			Plaintext: request.Ciphertext[len(prefix):],
			Algorithm: request.Algorithm,
			KeyID:     request.KeyHandle,
			Metadata: map[string]string{
				"mode": "mock",
			},
		}, nil
	}

	return nil, models.NewHSMError(models.ErrCodeDecryptionFailed,
		"Invalid mock ciphertext format").
		WithProvider(MockHSMProviderName)
}

func (c *MockHSMClient) WrapKey(ctx context.Context, request models.KeyWrapRequest) (*models.KeyWrapResponse, error) {
	if err := c.checkTestScenarios(ctx, "wrap_key"); err != nil {
		return nil, err
	}

	c.simulateLatency()

	// For mock HSM, return mock wrapped key
	return &models.KeyWrapResponse{
		WrappedKey: append([]byte("MOCK_WRAPPED:"), request.KeyToWrap...),
		Algorithm:  request.Algorithm,
		KEKId:      request.KEKHandle,
		Metadata: map[string]string{
			"mode": "mock",
		},
	}, nil
}

func (c *MockHSMClient) UnwrapKey(ctx context.Context, request models.KeyUnwrapRequest) (*models.KeyUnwrapResponse, error) {
	if err := c.checkTestScenarios(ctx, "unwrap_key"); err != nil {
		return nil, err
	}

	c.simulateLatency()

	// For mock HSM, return mock unwrapped key
	const prefix = "MOCK_WRAPPED:"
	if len(request.WrappedKey) > len(prefix) && string(request.WrappedKey[:len(prefix)]) == prefix {
		return &models.KeyUnwrapResponse{
			UnwrappedKey: request.WrappedKey[len(prefix):],
			Algorithm:    request.Algorithm,
			KEKId:        request.KEKHandle,
			Metadata: map[string]string{
				"mode": "mock",
			},
		}, nil
	}

	return nil, models.NewHSMError(models.ErrCodeKeyUnwrapFailed,
		"Invalid mock wrapped key format").
		WithProvider(MockHSMProviderName)
}

func (c *MockHSMClient) Close() error {
	if c.storageBackend != nil {
		return c.storageBackend.Close()
	}
	return nil
}

// Helper functions
func parseMockHSMConfig(config map[string]interface{}) (*MockHSMConfig, error) {
	mockConfig := &MockHSMConfig{
		KeyPrefix: "mock-hsm",
		MaxKeys:   1000, // Default key limit
	}

	if persistentStorage, ok := config["persistent_storage"].(bool); ok {
		mockConfig.PersistentStorage = persistentStorage
	}

	if storageConfig, ok := config["storage_config"].(map[string]interface{}); ok {
		mockConfig.StorageConfig = storageConfig
	}

	if simulateErrors, ok := config["simulate_errors"].(bool); ok {
		mockConfig.SimulateErrors = simulateErrors
	}

	if latencyMs, ok := config["simulate_latency_ms"].(float64); ok {
		mockConfig.SimulateLatency = time.Duration(latencyMs) * time.Millisecond
	}

	if maxKeys, ok := config["max_keys"].(float64); ok {
		mockConfig.MaxKeys = int(maxKeys)
	}

	if keyPrefix, ok := config["key_prefix"].(string); ok {
		mockConfig.KeyPrefix = keyPrefix
	}

	if scenarios, ok := config["test_scenarios"].([]interface{}); ok {
		for _, scenario := range scenarios {
			if scenarioStr, ok := scenario.(string); ok {
				mockConfig.TestScenarios = append(mockConfig.TestScenarios, scenarioStr)
			}
		}
	}

	return mockConfig, nil
}

func (c *MockHSMClient) generateKeyPair(spec models.KeySpec) (crypto.PrivateKey, crypto.PublicKey, error) {
	return cryptoutils.GenerateKeyPair(spec)
}

// validateKeySpec validates the key specification
func (c *MockHSMClient) validateKeySpec(spec models.KeySpec) error {
	// Validate key type
	switch spec.KeyType {
	case models.KeyTypeRSA:
		// RSA key size validation
		if spec.KeySize < 2048 || spec.KeySize > 4096 {
			return models.NewHSMError(models.ErrCodeInvalidKeySpec,
				fmt.Sprintf("Invalid RSA key size: %d. Must be between 2048 and 4096", spec.KeySize)).
				WithProvider(MockHSMProviderName)
		}
		// RSA key sizes must be multiples of 1024 for this mock
		if spec.KeySize%1024 != 0 {
			return models.NewHSMError(models.ErrCodeInvalidKeySpec,
				fmt.Sprintf("Invalid RSA key size: %d. Must be multiple of 1024", spec.KeySize)).
				WithProvider(MockHSMProviderName)
		}
	case models.KeyTypeECDSA:
		// ECDSA curve validation
		switch spec.KeySize {
		case 256, 384, 521: // P-256, P-384, P-521
			// Valid ECDSA key sizes
		default:
			return models.NewHSMError(models.ErrCodeInvalidKeySpec,
				fmt.Sprintf("Invalid ECDSA key size: %d. Must be 256, 384, or 521", spec.KeySize)).
				WithProvider(MockHSMProviderName)
		}
	case models.KeyTypeEd25519:
		// Ed25519 has fixed key size
		if spec.KeySize != 256 {
			return models.NewHSMError(models.ErrCodeInvalidKeySpec,
				fmt.Sprintf("Invalid Ed25519 key size: %d. Must be 256", spec.KeySize)).
				WithProvider(MockHSMProviderName)
		}
	default:
		return models.NewHSMError(models.ErrCodeInvalidKeySpec,
			fmt.Sprintf("Unsupported key type: %s", spec.KeyType)).
			WithProvider(MockHSMProviderName)
	}

	// Validate algorithm
	switch spec.Algorithm {
	case "RS256", "RS384", "RS512", "RSA-PSS":
		if spec.KeyType != models.KeyTypeRSA {
			return models.NewHSMError(models.ErrCodeInvalidKeySpec,
				fmt.Sprintf("Algorithm %s requires RSA key type", spec.Algorithm)).
				WithProvider(MockHSMProviderName)
		}
	case "ES256", "ES384", "ES512":
		if spec.KeyType != models.KeyTypeECDSA {
			return models.NewHSMError(models.ErrCodeInvalidKeySpec,
				fmt.Sprintf("Algorithm %s requires ECDSA key type", spec.Algorithm)).
				WithProvider(MockHSMProviderName)
		}
	case "EdDSA":
		if spec.KeyType != models.KeyTypeEd25519 {
			return models.NewHSMError(models.ErrCodeInvalidKeySpec,
				fmt.Sprintf("Algorithm %s requires Ed25519 key type", spec.Algorithm)).
				WithProvider(MockHSMProviderName)
		}
	default:
		return models.NewHSMError(models.ErrCodeInvalidAlgorithm,
			fmt.Sprintf("Unsupported algorithm: %s", spec.Algorithm)).
			WithProvider(MockHSMProviderName)
	}

	// Validate usage
	if len(spec.Usage) == 0 {
		return models.NewHSMError(models.ErrCodeInvalidKeySpec,
			"Key usage must be specified").
			WithProvider(MockHSMProviderName)
	}

	return nil
}

func (c *MockHSMClient) performSigning(privateKey crypto.PrivateKey, data []byte, algorithm string) ([]byte, error) {
	// The data might already be a hash digest from crypto.Signer interface
	// For crypto.Signer compliance, we assume data is already a proper digest
	var hash []byte
	
	// Check if data looks like a hash (32 bytes for SHA-256)
	if len(data) == 32 {
		// Assume this is already a SHA-256 hash digest from crypto.Signer
		hash = data
	} else {
		// For raw data, compute hash
		hashSum := sha256.Sum256(data)
		hash = hashSum[:]
	}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		// Use PKCS1v15 for RS256, PSS for RSA-PSS
		if algorithm == "RSA-PSS" {
			return rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash, nil)
		} else {
			// Default to PKCS1v15 for RS256
			return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash)
		}
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, hash)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(struct{ R, S *big.Int }{r, s})
	case ed25519.PrivateKey:
		// Ed25519 signs the original data, not the hash
		if len(data) == 32 {
			// If we received a hash, we need to sign it directly
			return ed25519.Sign(key, data), nil
		} else {
			return ed25519.Sign(key, data), nil
		}
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

func (c *MockHSMClient) performVerification(publicKey crypto.PublicKey, data, signature []byte, algorithm string) (bool, error) {
	// Handle both raw data and pre-computed hashes like the signing method
	var hash []byte
	
	// Check if data looks like a hash (32 bytes for SHA-256)
	if len(data) == 32 {
		// Assume this is already a SHA-256 hash digest
		hash = data
	} else {
		// For raw data, compute hash
		hashSum := sha256.Sum256(data)
		hash = hashSum[:]
	}

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		// Use PKCS1v15 for RS256, PSS for RSA-PSS
		if algorithm == "RSA-PSS" {
			err := rsa.VerifyPSS(key, crypto.SHA256, hash, signature, nil)
			return err == nil, nil
		} else {
			// Default to PKCS1v15 for RS256
			err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash, signature)
			return err == nil, nil
		}
	case *ecdsa.PublicKey:
		var sig struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(signature, &sig); err != nil {
			return false, err
		}
		return ecdsa.Verify(key, hash, sig.R, sig.S), nil
	case ed25519.PublicKey:
		return ed25519.Verify(key, data, signature), nil
	default:
		return false, fmt.Errorf("unsupported public key type")
	}
}

func (c *MockHSMClient) simulateLatency() {
	if c.latency > 0 {
		time.Sleep(c.latency)
	}
}

func (c *MockHSMClient) checkTestScenarios(ctx context.Context, operation string) error {
	if !c.simulateErrors || len(c.config.TestScenarios) == 0 {
		return nil
	}

	// Check if any test scenarios should trigger for this operation
	for _, scenarioName := range c.config.TestScenarios {
		if scenario, exists := TestScenarios[scenarioName]; exists {
			// Use crypto/rand for security-sensitive randomness instead of math/rand
			randomBytes := make([]byte, 1)
			if _, err := rand.Read(randomBytes); err != nil {
				c.logger.WithError(err).Warn("Failed to generate secure random number for test scenarios")
				continue
			}
			// 10% chance to trigger (randomByte < 26 out of 256 possible values ≈ 10%)
			if randomBytes[0] < 26 {
				return scenario.Handler(ctx, c, operation)
			}
		}
	}

	return nil
}

func (c *MockHSMClient) updateKeyState(ctx context.Context, keyHandle string, state models.KeyState) error {
	if err := c.checkTestScenarios(ctx, "update_key_state"); err != nil {
		return err
	}

	c.simulateLatency()

	c.keysMutex.Lock()
	defer c.keysMutex.Unlock()

	entry, exists := c.keys[keyHandle]
	if !exists {
		return models.NewHSMError(models.ErrCodeKeyNotFound,
			fmt.Sprintf("Key not found: %s", keyHandle)).
			WithProvider(MockHSMProviderName)
	}

	entry.Handle.State = state
	entry.Handle.UpdatedAt = time.Now()

	return nil
}

func (c *MockHSMClient) loadKeysFromStorage(ctx context.Context) error {
	if c.storageBackend == nil {
		return nil
	}

	prefix := c.getKeyPrefix()
	keys, err := c.storageBackend.List(ctx, prefix)
	if err != nil {
		return err
	}

	for _, keyPath := range keys {
		// Implementation would load key data from storage
		// For now, this is a placeholder
		c.logger.WithField("key_path", keyPath).Debug("Would load key from storage")
	}

	return nil
}

func (c *MockHSMClient) saveKeyToStorage(ctx context.Context, entry *MockKeyEntry) error {
	if c.storageBackend == nil {
		return nil
	}

	keyPath := c.getKeyPath(entry.Handle.ID)

	// For mock implementation, just save minimal metadata
	data := []byte(fmt.Sprintf("mock_key_%s_%s", entry.Handle.ID, entry.Handle.KeyType))

	return c.storageBackend.Store(ctx, keyPath, data)
}

func (c *MockHSMClient) getKeyPath(keyID string) string {
	return fmt.Sprintf("%s/keys/%s", c.config.KeyPrefix, keyID)
}

func (c *MockHSMClient) getKeyPrefix() string {
	return fmt.Sprintf("%s/keys/", c.config.KeyPrefix)
}

// Testing utilities
func (c *MockHSMClient) GetKeyAccessStats() map[string]int {
	c.keysMutex.RLock()
	defer c.keysMutex.RUnlock()

	stats := make(map[string]int)
	for keyID, entry := range c.keys {
		stats[keyID] = entry.AccessCount
	}
	return stats
}

func (c *MockHSMClient) ResetAccessStats() {
	c.keysMutex.Lock()
	defer c.keysMutex.Unlock()

	for _, entry := range c.keys {
		entry.AccessCount = 0
		entry.LastAccess = time.Time{}
	}
}

func (c *MockHSMClient) SetSimulateErrors(enabled bool) {
	c.simulateErrors = enabled
}

func (c *MockHSMClient) SetLatency(latency time.Duration) {
	c.latency = latency
}
