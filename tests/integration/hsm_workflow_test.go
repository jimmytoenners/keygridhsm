package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/jimmy/keygridhsm/internal/core"
	"github.com/jimmy/keygridhsm/internal/providers"
	"github.com/jimmy/keygridhsm/pkg/models"
)

// HSMIntegrationTestSuite is the test suite for HSM integration tests
type HSMIntegrationTestSuite struct {
	suite.Suite
	registry *core.ProviderRegistry
	manager  *core.HSMManager
	ctx      context.Context
}

// SetupSuite initializes the test suite
func (suite *HSMIntegrationTestSuite) SetupSuite() {
	suite.ctx = context.Background()
	suite.registry = core.NewProviderRegistry()
	
	// Create logger with reduced verbosity for tests
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	// Register all providers
	mockProvider := providers.NewMockHSMProvider(logger)
	err := suite.registry.RegisterProvider("mock-hsm", mockProvider)
	require.NoError(suite.T(), err)
	
	customProvider := providers.NewCustomStorageProvider(logger)
	err = suite.registry.RegisterProvider("custom-storage", customProvider)
	require.NoError(suite.T(), err)
	
	// Create HSM manager
	suite.manager = core.NewHSMManager(core.HSMManagerConfig{
		Registry: suite.registry,
		Logger:   logger,
	})
}

// TestCompleteKeyLifecycle tests the complete lifecycle of a key
func (suite *HSMIntegrationTestSuite) TestCompleteKeyLifecycle() {
	providerConfigs := map[string]map[string]interface{}{
		"mock-hsm": {
			"persistent_storage": false,
			"simulate_errors":    false,
			"max_keys":          1000,
			"key_prefix":        "integration-test",
		},
		"custom-storage": {
			"storage_type":     "memory",
			"encrypt_at_rest":  true,
			"encryption_key":   "test-encryption-key-32-chars-12",
			"key_prefix":       "integration-test",
		},
	}
	
	for providerName, config := range providerConfigs {
		suite.Run(providerName, func() {
			suite.testKeyLifecycleForProvider(providerName, config)
		})
	}
}

func (suite *HSMIntegrationTestSuite) testKeyLifecycleForProvider(providerName string, config map[string]interface{}) {
	// 1. Generate a key
	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}
	
	keyHandle, err := suite.manager.GenerateKey(suite.ctx, providerName, config, keySpec, "integration-test-key")
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), keyHandle.ID)
	assert.Equal(suite.T(), models.KeyTypeRSA, keyHandle.KeyType)
	assert.Equal(suite.T(), 2048, keyHandle.KeySize)
	assert.Equal(suite.T(), models.KeyStateActive, keyHandle.State)
	
	// 2. List keys and verify our key is there
	keys, err := suite.manager.ListKeys(suite.ctx, providerName, config)
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), keys)
	
	found := false
	for _, key := range keys {
		if key.ID == keyHandle.ID {
			found = true
			break
		}
	}
	assert.True(suite.T(), found, "Generated key should be found in key list")
	
	// 3. Retrieve the key
	retrievedKey, err := suite.manager.GetKey(suite.ctx, providerName, config, keyHandle.ID)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), keyHandle.ID, retrievedKey.ID)
	assert.Equal(suite.T(), keyHandle.KeyType, retrievedKey.KeyType)
	assert.Equal(suite.T(), keyHandle.KeySize, retrievedKey.KeySize)
	
	// 4. Get public key
	publicKey, err := suite.manager.GetPublicKey(suite.ctx, providerName, config, keyHandle.ID)
	require.NoError(suite.T(), err)
	assert.NotNil(suite.T(), publicKey)
	
	// 5. Sign data
	testData := []byte("Hello, KeyGrid HSM Integration Test!")
	signingRequest := models.SigningRequest{
		KeyHandle: keyHandle.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}
	
	sigResponse, err := suite.manager.Sign(suite.ctx, providerName, config, signingRequest)
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), sigResponse.Signature)
	assert.Equal(suite.T(), "RSA-PSS", sigResponse.Algorithm)
	assert.Equal(suite.T(), keyHandle.ID, sigResponse.KeyID)
	
	// 6. Verify signature
	valid, err := suite.manager.Verify(suite.ctx, providerName, config, keyHandle.ID, testData, sigResponse.Signature, "RSA-PSS")
	require.NoError(suite.T(), err)
	assert.True(suite.T(), valid, "Signature should be valid")
	
	// 7. Test with invalid data (signature should not verify)
	invalidData := []byte("Invalid data")
	valid, err = suite.manager.Verify(suite.ctx, providerName, config, keyHandle.ID, invalidData, sigResponse.Signature, "RSA-PSS")
	require.NoError(suite.T(), err)
	assert.False(suite.T(), valid, "Signature should not be valid for different data")
	
	// 8. Deactivate key
	err = suite.manager.DeactivateKey(suite.ctx, providerName, config, keyHandle.ID)
	require.NoError(suite.T(), err)
	
	// 9. Activate key again
	err = suite.manager.ActivateKey(suite.ctx, providerName, config, keyHandle.ID)
	require.NoError(suite.T(), err)
	
	// 10. Delete key
	err = suite.manager.DeleteKey(suite.ctx, providerName, config, keyHandle.ID)
	require.NoError(suite.T(), err)
	
	// 11. Verify key is deleted
	_, err = suite.manager.GetKey(suite.ctx, providerName, config, keyHandle.ID)
	assert.Error(suite.T(), err, "Deleted key should not be retrievable")
}

// TestMultipleKeyTypes tests different key types
func (suite *HSMIntegrationTestSuite) TestMultipleKeyTypes() {
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "key-types-test",
	}
	
	keySpecs := []struct {
		name     string
		keyType  models.KeyType
		keySize  int
		algorithm string
	}{
		{"RSA-2048", models.KeyTypeRSA, 2048, "RSA-PSS"},
		{"RSA-4096", models.KeyTypeRSA, 4096, "RSA-PSS"},
		{"ECDSA-P256", models.KeyTypeECDSA, 256, "ECDSA"},
		{"ECDSA-P384", models.KeyTypeECDSA, 384, "ECDSA"},
		{"Ed25519", models.KeyTypeEd25519, 256, "Ed25519"},
	}
	
	generatedKeys := []string{}
	
	for _, spec := range keySpecs {
		suite.Run(spec.name, func() {
			keySpec := models.KeySpec{
				KeyType:   spec.keyType,
				KeySize:   spec.keySize,
				Algorithm: spec.algorithm,
				Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
			}
			
			keyHandle, err := suite.manager.GenerateKey(suite.ctx, "mock-hsm", config, keySpec, spec.name)
			require.NoError(suite.T(), err)
			assert.Equal(suite.T(), spec.keyType, keyHandle.KeyType)
			assert.Equal(suite.T(), spec.keySize, keyHandle.KeySize)
			
			generatedKeys = append(generatedKeys, keyHandle.ID)
			
			// Test signing with each key type
			testData := []byte("Test data for " + spec.name)
			signingRequest := models.SigningRequest{
				KeyHandle: keyHandle.ID,
				Data:      testData,
				Algorithm: spec.algorithm,
			}
			
			sigResponse, err := suite.manager.Sign(suite.ctx, "mock-hsm", config, signingRequest)
			require.NoError(suite.T(), err)
			assert.NotEmpty(suite.T(), sigResponse.Signature)
			
			// Verify signature
			valid, err := suite.manager.Verify(suite.ctx, "mock-hsm", config, keyHandle.ID, testData, sigResponse.Signature, spec.algorithm)
			require.NoError(suite.T(), err)
			assert.True(suite.T(), valid)
		})
	}
	
	// Clean up all generated keys
	for _, keyID := range generatedKeys {
		_ = suite.manager.DeleteKey(suite.ctx, "mock-hsm", config, keyID)
	}
}

// TestConcurrentOperations tests concurrent key operations
func (suite *HSMIntegrationTestSuite) TestConcurrentOperations() {
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "concurrent-test",
	}
	
	const numGoroutines = 10
	results := make(chan error, numGoroutines)
	keyIDs := make(chan string, numGoroutines)
	
	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}
	
	// Generate keys concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			keyName := fmt.Sprintf("concurrent-key-%d", id)
			keyHandle, err := suite.manager.GenerateKey(suite.ctx, "mock-hsm", config, keySpec, keyName)
			if err != nil {
				results <- err
				return
			}
			keyIDs <- keyHandle.ID
			results <- nil
		}(i)
	}
	
	// Collect results
	generatedKeys := []string{}
	for i := 0; i < numGoroutines; i++ {
		err := <-results
		assert.NoError(suite.T(), err)
		if err == nil {
			keyID := <-keyIDs
			generatedKeys = append(generatedKeys, keyID)
		}
	}
	
	assert.Len(suite.T(), generatedKeys, numGoroutines)
	
	// Test concurrent signing operations
	testData := []byte("Concurrent signing test data")
	for _, keyID := range generatedKeys {
		go func(id string) {
			signingRequest := models.SigningRequest{
				KeyHandle: id,
				Data:      testData,
				Algorithm: "RSA-PSS",
			}
			
			_, err := suite.manager.Sign(suite.ctx, "mock-hsm", config, signingRequest)
			results <- err
		}(keyID)
	}
	
	// Collect signing results
	for i := 0; i < len(generatedKeys); i++ {
		err := <-results
		assert.NoError(suite.T(), err)
	}
	
	// Clean up
	for _, keyID := range generatedKeys {
		_ = suite.manager.DeleteKey(suite.ctx, "mock-hsm", config, keyID)
	}
}

// TestEncryptionDecryption tests encryption/decryption operations
func (suite *HSMIntegrationTestSuite) TestEncryptionDecryption() {
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "encryption-test",
	}
	
	// Generate RSA key for encryption
	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-OAEP",
		Usage:     []models.KeyUsage{models.KeyUsageEncrypt, models.KeyUsageDecrypt},
	}
	
	keyHandle, err := suite.manager.GenerateKey(suite.ctx, "mock-hsm", config, keySpec, "encryption-test-key")
	require.NoError(suite.T(), err)
	
	// Test data
	plaintext := []byte("Secret message for encryption test")
	
	// Encrypt
	encRequest := models.EncryptionRequest{
		KeyHandle: keyHandle.ID,
		Plaintext: plaintext,
		Algorithm: "RSA-OAEP",
	}
	
	encResponse, err := suite.manager.Encrypt(suite.ctx, "mock-hsm", config, encRequest)
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), encResponse.Ciphertext)
	assert.NotEqual(suite.T(), plaintext, encResponse.Ciphertext)
	
	// Decrypt
	decRequest := models.DecryptionRequest{
		KeyHandle:  keyHandle.ID,
		Ciphertext: encResponse.Ciphertext,
		Algorithm:  "RSA-OAEP",
	}
	
	decResponse, err := suite.manager.Decrypt(suite.ctx, "mock-hsm", config, decRequest)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), plaintext, decResponse.Plaintext)
	
	// Clean up
	_ = suite.manager.DeleteKey(suite.ctx, "mock-hsm", config, keyHandle.ID)
}

// TestKeyExpiration tests key expiration functionality
func (suite *HSMIntegrationTestSuite) TestKeyExpiration() {
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "expiration-test",
	}
	
	// Generate key with expiration
	expiration := time.Now().Add(time.Hour)
	keySpec := models.KeySpec{
		KeyType:       models.KeyTypeRSA,
		KeySize:       2048,
		Algorithm:     "RSA-PSS",
		Usage:         []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
		KeyExpiration: &expiration,
	}
	
	keyHandle, err := suite.manager.GenerateKey(suite.ctx, "mock-hsm", config, keySpec, "expiration-test-key")
	require.NoError(suite.T(), err)
	assert.NotNil(suite.T(), keyHandle.ExpiresAt)
	
	// Set expiration to a different time
	newExpiration := time.Now().Add(2 * time.Hour)
	err = suite.manager.SetKeyExpiration(suite.ctx, "mock-hsm", config, keyHandle.ID, newExpiration)
	require.NoError(suite.T(), err)
	
	// Retrieve key and verify expiration was updated
	updatedKey, err := suite.manager.GetKey(suite.ctx, "mock-hsm", config, keyHandle.ID)
	require.NoError(suite.T(), err)
	assert.NotNil(suite.T(), updatedKey.ExpiresAt)
	// Note: Exact time comparison might be tricky due to precision, so we check if it's close
	assert.WithinDuration(suite.T(), newExpiration, *updatedKey.ExpiresAt, time.Second)
	
	// Clean up
	_ = suite.manager.DeleteKey(suite.ctx, "mock-hsm", config, keyHandle.ID)
}

// TestErrorHandling tests various error conditions
func (suite *HSMIntegrationTestSuite) TestErrorHandling() {
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "error-test",
	}
	
	// Test operations with invalid key ID
	invalidKeyID := "non-existent-key-id"
	
	// Get non-existent key
	_, err := suite.manager.GetKey(suite.ctx, "mock-hsm", config, invalidKeyID)
	assert.Error(suite.T(), err)
	
	// Delete non-existent key
	err = suite.manager.DeleteKey(suite.ctx, "mock-hsm", config, invalidKeyID)
	assert.Error(suite.T(), err)
	
	// Sign with non-existent key
	signingRequest := models.SigningRequest{
		KeyHandle: invalidKeyID,
		Data:      []byte("test data"),
		Algorithm: "RSA-PSS",
	}
	_, err = suite.manager.Sign(suite.ctx, "mock-hsm", config, signingRequest)
	assert.Error(suite.T(), err)
	
	// Test with invalid provider
	_, err = suite.manager.GenerateKey(suite.ctx, "non-existent-provider", config, models.KeySpec{}, "test-key")
	assert.Error(suite.T(), err)
}

// TestProviderHealthChecks tests health check functionality
func (suite *HSMIntegrationTestSuite) TestProviderHealthChecks() {
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
	}
	
	providers := []string{"mock-hsm", "custom-storage"}
	
	for _, providerName := range providers {
		suite.Run(providerName, func() {
			health, err := suite.manager.CheckProviderHealth(suite.ctx, providerName, config)
			require.NoError(suite.T(), err)
			assert.Equal(suite.T(), "healthy", health.Status)
			assert.Equal(suite.T(), providerName, health.Provider)
			assert.True(suite.T(), health.ResponseTime > 0)
		})
	}
}

// Run the integration test suite
func TestHSMIntegrationSuite(t *testing.T) {
	suite.Run(t, new(HSMIntegrationTestSuite))
}

// TestLongRunningOperations tests operations that might take longer
func (suite *HSMIntegrationTestSuite) TestLongRunningOperations() {
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"simulate_latency_ms": 100, // Add some latency to simulate real-world conditions
		"max_keys":          1000,
		"key_prefix":        "long-running-test",
	}
	
	// Generate multiple large keys
	keySpecs := []models.KeySpec{
		{
			KeyType:   models.KeyTypeRSA,
			KeySize:   4096, // Larger key size
			Algorithm: "RSA-PSS",
			Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
		},
	}
	
	for i, spec := range keySpecs {
		keyName := fmt.Sprintf("large-key-%d", i)
		
		start := time.Now()
		keyHandle, err := suite.manager.GenerateKey(suite.ctx, "mock-hsm", config, spec, keyName)
		duration := time.Since(start)
		
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), spec.KeySize, keyHandle.KeySize)
		
		// Log the duration for performance monitoring
		suite.T().Logf("Generated %d-bit %s key in %v", spec.KeySize, spec.KeyType, duration)
		
		// Clean up
		_ = suite.manager.DeleteKey(suite.ctx, "mock-hsm", config, keyHandle.ID)
	}
}