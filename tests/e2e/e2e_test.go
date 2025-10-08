package e2e

import (
	"context"
	"fmt"
	"os"
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

// E2ETestSuite contains end-to-end tests for the complete HSM system
type E2ETestSuite struct {
	suite.Suite
	registry    *core.ProviderRegistry
	manager     *core.HSMManager
}

// SetupSuite initializes the test environment
func (s *E2ETestSuite) SetupSuite() {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise for tests

	// Initialize registry and manager
	s.registry = core.NewProviderRegistry()

	// Register providers
	mockProvider := providers.NewMockHSMProvider(logger)
	err := s.registry.RegisterProvider("mock-hsm", mockProvider)
	s.Require().NoError(err)

	customProvider := providers.NewCustomStorageProvider(logger)
	err = s.registry.RegisterProvider("custom-storage", customProvider)
	s.Require().NoError(err)

	s.manager = core.NewHSMManager(core.HSMManagerConfig{
		Registry: s.registry,
		Logger:   logger,
	})
}

// TearDownSuite cleans up the test environment
func (s *E2ETestSuite) TearDownSuite() {
	// Cleanup any remaining test resources
	// This will be expanded as needed
}

// TestCompleteKeyLifecycle tests the complete key lifecycle from creation to deletion
func (s *E2ETestSuite) TestCompleteKeyLifecycle() {
	ctx := context.Background()
	
	// Test configuration
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "e2e-lifecycle",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Step 1: Generate key
	keyHandle, err := s.manager.GenerateKey(ctx, "mock-hsm", config, keySpec, "e2e-test-key")
	s.Require().NoError(err)
	s.Assert().NotEmpty(keyHandle.ID)
	s.Assert().Equal(models.KeyStatusActive, keyHandle.Status)

	defer func() {
		// Always try to clean up, ignore errors since key might be deleted in test
		_ = s.manager.DeleteKey(ctx, "mock-hsm", config, keyHandle.ID)
	}()

	// Step 2: List keys and verify our key is present
	keys, err := s.manager.ListKeys(ctx, "mock-hsm", config)
	s.Require().NoError(err)
	
	found := false
	for _, key := range keys {
		if key.ID == keyHandle.ID {
			found = true
			s.Assert().Equal(keyHandle.Name, key.Name)
			s.Assert().Equal(keyHandle.KeyType, key.KeyType)
			s.Assert().Equal(keyHandle.KeySize, key.KeySize)
			break
		}
	}
	s.Assert().True(found, "Generated key should be found in key listing")

	// Step 3: Get specific key
	retrievedKey, err := s.manager.GetKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Require().NoError(err)
	s.Assert().Equal(keyHandle.ID, retrievedKey.ID)
	s.Assert().Equal(keyHandle.Name, retrievedKey.Name)

	// Step 4: Sign data with the key
	testData := []byte("End-to-end test data for signing")
	signingRequest := models.SigningRequest{
		KeyHandle: keyHandle.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}

	sigResponse, err := s.manager.Sign(ctx, "mock-hsm", config, signingRequest)
	s.Require().NoError(err)
	s.Assert().NotEmpty(sigResponse.Signature)
	s.Assert().Equal(keyHandle.ID, sigResponse.KeyHandle)

	// Step 5: Verify the signature
	valid, err := s.manager.Verify(ctx, "mock-hsm", config, keyHandle.ID, 
		testData, sigResponse.Signature, "RSA-PSS")
	s.Require().NoError(err)
	s.Assert().True(valid, "Signature should verify successfully")

	// Step 6: Test key deactivation
	err = s.manager.DeactivateKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Require().NoError(err)

	// Verify key is deactivated
	deactivatedKey, err := s.manager.GetKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Require().NoError(err)
	s.Assert().Equal(models.KeyStatusInactive, deactivatedKey.Status)

	// Deactivated key should not be able to sign
	_, err = s.manager.Sign(ctx, "mock-hsm", config, signingRequest)
	s.Assert().Error(err, "Deactivated key should not be able to sign")

	// Step 7: Reactivate key
	err = s.manager.ActivateKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Require().NoError(err)

	// Verify key is active again
	reactivatedKey, err := s.manager.GetKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Require().NoError(err)
	s.Assert().Equal(models.KeyStatusActive, reactivatedKey.Status)

	// Should be able to sign again
	sigResponse2, err := s.manager.Sign(ctx, "mock-hsm", config, signingRequest)
	s.Require().NoError(err)
	s.Assert().NotEmpty(sigResponse2.Signature)

	// Step 8: Delete the key
	err = s.manager.DeleteKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Require().NoError(err)

	// Step 9: Verify key is completely gone
	_, err = s.manager.GetKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Assert().Error(err, "Deleted key should not be retrievable")

	// Key should not appear in listing
	finalKeys, err := s.manager.ListKeys(ctx, "mock-hsm", config)
	s.Require().NoError(err)

	for _, key := range finalKeys {
		s.Assert().NotEqual(keyHandle.ID, key.ID, "Deleted key should not appear in listing")
	}

	// Should not be able to sign with deleted key
	_, err = s.manager.Sign(ctx, "mock-hsm", config, signingRequest)
	s.Assert().Error(err, "Deleted key should not be usable for signing")
}

// TestMultiProviderWorkflow tests workflows across multiple providers
func (s *E2ETestSuite) TestMultiProviderWorkflow() {
	ctx := context.Background()

	providers := map[string]map[string]interface{}{
		"mock-hsm": {
			"persistent_storage": false,
			"simulate_errors":    false,
			"max_keys":          1000,
			"key_prefix":        "e2e-multi-mock",
		},
		"custom-storage": {
			"storage_type":    "memory",
			"encrypt_at_rest": false,
			"key_prefix":      "e2e-multi-custom",
		},
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	createdKeys := make(map[string]*models.KeyHandle)

	defer func() {
		// Clean up all created keys
		for providerName, keyHandle := range createdKeys {
			config := providers[providerName]
			_ = s.manager.DeleteKey(ctx, providerName, config, keyHandle.ID)
		}
	}()

	// Step 1: Create keys in each provider
	for providerName, config := range providers {
		keyName := fmt.Sprintf("multi-provider-key-%s", providerName)
		keyHandle, err := s.manager.GenerateKey(ctx, providerName, config, keySpec, keyName)
		s.Require().NoError(err, "Failed to create key in provider %s", providerName)
		
		createdKeys[providerName] = keyHandle
		s.T().Logf("Created key %s in provider %s", keyHandle.ID, providerName)
	}

	// Step 2: Verify each provider only sees its own keys
	for providerName, config := range providers {
		keys, err := s.manager.ListKeys(ctx, providerName, config)
		s.Require().NoError(err, "Failed to list keys for provider %s", providerName)

		// Should find our key for this provider
		found := false
		for _, key := range keys {
			if key.ID == createdKeys[providerName].ID {
				found = true
				break
			}
		}
		s.Assert().True(found, "Provider %s should see its own key", providerName)

		// Should not find keys from other providers
		for otherProviderName, otherKeyHandle := range createdKeys {
			if otherProviderName != providerName {
				for _, key := range keys {
					s.Assert().NotEqual(otherKeyHandle.ID, key.ID,
						"Provider %s should not see keys from provider %s", providerName, otherProviderName)
				}
			}
		}
	}

	// Step 3: Test operations with each key
	testData := []byte("Multi-provider test data")

	for providerName, keyHandle := range createdKeys {
		config := providers[providerName]
		
		// Sign with this provider's key
		signingRequest := models.SigningRequest{
			KeyHandle: keyHandle.ID,
			Data:      testData,
			Algorithm: "RSA-PSS",
		}

		sigResponse, err := s.manager.Sign(ctx, providerName, config, signingRequest)
		s.Require().NoError(err, "Failed to sign with provider %s", providerName)

		// Verify signature
		valid, err := s.manager.Verify(ctx, providerName, config, keyHandle.ID,
			testData, sigResponse.Signature, "RSA-PSS")
		s.Require().NoError(err, "Failed to verify signature for provider %s", providerName)
		s.Assert().True(valid, "Signature should verify for provider %s", providerName)

		s.T().Logf("Successfully signed and verified with provider %s", providerName)
	}

	// Step 4: Test cross-provider isolation (keys should not work across providers)
	mockKey := createdKeys["mock-hsm"]
	customConfig := providers["custom-storage"]

	signingRequest := models.SigningRequest{
		KeyHandle: mockKey.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}

	// Should not be able to use mock HSM key with custom storage provider
	_, err := s.manager.Sign(ctx, "custom-storage", customConfig, signingRequest)
	s.Assert().Error(err, "Should not be able to use mock HSM key with custom storage provider")
}

// TestMultipleKeyTypes tests workflow with different key types
func (s *E2ETestSuite) TestMultipleKeyTypes() {
	ctx := context.Background()
	
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "e2e-key-types",
	}

	keySpecs := map[string]models.KeySpec{
		"RSA-2048": {
			KeyType:   models.KeyTypeRSA,
			KeySize:   2048,
			Algorithm: "RSA-PSS",
			Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
		},
		"ECDSA-P256": {
			KeyType:   models.KeyTypeECDSA,
			KeySize:   256,
			Algorithm: "ECDSA",
			Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
		},
		"Ed25519": {
			KeyType:   models.KeyTypeEd25519,
			KeySize:   256,
			Algorithm: "Ed25519",
			Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
		},
	}

	createdKeys := make(map[string]*models.KeyHandle)

	defer func() {
		// Clean up
		for _, keyHandle := range createdKeys {
			_ = s.manager.DeleteKey(ctx, "mock-hsm", config, keyHandle.ID)
		}
	}()

	// Step 1: Generate keys of different types
	for keyTypeName, keySpec := range keySpecs {
		keyName := fmt.Sprintf("e2e-key-%s", keyTypeName)
		keyHandle, err := s.manager.GenerateKey(ctx, "mock-hsm", config, keySpec, keyName)
		s.Require().NoError(err, "Failed to generate %s key", keyTypeName)
		
		createdKeys[keyTypeName] = keyHandle
		s.Assert().Equal(keySpec.KeyType, keyHandle.KeyType)
		s.Assert().Equal(keySpec.KeySize, keyHandle.KeySize)
		
		s.T().Logf("Generated %s key: %s", keyTypeName, keyHandle.ID)
	}

	// Step 2: Test signing and verification with each key type
	testData := []byte("Multi-key-type test data")

	for keyTypeName, keyHandle := range createdKeys {
		keySpec := keySpecs[keyTypeName]
		
		signingRequest := models.SigningRequest{
			KeyHandle: keyHandle.ID,
			Data:      testData,
			Algorithm: keySpec.Algorithm,
		}

		// Sign
		sigResponse, err := s.manager.Sign(ctx, "mock-hsm", config, signingRequest)
		s.Require().NoError(err, "Failed to sign with %s key", keyTypeName)
		s.Assert().NotEmpty(sigResponse.Signature)

		// Verify
		valid, err := s.manager.Verify(ctx, "mock-hsm", config, keyHandle.ID,
			testData, sigResponse.Signature, keySpec.Algorithm)
		s.Require().NoError(err, "Failed to verify %s signature", keyTypeName)
		s.Assert().True(valid, "%s signature should verify", keyTypeName)

		s.T().Logf("Successfully tested %s key operations", keyTypeName)
	}

	// Step 3: Verify all keys are listed correctly
	keys, err := s.manager.ListKeys(ctx, "mock-hsm", config)
	s.Require().NoError(err)

	// Should have at least our created keys
	s.Assert().GreaterOrEqual(len(keys), len(createdKeys))

	// Verify each key type is present
	foundKeyTypes := make(map[string]bool)
	for _, key := range keys {
		for keyTypeName, createdKey := range createdKeys {
			if key.ID == createdKey.ID {
				foundKeyTypes[keyTypeName] = true
			}
		}
	}

	for keyTypeName := range keySpecs {
		s.Assert().True(foundKeyTypes[keyTypeName], "Should find %s key in listing", keyTypeName)
	}
}

// TestErrorConditionsAndRecovery tests error handling and system recovery
func (s *E2ETestSuite) TestErrorConditionsAndRecovery() {
	ctx := context.Background()

	// Test with error-simulating configuration
	errorConfig := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    true,
		"error_rate":         0.3, // 30% error rate
		"max_keys":          1000,
		"key_prefix":        "e2e-error-test",
	}

	normalConfig := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "e2e-normal-test",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Step 1: Test error conditions
	var successCount, errorCount int
	const attempts = 20

	for i := 0; i < attempts; i++ {
		keyName := fmt.Sprintf("error-test-key-%d", i)
		keyHandle, err := s.manager.GenerateKey(ctx, "mock-hsm", errorConfig, keySpec, keyName)

		if err != nil {
			errorCount++
			s.T().Logf("Expected error %d: %v", errorCount, err)
		} else {
			successCount++
			// Clean up successful keys
			_ = s.manager.DeleteKey(ctx, "mock-hsm", errorConfig, keyHandle.ID)
		}
	}

	s.T().Logf("Error simulation results: %d successes, %d errors out of %d attempts", 
		successCount, errorCount, attempts)

	// Should have some errors due to error simulation
	s.Assert().Greater(errorCount, 0, "Should have some simulated errors")
	s.Assert().Greater(successCount, 0, "Should have some successes even with errors")

	// Step 2: Test system recovery - normal operations should still work
	normalKey, err := s.manager.GenerateKey(ctx, "mock-hsm", normalConfig, keySpec, "recovery-test-key")
	s.Require().NoError(err, "Normal operations should work after errors")

	defer func() {
		_ = s.manager.DeleteKey(ctx, "mock-hsm", normalConfig, normalKey.ID)
	}()

	// Should be able to perform normal operations
	testData := []byte("Recovery test data")
	signingRequest := models.SigningRequest{
		KeyHandle: normalKey.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}

	sigResponse, err := s.manager.Sign(ctx, "mock-hsm", normalConfig, signingRequest)
	s.Require().NoError(err, "Signing should work after error recovery")

	valid, err := s.manager.Verify(ctx, "mock-hsm", normalConfig, normalKey.ID,
		testData, sigResponse.Signature, "RSA-PSS")
	s.Require().NoError(err, "Verification should work after error recovery")
	s.Assert().True(valid, "Signature should verify after error recovery")

	s.T().Log("System successfully recovered from error conditions")
}

// TestCapacityLimitsAndCleanup tests system behavior at capacity limits
func (s *E2ETestSuite) TestCapacityLimitsAndCleanup() {
	ctx := context.Background()

	// Test with limited capacity
	limitedConfig := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          10, // Very limited capacity
		"key_prefix":        "e2e-capacity-test",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	var createdKeys []*models.KeyHandle

	defer func() {
		// Clean up all keys
		for _, keyHandle := range createdKeys {
			_ = s.manager.DeleteKey(ctx, "mock-hsm", limitedConfig, keyHandle.ID)
		}
	}()

	// Step 1: Fill up to capacity
	for i := 0; i < 10; i++ {
		keyName := fmt.Sprintf("capacity-key-%d", i)
		keyHandle, err := s.manager.GenerateKey(ctx, "mock-hsm", limitedConfig, keySpec, keyName)
		s.Require().NoError(err, "Should be able to create key %d within capacity", i)
		createdKeys = append(createdKeys, keyHandle)
	}

	// Step 2: Try to exceed capacity
	_, err := s.manager.GenerateKey(ctx, "mock-hsm", limitedConfig, keySpec, "capacity-exceeded-key")
	s.Assert().Error(err, "Should fail when exceeding capacity")

	// Step 3: Verify we can still operate within capacity
	if len(createdKeys) > 0 {
		testData := []byte("Capacity test data")
		signingRequest := models.SigningRequest{
			KeyHandle: createdKeys[0].ID,
			Data:      testData,
			Algorithm: "RSA-PSS",
		}

		_, err := s.manager.Sign(ctx, "mock-hsm", limitedConfig, signingRequest)
		s.Assert().NoError(err, "Should still be able to sign within capacity")
	}

	// Step 4: Test cleanup frees capacity
	if len(createdKeys) > 0 {
		keyToDelete := createdKeys[0]
		err := s.manager.DeleteKey(ctx, "mock-hsm", limitedConfig, keyToDelete.ID)
		s.Require().NoError(err)

		// Remove from our tracking
		createdKeys = createdKeys[1:]

		// Should now be able to create a new key
		newKey, err := s.manager.GenerateKey(ctx, "mock-hsm", limitedConfig, keySpec, "capacity-freed-key")
		s.Assert().NoError(err, "Should be able to create key after cleanup")

		if err == nil {
			createdKeys = append(createdKeys, newKey)
		}
	}

	s.T().Log("Capacity management working correctly")
}

// TestDataIntegrityAndConsistency tests data integrity throughout operations
func (s *E2ETestSuite) TestDataIntegrityAndConsistency() {
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "e2e-integrity",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Step 1: Create key and perform baseline operations
	keyHandle, err := s.manager.GenerateKey(ctx, "mock-hsm", config, keySpec, "integrity-test-key")
	s.Require().NoError(err)

	defer func() {
		_ = s.manager.DeleteKey(ctx, "mock-hsm", config, keyHandle.ID)
	}()

	// Step 2: Test signature consistency - same data should verify consistently
	testData := []byte("Consistency test data for integrity verification")
	signingRequest := models.SigningRequest{
		KeyHandle: keyHandle.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}

	// Create multiple signatures and verify them all
	const numSignatures = 5
	signatures := make([][]byte, numSignatures)

	for i := 0; i < numSignatures; i++ {
		sigResponse, err := s.manager.Sign(ctx, "mock-hsm", config, signingRequest)
		s.Require().NoError(err, "Signing attempt %d should succeed", i)
		signatures[i] = sigResponse.Signature
	}

	// All signatures should verify
	for i, signature := range signatures {
		valid, err := s.manager.Verify(ctx, "mock-hsm", config, keyHandle.ID,
			testData, signature, "RSA-PSS")
		s.Require().NoError(err, "Verification attempt %d should not error", i)
		s.Assert().True(valid, "Signature %d should verify", i)
	}

	// Step 3: Test data tampering detection
	tamperedData := make([]byte, len(testData))
	copy(tamperedData, testData)
	tamperedData[0] ^= 0xFF // Flip some bits

	for i, signature := range signatures {
		valid, err := s.manager.Verify(ctx, "mock-hsm", config, keyHandle.ID,
			tamperedData, signature, "RSA-PSS")
		s.Require().NoError(err, "Tampered verification attempt %d should not error", i)
		s.Assert().False(valid, "Tampered data should not verify with signature %d", i)
	}

	// Step 4: Test key metadata consistency
	retrievedKey, err := s.manager.GetKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Require().NoError(err)

	s.Assert().Equal(keyHandle.ID, retrievedKey.ID)
	s.Assert().Equal(keyHandle.Name, retrievedKey.Name)
	s.Assert().Equal(keyHandle.KeyType, retrievedKey.KeyType)
	s.Assert().Equal(keyHandle.KeySize, retrievedKey.KeySize)
	s.Assert().Equal(keyHandle.Algorithm, retrievedKey.Algorithm)
	s.Assert().Equal(keyHandle.Status, retrievedKey.Status)

	// Step 5: Test state consistency after operations
	// Deactivate and check consistency
	err = s.manager.DeactivateKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Require().NoError(err)

	deactivatedKey, err := s.manager.GetKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Require().NoError(err)
	s.Assert().Equal(models.KeyStatusInactive, deactivatedKey.Status)

	// Reactivate and check consistency
	err = s.manager.ActivateKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Require().NoError(err)

	reactivatedKey, err := s.manager.GetKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Require().NoError(err)
	s.Assert().Equal(models.KeyStatusActive, reactivatedKey.Status)

	s.T().Log("Data integrity and consistency verified")
}

// TestProviderHealthAndAvailability tests provider health monitoring
func (s *E2ETestSuite) TestProviderHealthAndAvailability() {
	ctx := context.Background()

	// Test health check for all registered providers
	providerNames := []string{"mock-hsm", "custom-storage"}

	for _, providerName := range providerNames {
		// Test health check
		healthy, err := s.registry.HealthCheck(ctx, providerName)
		s.Require().NoError(err, "Health check should not error for provider %s", providerName)
		s.Assert().True(healthy, "Provider %s should be healthy", providerName)

		s.T().Logf("Provider %s health check passed", providerName)
	}

	// Test health check for non-existent provider
	_, err := s.registry.HealthCheck(ctx, "non-existent-provider")
	s.Assert().Error(err, "Health check should fail for non-existent provider")
}

// TestSystemScalabilityBasics tests basic scalability characteristics
func (s *E2ETestSuite) TestSystemScalabilityBasics() {
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "e2e-scalability",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Test creating a moderate number of keys
	const numKeys = 50
	keyHandles := make([]*models.KeyHandle, 0, numKeys)

	defer func() {
		// Clean up all keys
		for _, keyHandle := range keyHandles {
			_ = s.manager.DeleteKey(ctx, "mock-hsm", config, keyHandle.ID)
		}
	}()

	startTime := time.Now()

	// Create keys
	for i := 0; i < numKeys; i++ {
		keyName := fmt.Sprintf("scalability-key-%d", i)
		keyHandle, err := s.manager.GenerateKey(ctx, "mock-hsm", config, keySpec, keyName)
		s.Require().NoError(err, "Should be able to create key %d", i)
		keyHandles = append(keyHandles, keyHandle)
	}

	creationTime := time.Since(startTime)
	creationRate := float64(numKeys) / creationTime.Seconds()

	s.T().Logf("Created %d keys in %v (%.2f keys/sec)", numKeys, creationTime, creationRate)

	// Test listing performance with many keys
	listStartTime := time.Now()
	keys, err := s.manager.ListKeys(ctx, "mock-hsm", config)
	listTime := time.Since(listStartTime)

	s.Require().NoError(err)
	s.Assert().GreaterOrEqual(len(keys), numKeys)

	s.T().Logf("Listed %d keys in %v", len(keys), listTime)

	// Test signing performance with multiple keys
	testData := []byte("Scalability test data")
	signStartTime := time.Now()

	for i, keyHandle := range keyHandles {
		if i >= 10 { // Test with first 10 keys to keep test time reasonable
			break
		}

		signingRequest := models.SigningRequest{
			KeyHandle: keyHandle.ID,
			Data:      testData,
			Algorithm: "RSA-PSS",
		}

		_, err := s.manager.Sign(ctx, "mock-hsm", config, signingRequest)
		s.Require().NoError(err, "Should be able to sign with key %d", i)
	}

	signTime := time.Since(signStartTime)
	signRate := 10.0 / signTime.Seconds()

	s.T().Logf("Performed 10 signing operations in %v (%.2f signs/sec)", signTime, signRate)

	// Basic performance assertions (adjust based on acceptable performance)
	s.Assert().Less(creationTime, 30*time.Second, "Key creation should complete in reasonable time")
	s.Assert().Less(listTime, 1*time.Second, "Key listing should be fast")
	s.Assert().Less(signTime, 10*time.Second, "Signing operations should complete in reasonable time")

	s.T().Log("Basic scalability test completed successfully")
}

// TestSystemIntegration tests integration between different system components
func (s *E2ETestSuite) TestSystemIntegration() {
	ctx := context.Background()

	// Test integration between registry, manager, and providers
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "e2e-integration",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Step 1: Test provider registration and listing
	providerList := s.registry.ListProviders()
	s.Assert().Contains(providerList, "mock-hsm", "Mock HSM provider should be registered")
	s.Assert().Contains(providerList, "custom-storage", "Custom storage provider should be registered")

	// Step 2: Test manager integration with registry
	keyHandle, err := s.manager.GenerateKey(ctx, "mock-hsm", config, keySpec, "integration-test-key")
	s.Require().NoError(err)

	defer func() {
		_ = s.manager.DeleteKey(ctx, "mock-hsm", config, keyHandle.ID)
	}()

	// Step 3: Test cross-component data flow
	// Manager -> Provider -> Manager
	retrievedKey, err := s.manager.GetKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Require().NoError(err)
	s.Assert().Equal(keyHandle.ID, retrievedKey.ID)

	// Step 4: Test operation chaining
	testData := []byte("Integration test data")
	
	// Sign
	signingRequest := models.SigningRequest{
		KeyHandle: keyHandle.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}

	sigResponse, err := s.manager.Sign(ctx, "mock-hsm", config, signingRequest)
	s.Require().NoError(err)

	// Verify
	valid, err := s.manager.Verify(ctx, "mock-hsm", config, keyHandle.ID,
		testData, sigResponse.Signature, "RSA-PSS")
	s.Require().NoError(err)
	s.Assert().True(valid)

	// Step 5: Test state management integration
	err = s.manager.DeactivateKey(ctx, "mock-hsm", config, keyHandle.ID)
	s.Require().NoError(err)

	// Verify state is reflected across components
	keys, err := s.manager.ListKeys(ctx, "mock-hsm", config)
	s.Require().NoError(err)

	found := false
	for _, key := range keys {
		if key.ID == keyHandle.ID {
			s.Assert().Equal(models.KeyStatusInactive, key.Status)
			found = true
			break
		}
	}
	s.Assert().True(found, "Deactivated key should be found with correct status")

	s.T().Log("System integration test completed successfully")
}

// TestE2E runs all end-to-end tests
func TestE2E(t *testing.T) {
	// Skip if not in integration test mode
	if testing.Short() {
		t.Skip("Skipping E2E tests in short mode")
	}

	// Check if we should run E2E tests
	if os.Getenv("RUN_E2E_TESTS") != "true" {
		t.Skip("Skipping E2E tests (set RUN_E2E_TESTS=true to run)")
	}

	suite.Run(t, new(E2ETestSuite))
}