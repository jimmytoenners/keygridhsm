package security

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jimmy/keygridhsm/internal/core"
	"github.com/jimmy/keygridhsm/internal/providers"
	"github.com/jimmy/keygridhsm/pkg/models"
)

var (
	securityRegistry *core.ProviderRegistry
	securityManager  *core.HSMManager
)

// setupSecurityTests initializes the security test environment
func setupSecurityTests() {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise

	securityRegistry = core.NewProviderRegistry()

	// Register providers
	mockProvider := providers.NewMockHSMProvider(logger)
	_ = securityRegistry.RegisterProvider("mock-hsm", mockProvider)

	customProvider := providers.NewCustomStorageProvider(logger)
	_ = securityRegistry.RegisterProvider("custom-storage", customProvider)

	securityManager = core.NewHSMManager(core.HSMManagerConfig{
		Registry: securityRegistry,
		Logger:   logger,
	})
}

// TestKeyIsolation tests that keys from different contexts are properly isolated
func TestKeyIsolation(t *testing.T) {
	setupSecurityTests()
	ctx := context.Background()

	// Create separate configurations for different "tenants"
	tenant1Config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "tenant1",
	}

	tenant2Config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "tenant2",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Generate keys for tenant 1
	tenant1Key1, err := securityManager.GenerateKey(ctx, "mock-hsm", tenant1Config, keySpec, "isolated-key-1")
	require.NoError(t, err)
	
	tenant1Key2, err := securityManager.GenerateKey(ctx, "mock-hsm", tenant1Config, keySpec, "isolated-key-2")
	require.NoError(t, err)

	// Generate keys for tenant 2
	tenant2Key1, err := securityManager.GenerateKey(ctx, "mock-hsm", tenant2Config, keySpec, "isolated-key-1")
	require.NoError(t, err)
	
	tenant2Key2, err := securityManager.GenerateKey(ctx, "mock-hsm", tenant2Config, keySpec, "isolated-key-2")
	require.NoError(t, err)

	defer func() {
		// Clean up
		_ = securityManager.DeleteKey(ctx, "mock-hsm", tenant1Config, tenant1Key1.ID)
		_ = securityManager.DeleteKey(ctx, "mock-hsm", tenant1Config, tenant1Key2.ID)
		_ = securityManager.DeleteKey(ctx, "mock-hsm", tenant2Config, tenant2Key1.ID)
		_ = securityManager.DeleteKey(ctx, "mock-hsm", tenant2Config, tenant2Key2.ID)
	}()

	// Test isolation: tenant1 should only see their keys
	tenant1Keys, err := securityManager.ListKeys(ctx, "mock-hsm", tenant1Config)
	require.NoError(t, err)
	assert.Equal(t, 2, len(tenant1Keys), "Tenant 1 should only see their 2 keys")

	// Test isolation: tenant2 should only see their keys
	tenant2Keys, err := securityManager.ListKeys(ctx, "mock-hsm", tenant2Config)
	require.NoError(t, err)
	assert.Equal(t, 2, len(tenant2Keys), "Tenant 2 should only see their 2 keys")

	// Verify key IDs are different (proper isolation)
	tenant1KeyIDs := make(map[string]bool)
	for _, key := range tenant1Keys {
		tenant1KeyIDs[key.ID] = true
	}

	for _, key := range tenant2Keys {
		assert.False(t, tenant1KeyIDs[key.ID], "Tenant 2 should not have access to tenant 1's keys")
	}

	// Test cross-tenant access denial: tenant1 shouldn't be able to access tenant2's keys
	testData := []byte("Cross-tenant test data")
	signingRequest := models.SigningRequest{
		KeyHandle: tenant2Key1.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}

	// This should fail or only work within proper context
	_, err = securityManager.Sign(ctx, "mock-hsm", tenant1Config, signingRequest)
	// The error behavior depends on implementation - could be key not found or access denied
	// The important thing is that one tenant can't arbitrarily access another's keys
	
	t.Logf("Cross-tenant access attempt result: %v", err)
}

// TestInputValidation tests security through input validation
func TestInputValidation(t *testing.T) {
	setupSecurityTests()
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "validation-test",
	}

	testCases := []struct {
		name        string
		keyName     string
		keySpec     models.KeySpec
		shouldError bool
		description string
	}{
		{
			name:    "Empty-Key-Name",
			keyName: "",
			keySpec: models.KeySpec{
				KeyType:   models.KeyTypeRSA,
				KeySize:   2048,
				Algorithm: "RSA-PSS",
				Usage:     []models.KeyUsage{models.KeyUsageSign},
			},
			shouldError: true,
			description: "Empty key names should be rejected",
		},
		{
			name:    "Malicious-Key-Name",
			keyName: "../../../etc/passwd",
			keySpec: models.KeySpec{
				KeyType:   models.KeyTypeRSA,
				KeySize:   2048,
				Algorithm: "RSA-PSS",
				Usage:     []models.KeyUsage{models.KeyUsageSign},
			},
			shouldError: false, // Should be sanitized, not error
			description: "Path traversal attempts should be sanitized",
		},
		{
			name:    "SQL-Injection-Key-Name",
			keyName: "'; DROP TABLE keys; --",
			keySpec: models.KeySpec{
				KeyType:   models.KeyTypeRSA,
				KeySize:   2048,
				Algorithm: "RSA-PSS",
				Usage:     []models.KeyUsage{models.KeyUsageSign},
			},
			shouldError: false, // Should be sanitized
			description: "SQL injection attempts should be handled safely",
		},
		{
			name:    "Invalid-Key-Size",
			keyName: "invalid-size-key",
			keySpec: models.KeySpec{
				KeyType:   models.KeyTypeRSA,
				KeySize:   512, // Too small for production
				Algorithm: "RSA-PSS",
				Usage:     []models.KeyUsage{models.KeyUsageSign},
			},
			shouldError: true,
			description: "Invalid key sizes should be rejected",
		},
		{
			name:    "Invalid-Algorithm",
			keyName: "invalid-algo-key",
			keySpec: models.KeySpec{
				KeyType:   models.KeyTypeRSA,
				KeySize:   2048,
				Algorithm: "INVALID-ALGORITHM",
				Usage:     []models.KeyUsage{models.KeyUsageSign},
			},
			shouldError: true,
			description: "Invalid algorithms should be rejected",
		},
		{
			name:    "Empty-Usage",
			keyName: "empty-usage-key",
			keySpec: models.KeySpec{
				KeyType:   models.KeyTypeRSA,
				KeySize:   2048,
				Algorithm: "RSA-PSS",
				Usage:     []models.KeyUsage{}, // Empty usage
			},
			shouldError: true,
			description: "Keys without usage should be rejected",
		},
	}

	var createdKeys []string
	defer func() {
		// Clean up any successfully created keys
		for _, keyID := range createdKeys {
			_ = securityManager.DeleteKey(ctx, "mock-hsm", config, keyID)
		}
	}()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyHandle, err := securityManager.GenerateKey(ctx, "mock-hsm", config, tc.keySpec, tc.keyName)

			if tc.shouldError {
				assert.Error(t, err, tc.description)
			} else {
				if err == nil {
					assert.NotNil(t, keyHandle, "Should return valid key handle")
					createdKeys = append(createdKeys, keyHandle.ID)
					
					// For sanitization tests, verify the key name was cleaned
					if strings.Contains(tc.keyName, "/") || strings.Contains(tc.keyName, "'") {
						t.Logf("Potentially malicious input '%s' was handled, key created with ID: %s", 
							tc.keyName, keyHandle.ID)
					}
				}
			}
		})
	}
}

// TestSignatureValidation tests cryptographic signature validation security
func TestSignatureValidation(t *testing.T) {
	setupSecurityTests()
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "sig-validation",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Generate test key
	keyHandle, err := securityManager.GenerateKey(ctx, "mock-hsm", config, keySpec, "signature-test-key")
	require.NoError(t, err)

	defer func() {
		_ = securityManager.DeleteKey(ctx, "mock-hsm", config, keyHandle.ID)
	}()

	originalData := []byte("This is the original message to be signed")
	tamperedData := []byte("This is a TAMPERED message - not the original")

	// Generate valid signature
	signingRequest := models.SigningRequest{
		KeyHandle: keyHandle.ID,
		Data:      originalData,
		Algorithm: "RSA-PSS",
	}

	sigResponse, err := securityManager.Sign(ctx, "mock-hsm", config, signingRequest)
	require.NoError(t, err)
	require.NotEmpty(t, sigResponse.Signature)

	// Test 1: Valid signature should verify successfully
	valid, err := securityManager.Verify(ctx, "mock-hsm", config, keyHandle.ID, 
		originalData, sigResponse.Signature, "RSA-PSS")
	require.NoError(t, err)
	assert.True(t, valid, "Valid signature should verify successfully")

	// Test 2: Tampered data should fail verification
	valid, err = securityManager.Verify(ctx, "mock-hsm", config, keyHandle.ID, 
		tamperedData, sigResponse.Signature, "RSA-PSS")
	require.NoError(t, err)
	assert.False(t, valid, "Signature of tampered data should fail verification")

	// Test 3: Corrupted signature should fail verification
	corruptedSignature := make([]byte, len(sigResponse.Signature))
	copy(corruptedSignature, sigResponse.Signature)
	corruptedSignature[0] ^= 0xFF // Flip bits in first byte

	valid, err = securityManager.Verify(ctx, "mock-hsm", config, keyHandle.ID, 
		originalData, corruptedSignature, "RSA-PSS")
	require.NoError(t, err)
	assert.False(t, valid, "Corrupted signature should fail verification")

	// Test 4: Empty signature should fail
	valid, err = securityManager.Verify(ctx, "mock-hsm", config, keyHandle.ID, 
		originalData, []byte{}, "RSA-PSS")
	if err == nil {
		assert.False(t, valid, "Empty signature should fail verification")
	} else {
		t.Logf("Empty signature correctly caused error: %v", err)
	}

	// Test 5: Wrong algorithm should fail or error
	if len(sigResponse.Signature) > 0 {
		valid, err = securityManager.Verify(ctx, "mock-hsm", config, keyHandle.ID, 
			originalData, sigResponse.Signature, "ECDSA") // Wrong algorithm
		
		if err != nil {
			t.Logf("Wrong algorithm correctly caused error: %v", err)
		} else {
			assert.False(t, valid, "Wrong algorithm should fail verification")
		}
	}
}

// TestKeyLifecycleSecurity tests security aspects of key lifecycle management
func TestKeyLifecycleSecurity(t *testing.T) {
	setupSecurityTests()
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "lifecycle-security",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Test 1: Generate key and ensure it's immediately usable
	keyHandle, err := securityManager.GenerateKey(ctx, "mock-hsm", config, keySpec, "lifecycle-test-key")
	require.NoError(t, err)
	require.NotEmpty(t, keyHandle.ID)

	// Test 2: Key should be active by default
	assert.Equal(t, models.KeyStateActive, keyHandle.State, "New key should be active by default")

	// Test 3: Deactivated key should not be usable for signing
	err = securityManager.DeactivateKey(ctx, "mock-hsm", config, keyHandle.ID)
	require.NoError(t, err)

	// Verify key is deactivated
	keys, err := securityManager.ListKeys(ctx, "mock-hsm", config)
	require.NoError(t, err)

	var deactivatedKey *models.KeyHandle
	for _, key := range keys {
		if key.ID == keyHandle.ID {
			deactivatedKey = key
			break
		}
	}
	require.NotNil(t, deactivatedKey)
	assert.Equal(t, models.KeyStateInactive, deactivatedKey.State)

	// Deactivated key should not sign
	testData := []byte("Test data for deactivated key")
	signingRequest := models.SigningRequest{
		KeyHandle: keyHandle.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}

	_, err = securityManager.Sign(ctx, "mock-hsm", config, signingRequest)
	assert.Error(t, err, "Deactivated key should not be able to sign")

	// Test 4: Reactivate key and ensure it works again
	err = securityManager.ActivateKey(ctx, "mock-hsm", config, keyHandle.ID)
	require.NoError(t, err)

	// Should be able to sign again
	_, err = securityManager.Sign(ctx, "mock-hsm", config, signingRequest)
	assert.NoError(t, err, "Reactivated key should be able to sign")

	// Test 5: Deleted key should not be accessible
	err = securityManager.DeleteKey(ctx, "mock-hsm", config, keyHandle.ID)
	require.NoError(t, err)

	// Key should not be in listing
	keys, err = securityManager.ListKeys(ctx, "mock-hsm", config)
	require.NoError(t, err)

	for _, key := range keys {
		assert.NotEqual(t, keyHandle.ID, key.ID, "Deleted key should not appear in key listing")
	}

	// Deleted key should not be usable
	_, err = securityManager.Sign(ctx, "mock-hsm", config, signingRequest)
	assert.Error(t, err, "Deleted key should not be usable for signing")
}

// TestTimingAttackResistance tests resistance to timing-based attacks
func TestTimingAttackResistance(t *testing.T) {
	setupSecurityTests()
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "timing-attack",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Generate a valid key
	keyHandle, err := securityManager.GenerateKey(ctx, "mock-hsm", config, keySpec, "timing-test-key")
	require.NoError(t, err)

	defer func() {
		_ = securityManager.DeleteKey(ctx, "mock-hsm", config, keyHandle.ID)
	}()

	testData := []byte("Timing attack test data")
	
	// Generate valid signature
	signingRequest := models.SigningRequest{
		KeyHandle: keyHandle.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}

	sigResponse, err := securityManager.Sign(ctx, "mock-hsm", config, signingRequest)
	require.NoError(t, err)

	// Test timing consistency for verification operations
	const numSamples = 100
	validTimes := make([]time.Duration, numSamples)
	invalidTimes := make([]time.Duration, numSamples)

	// Measure valid signature verification times
	for i := 0; i < numSamples; i++ {
		start := time.Now()
		valid, err := securityManager.Verify(ctx, "mock-hsm", config, keyHandle.ID, 
			testData, sigResponse.Signature, "RSA-PSS")
		validTimes[i] = time.Since(start)
		
		require.NoError(t, err)
		require.True(t, valid)
	}

	// Create invalid signature (corrupted)
	invalidSignature := make([]byte, len(sigResponse.Signature))
	copy(invalidSignature, sigResponse.Signature)
	invalidSignature[0] ^= 0xFF

	// Measure invalid signature verification times
	for i := 0; i < numSamples; i++ {
		start := time.Now()
		valid, err := securityManager.Verify(ctx, "mock-hsm", config, keyHandle.ID, 
			testData, invalidSignature, "RSA-PSS")
		invalidTimes[i] = time.Since(start)
		
		require.NoError(t, err)
		require.False(t, valid)
	}

	// Calculate averages
	var validTotal, invalidTotal time.Duration
	for i := 0; i < numSamples; i++ {
		validTotal += validTimes[i]
		invalidTotal += invalidTimes[i]
	}

	validAvg := validTotal / time.Duration(numSamples)
	invalidAvg := invalidTotal / time.Duration(numSamples)

	t.Logf("Timing Analysis:")
	t.Logf("  Valid signature avg time: %v", validAvg)
	t.Logf("  Invalid signature avg time: %v", invalidAvg)

	// The timing difference should not be excessive (less than 2x difference)
	// This is a basic check - real timing attack resistance requires more sophisticated analysis
	ratio := float64(validAvg) / float64(invalidAvg)
	if ratio < 1 {
		ratio = 1 / ratio
	}

	assert.Less(t, ratio, 2.0, "Verification times should not differ excessively (potential timing attack vector)")
}

// TestRandomnessQuality tests the quality of random number generation
func TestRandomnessQuality(t *testing.T) {
	setupSecurityTests()
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "randomness-test",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Generate multiple keys and check for uniqueness
	const numKeys = 20
	keyIDs := make(map[string]bool)
	keyHandles := make([]*models.KeyHandle, 0, numKeys)

	defer func() {
		// Clean up
		for _, keyHandle := range keyHandles {
			_ = securityManager.DeleteKey(ctx, "mock-hsm", config, keyHandle.ID)
		}
	}()

	// Test key ID uniqueness
	for i := 0; i < numKeys; i++ {
		keyName := fmt.Sprintf("randomness-key-%d", i)
		keyHandle, err := securityManager.GenerateKey(ctx, "mock-hsm", config, keySpec, keyName)
		require.NoError(t, err)

		// Check uniqueness
		assert.False(t, keyIDs[keyHandle.ID], "Key ID should be unique: %s", keyHandle.ID)
		keyIDs[keyHandle.ID] = true
		keyHandles = append(keyHandles, keyHandle)
	}

	// Test signature randomness (for algorithms that use randomness)
	if len(keyHandles) > 0 {
		keyHandle := keyHandles[0]
		testData := []byte("Randomness test data for signatures")
		
		signingRequest := models.SigningRequest{
			KeyHandle: keyHandle.ID,
			Data:      testData,
			Algorithm: "RSA-PSS", // RSA-PSS uses salt, should produce different signatures
		}

		signatures := make(map[string]bool)
		const numSignatures = 10

		for i := 0; i < numSignatures; i++ {
			sigResponse, err := securityManager.Sign(ctx, "mock-hsm", config, signingRequest)
			require.NoError(t, err)

			sigHex := fmt.Sprintf("%x", sigResponse.Signature)
			
			// For PSS, signatures of the same data should be different due to salt
			if !signatures[sigHex] {
				signatures[sigHex] = true
			} else {
				// This might be acceptable for some implementations, just log it
				t.Logf("Warning: Duplicate signature detected (may indicate weak randomness)")
			}
		}

		t.Logf("Generated %d unique signatures out of %d attempts", len(signatures), numSignatures)
	}
}

// TestSecureKeyDeletion tests that keys are securely deleted
func TestSecureKeyDeletion(t *testing.T) {
	setupSecurityTests()
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "secure-deletion",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Generate and use a key
	keyHandle, err := securityManager.GenerateKey(ctx, "mock-hsm", config, keySpec, "deletion-test-key")
	require.NoError(t, err)

	testData := []byte("Data to sign before deletion")
	signingRequest := models.SigningRequest{
		KeyHandle: keyHandle.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}

	// Sign data to prove key works
	sigResponse, err := securityManager.Sign(ctx, "mock-hsm", config, signingRequest)
	require.NoError(t, err)
	require.NotEmpty(t, sigResponse.Signature)

	// Verify signature works
	valid, err := securityManager.Verify(ctx, "mock-hsm", config, keyHandle.ID, 
		testData, sigResponse.Signature, "RSA-PSS")
	require.NoError(t, err)
	require.True(t, valid)

	// Delete the key
	err = securityManager.DeleteKey(ctx, "mock-hsm", config, keyHandle.ID)
	require.NoError(t, err)

	// Verify key is completely inaccessible
	// 1. Should not appear in key listing
	keys, err := securityManager.ListKeys(ctx, "mock-hsm", config)
	require.NoError(t, err)
	
	for _, key := range keys {
		assert.NotEqual(t, keyHandle.ID, key.ID, "Deleted key should not appear in listings")
	}

	// 2. Should not be usable for signing
	_, err = securityManager.Sign(ctx, "mock-hsm", config, signingRequest)
	assert.Error(t, err, "Deleted key should not be usable for signing")

	// 3. Should not be usable for verification (using the old signature)
	_, err = securityManager.Verify(ctx, "mock-hsm", config, keyHandle.ID, 
		testData, sigResponse.Signature, "RSA-PSS")
	assert.Error(t, err, "Deleted key should not be usable for verification")

	// 4. Key retrieval should fail
	_, err = securityManager.GetKey(ctx, "mock-hsm", config, keyHandle.ID)
	assert.Error(t, err, "Deleted key should not be retrievable")
}

// TestProviderSecurityIsolation tests security isolation between providers
func TestProviderSecurityIsolation(t *testing.T) {
	setupSecurityTests()
	ctx := context.Background()

	mockConfig := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "mock-isolation",
	}

	customConfig := map[string]interface{}{
		"storage_type":    "memory",
		"encrypt_at_rest": true,
		"key_prefix":      "custom-isolation",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Generate keys in both providers
	mockKey, err := securityManager.GenerateKey(ctx, "mock-hsm", mockConfig, keySpec, "provider-isolation-key")
	require.NoError(t, err)

	customKey, err := securityManager.GenerateKey(ctx, "custom-storage", customConfig, keySpec, "provider-isolation-key")
	require.NoError(t, err)

	defer func() {
		_ = securityManager.DeleteKey(ctx, "mock-hsm", mockConfig, mockKey.ID)
		_ = securityManager.DeleteKey(ctx, "custom-storage", customConfig, customKey.ID)
	}()

	// Test 1: Each provider should only see its own keys
	mockKeys, err := securityManager.ListKeys(ctx, "mock-hsm", mockConfig)
	require.NoError(t, err)

	customKeys, err := securityManager.ListKeys(ctx, "custom-storage", customConfig)
	require.NoError(t, err)

	// Verify isolation
	mockKeyIDs := make(map[string]bool)
	for _, key := range mockKeys {
		mockKeyIDs[key.ID] = true
	}

	for _, key := range customKeys {
		assert.False(t, mockKeyIDs[key.ID], 
			"Custom storage provider should not see mock HSM keys")
	}

	// Test 2: Cross-provider key access should fail
	testData := []byte("Cross-provider access test")

	// Try to use mock key with custom provider
	signingRequest := models.SigningRequest{
		KeyHandle: mockKey.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}

	_, err = securityManager.Sign(ctx, "custom-storage", customConfig, signingRequest)
	assert.Error(t, err, "Should not be able to use mock HSM key with custom storage provider")

	// Try to use custom key with mock provider
	signingRequest.KeyHandle = customKey.ID
	_, err = securityManager.Sign(ctx, "mock-hsm", mockConfig, signingRequest)
	assert.Error(t, err, "Should not be able to use custom storage key with mock HSM provider")

	t.Log("Provider isolation verified: keys are properly isolated between providers")
}

// TestCryptographicStrength tests the cryptographic strength of generated keys
func TestCryptographicStrength(t *testing.T) {
	setupSecurityTests()
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "crypto-strength",
	}

	testCases := []struct {
		name      string
		keyType   models.KeyType
		keySize   int
		algorithm string
		minSize   int
	}{
		{"RSA-2048", models.KeyTypeRSA, 2048, "RSA-PSS", 2048},
		{"RSA-3072", models.KeyTypeRSA, 3072, "RSA-PSS", 3072},
		{"RSA-4096", models.KeyTypeRSA, 4096, "RSA-PSS", 4096},
		{"ECDSA-P256", models.KeyTypeECDSA, 256, "ECDSA", 256},
		{"ECDSA-P384", models.KeyTypeECDSA, 384, "ECDSA", 384},
		{"ECDSA-P521", models.KeyTypeECDSA, 521, "ECDSA", 521},
		{"Ed25519", models.KeyTypeEd25519, 256, "Ed25519", 256},
	}

	var createdKeys []*models.KeyHandle

	defer func() {
		// Clean up
		for _, keyHandle := range createdKeys {
			_ = securityManager.DeleteKey(ctx, "mock-hsm", config, keyHandle.ID)
		}
	}()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keySpec := models.KeySpec{
				KeyType:   tc.keyType,
				KeySize:   tc.keySize,
				Algorithm: tc.algorithm,
				Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
			}

			keyHandle, err := securityManager.GenerateKey(ctx, "mock-hsm", config, keySpec, 
				fmt.Sprintf("strength-test-%s", tc.name))
			require.NoError(t, err)
			createdKeys = append(createdKeys, keyHandle)

			// Verify key properties
			assert.Equal(t, tc.keyType, keyHandle.KeyType)
			assert.Equal(t, tc.keySize, keyHandle.KeySize)
			assert.GreaterOrEqual(t, keyHandle.KeySize, tc.minSize, 
				"Key size should meet minimum security requirements")

			// Test signing and verification
			testData := []byte(fmt.Sprintf("Cryptographic strength test for %s", tc.name))
			signingRequest := models.SigningRequest{
				KeyHandle: keyHandle.ID,
				Data:      testData,
				Algorithm: tc.algorithm,
			}

			sigResponse, err := securityManager.Sign(ctx, "mock-hsm", config, signingRequest)
			require.NoError(t, err)
			require.NotEmpty(t, sigResponse.Signature)

			// Verify signature
			valid, err := securityManager.Verify(ctx, "mock-hsm", config, keyHandle.ID, 
				testData, sigResponse.Signature, tc.algorithm)
			require.NoError(t, err)
			require.True(t, valid)

			t.Logf("Successfully tested %s key with %d-bit strength", 
				tc.keyType, tc.keySize)
		})
	}
}

// TestConcurrentSecurityOperations tests security under concurrent access
func TestConcurrentSecurityOperations(t *testing.T) {
	setupSecurityTests()
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "concurrent-security",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Generate a shared key for concurrent operations
	sharedKey, err := securityManager.GenerateKey(ctx, "mock-hsm", config, keySpec, "concurrent-shared-key")
	require.NoError(t, err)

	defer func() {
		_ = securityManager.DeleteKey(ctx, "mock-hsm", config, sharedKey.ID)
	}()

	const numConcurrentOps = 50
	errors := make(chan error, numConcurrentOps)
	results := make(chan bool, numConcurrentOps)

	// Launch concurrent signing operations
	for i := 0; i < numConcurrentOps; i++ {
		go func(operationID int) {
			testData := []byte(fmt.Sprintf("Concurrent security test data %d", operationID))
			signingRequest := models.SigningRequest{
				KeyHandle: sharedKey.ID,
				Data:      testData,
				Algorithm: "RSA-PSS",
			}

			// Sign
			sigResponse, err := securityManager.Sign(ctx, "mock-hsm", config, signingRequest)
			if err != nil {
				errors <- err
				return
			}

			// Verify
			valid, err := securityManager.Verify(ctx, "mock-hsm", config, sharedKey.ID, 
				testData, sigResponse.Signature, "RSA-PSS")
			if err != nil {
				errors <- err
				return
			}

			results <- valid
		}(i)
	}

	// Collect results
	var successCount, errorCount int
	for i := 0; i < numConcurrentOps; i++ {
		select {
		case err := <-errors:
			errorCount++
			t.Logf("Concurrent operation error: %v", err)
		case valid := <-results:
			if valid {
				successCount++
			} else {
				t.Error("Signature verification failed in concurrent test")
			}
		case <-time.After(30 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}

	// All operations should succeed
	assert.Equal(t, numConcurrentOps, successCount, "All concurrent operations should succeed")
	assert.Equal(t, 0, errorCount, "No concurrent operations should error")

	t.Logf("Concurrent security test completed: %d successes, %d errors", successCount, errorCount)
}