package providers

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jimmy/keygridhsm/pkg/models"
)

func TestAWSKMSProvider_Basic(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel) // Reduce noise in tests

	provider := NewAWSKMSProvider(logger)

	t.Run("Provider Info", func(t *testing.T) {
		assert.Equal(t, AWSKMSProviderName, provider.Name())
		assert.Equal(t, AWSKMSProviderVersion, provider.Version())
		
		capabilities := provider.Capabilities()
		assert.Contains(t, capabilities, "key_generation")
		assert.Contains(t, capabilities, "signing")
		assert.Contains(t, capabilities, "encryption")
		assert.Contains(t, capabilities, "managed_service")
		assert.Contains(t, capabilities, "enterprise_grade")
	})

	t.Run("Config Validation", func(t *testing.T) {
		// Valid config
		validConfig := map[string]interface{}{
			"region": "us-west-2",
		}
		err := provider.ValidateConfig(validConfig)
		assert.NoError(t, err)

		// Missing region
		invalidConfig := map[string]interface{}{}
		err = provider.ValidateConfig(invalidConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "region is required")
	})

	t.Run("Client Creation", func(t *testing.T) {
		// Note: This will fail without real AWS credentials, but tests config parsing
		config := map[string]interface{}{
			"region":  "us-west-2",
			"profile": "default",
		}
		
		client, err := provider.CreateClient(config)
		// We expect this to fail due to missing credentials in test environment
		// but we want to ensure it gets to the credential loading phase
		if err != nil {
			assert.Contains(t, err.Error(), "Failed to load AWS configuration")
		} else {
			assert.NotNil(t, client)
		}
	})
}

func TestAWSKMSProvider_ConfigParsing(t *testing.T) {
	t.Run("Parse Valid Config", func(t *testing.T) {
		config := map[string]interface{}{
			"region":            "us-east-1",
			"access_key_id":     "test-access-key",
			"secret_access_key": "test-secret-key",
			"profile":           "test-profile",
			"use_instance_role": true,
		}

		awsConfig, err := parseAWSKMSConfig(config)
		require.NoError(t, err)
		
		assert.Equal(t, "us-east-1", awsConfig.Region)
		assert.Equal(t, "test-access-key", awsConfig.AccessKeyID)
		assert.Equal(t, "test-secret-key", awsConfig.SecretAccessKey)
		assert.Equal(t, "test-profile", awsConfig.Profile)
		assert.True(t, awsConfig.UseInstanceRole)
	})

	t.Run("Parse Empty Config", func(t *testing.T) {
		config := map[string]interface{}{}
		awsConfig, err := parseAWSKMSConfig(config)
		require.NoError(t, err)
		
		assert.Empty(t, awsConfig.Region)
		assert.Empty(t, awsConfig.AccessKeyID)
		assert.False(t, awsConfig.UseInstanceRole)
	})
}

func TestAWSKMSProvider_KeySpecConversion(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	// Create a mock client for testing conversion functions
	client := &AWSKMSClient{
		region: "us-west-2",
		logger: logger,
	}

	t.Run("Valid RSA Key Spec", func(t *testing.T) {
		spec := models.KeySpec{
			KeyType: models.KeyTypeRSA,
			KeySize: 2048,
			Usage:   []string{"sign", "verify"},
		}

		keyUsage, keySpec, err := client.convertKeySpecToAWS(spec)
		require.NoError(t, err)
		
		assert.Equal(t, "SIGN_VERIFY", string(keyUsage))
		assert.Equal(t, "RSA_2048", string(keySpec))
	})

	t.Run("Valid ECDSA Key Spec", func(t *testing.T) {
		spec := models.KeySpec{
			KeyType: models.KeyTypeECDSA,
			KeySize: 256,
			Usage:   []string{"sign"},
		}

		keyUsage, keySpec, err := client.convertKeySpecToAWS(spec)
		require.NoError(t, err)
		
		assert.Equal(t, "SIGN_VERIFY", string(keyUsage))
		assert.Equal(t, "ECC_NIST_P256", string(keySpec))
	})

	t.Run("Invalid Key Size", func(t *testing.T) {
		spec := models.KeySpec{
			KeyType: models.KeyTypeRSA,
			KeySize: 1024, // Unsupported
		}

		_, _, err := client.convertKeySpecToAWS(spec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Unsupported RSA key size")
	})

	t.Run("Invalid Key Type", func(t *testing.T) {
		spec := models.KeySpec{
			KeyType: "INVALID",
			KeySize: 2048,
		}

		_, _, err := client.convertKeySpecToAWS(spec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Unsupported key type")
	})
}

func TestAWSKMSProvider_AlgorithmConversion(t *testing.T) {
	client := &AWSKMSClient{}

	testCases := []struct {
		algorithm string
		expected  string
		shouldErr bool
	}{
		{"RS256", "RSASSA_PKCS1_V1_5_SHA_256", false},
		{"RS384", "RSASSA_PKCS1_V1_5_SHA_384", false},
		{"ES256", "ECDSA_SHA_256", false},
		{"ES384", "ECDSA_SHA_384", false},
		{"INVALID", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			result, err := client.convertAlgorithmToAWS(tc.algorithm)
			
			if tc.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, string(result))
			}
		})
	}
}

func TestAWSCloudHSMProvider_Basic(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	provider := NewAWSCloudHSMProvider(logger)

	t.Run("Provider Info", func(t *testing.T) {
		assert.Equal(t, AWSCloudHSMProviderName, provider.Name())
		assert.Equal(t, AWSCloudHSMProviderVersion, provider.Version())
		
		capabilities := provider.Capabilities()
		assert.Contains(t, capabilities, "key_generation")
		assert.Contains(t, capabilities, "signing")
		assert.Contains(t, capabilities, "hsm_backed")
		assert.Contains(t, capabilities, "fips_140_2_level_3")
		assert.Contains(t, capabilities, "dedicated_hardware")
	})

	t.Run("Config Validation", func(t *testing.T) {
		// Valid config
		validConfig := map[string]interface{}{
			"region":     "us-west-2",
			"cluster_id": "cluster-12345",
		}
		err := provider.ValidateConfig(validConfig)
		assert.NoError(t, err)

		// Missing region
		invalidConfig1 := map[string]interface{}{
			"cluster_id": "cluster-12345",
		}
		err = provider.ValidateConfig(invalidConfig1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "region is required")

		// Missing cluster_id
		invalidConfig2 := map[string]interface{}{
			"region": "us-west-2",
		}
		err = provider.ValidateConfig(invalidConfig2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cluster_id is required")
	})

	t.Run("Client Creation", func(t *testing.T) {
		config := map[string]interface{}{
			"region":     "us-west-2",
			"cluster_id": "cluster-12345",
			"profile":    "default",
		}
		
		client, err := provider.CreateClient(config)
		// We expect this to fail due to missing credentials in test environment
		if err != nil {
			assert.Contains(t, err.Error(), "Failed to load AWS configuration")
		} else {
			assert.NotNil(t, client)
		}
	})
}

func TestAWSCloudHSMProvider_ConfigParsing(t *testing.T) {
	t.Run("Parse Valid Config", func(t *testing.T) {
		config := map[string]interface{}{
			"region":            "eu-west-1",
			"cluster_id":        "cluster-abcdef",
			"access_key_id":     "test-access",
			"secret_access_key": "test-secret",
			"profile":           "cloudh-sm-profile",
			"use_instance_role": true,
		}

		awsConfig, err := parseAWSCloudHSMConfig(config)
		require.NoError(t, err)
		
		assert.Equal(t, "eu-west-1", awsConfig.Region)
		assert.Equal(t, "cluster-abcdef", awsConfig.ClusterID)
		assert.Equal(t, "test-access", awsConfig.AccessKeyID)
		assert.Equal(t, "test-secret", awsConfig.SecretAccessKey)
		assert.Equal(t, "cloudh-sm-profile", awsConfig.Profile)
		assert.True(t, awsConfig.UseInstanceRole)
	})
}

func TestAWSCloudHSMProvider_Operations(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	// Create a mock client
	client := &AWSCloudHSMClient{
		region:    "us-west-2",
		clusterID: "cluster-test",
		logger:    logger,
	}

	t.Run("All Operations Return Not Implemented", func(t *testing.T) {
		// All CloudHSM operations should return "not implemented" errors
		// until proper PKCS#11 integration is added

		spec := models.KeySpec{
			KeyType: models.KeyTypeRSA,
			KeySize: 2048,
		}

		_, err := client.GenerateKey(nil, spec, "test-key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "PKCS#11 client setup")

		_, err = client.GetKey(nil, "test-handle")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "PKCS#11 client setup")

		_, err = client.ListKeys(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "PKCS#11 client setup")

		err = client.DeleteKey(nil, "test-handle")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "PKCS#11 client setup")

		_, err = client.Sign(nil, "test-handle", []byte("test"), "RS256")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "PKCS#11 client setup")
	})
}

// Benchmark tests
func BenchmarkAWSKMSProvider_ConfigParsing(b *testing.B) {
	config := map[string]interface{}{
		"region":            "us-west-2",
		"access_key_id":     "test-key",
		"secret_access_key": "test-secret",
		"profile":           "test-profile",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseAWSKMSConfig(config)
	}
}

func BenchmarkAWSKMSProvider_ValidateConfig(b *testing.B) {
	provider := NewAWSKMSProvider(nil)
	config := map[string]interface{}{
		"region": "us-west-2",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = provider.ValidateConfig(config)
	}
}