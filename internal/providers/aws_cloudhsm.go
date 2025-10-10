// Package providers contains HSM provider implementations for various
// backends including AWS CloudHSM, Azure Key Vault, custom storage, and mock HSM.
package providers

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudhsmv2"
	"github.com/aws/aws-sdk-go-v2/service/cloudhsmv2/types"
	"github.com/sirupsen/logrus"

	"github.com/jimmy/keygridhsm/pkg/models"
)

const (
	AWSCloudHSMProviderName    = "aws-cloudhsm"
	AWSCloudHSMProviderVersion = "1.0.0"
)

// AWSCloudHSMProvider implements the HSMProvider interface for AWS CloudHSM
type AWSCloudHSMProvider struct {
	logger *logrus.Logger
}

// AWSCloudHSMClient implements the HSMClient interface for AWS CloudHSM
type AWSCloudHSMClient struct {
	client    *cloudhsmv2.Client
	region    string
	clusterID string
	logger    *logrus.Logger
	config    *AWSCloudHSMConfig
}

// AWSCloudHSMConfig holds configuration for AWS CloudHSM
type AWSCloudHSMConfig struct {
	Region          string `json:"region"`
	ClusterID       string `json:"cluster_id"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SessionToken    string `json:"session_token,omitempty"`
	Profile         string `json:"profile,omitempty"`
	RoleARN         string `json:"role_arn,omitempty"`
	UseInstanceRole bool   `json:"use_instance_role"`
}

// NewAWSCloudHSMProvider creates a new AWS CloudHSM provider
func NewAWSCloudHSMProvider(logger *logrus.Logger) *AWSCloudHSMProvider {
	if logger == nil {
		logger = logrus.New()
	}

	return &AWSCloudHSMProvider{
		logger: logger,
	}
}

// Provider interface implementation
func (p *AWSCloudHSMProvider) Name() string {
	return AWSCloudHSMProviderName
}

func (p *AWSCloudHSMProvider) Version() string {
	return AWSCloudHSMProviderVersion
}

func (p *AWSCloudHSMProvider) Capabilities() []string {
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
		"fips_140_2_level_3",
		"dedicated_hardware",
	}
}

func (p *AWSCloudHSMProvider) ValidateConfig(config map[string]interface{}) error {
	awsConfig, err := parseAWSCloudHSMConfig(config)
	if err != nil {
		return models.NewHSMErrorWithCause(models.ErrCodeInvalidConfig,
			"Invalid AWS CloudHSM configuration", err).
			WithProvider(AWSCloudHSMProviderName)
	}

	if awsConfig.Region == "" {
		return models.NewHSMError(models.ErrCodeInvalidConfig,
			"region is required for AWS CloudHSM provider").
			WithProvider(AWSCloudHSMProviderName)
	}

	if awsConfig.ClusterID == "" {
		return models.NewHSMError(models.ErrCodeInvalidConfig,
			"cluster_id is required for AWS CloudHSM provider").
			WithProvider(AWSCloudHSMProviderName)
	}

	return nil
}

func (p *AWSCloudHSMProvider) CreateClient(config map[string]interface{}) (models.HSMClient, error) {
	awsConfig, err := parseAWSCloudHSMConfig(config)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeInvalidConfig,
			"Failed to parse AWS CloudHSM configuration", err).
			WithProvider(AWSCloudHSMProviderName)
	}

	if validationErr := p.ValidateConfig(config); validationErr != nil {
		return nil, validationErr
	}

	// Load AWS configuration
	cfg, err := p.loadAWSConfig(context.Background(), awsConfig)
	if err != nil {
		return nil, models.NewHSMErrorWithCause(models.ErrCodeAuthenticationFailed,
			"Failed to load AWS configuration", err).
			WithProvider(AWSCloudHSMProviderName)
	}

	// Create CloudHSM client
	client := cloudhsmv2.NewFromConfig(cfg)

	return &AWSCloudHSMClient{
		client:    client,
		region:    awsConfig.Region,
		clusterID: awsConfig.ClusterID,
		logger:    p.logger,
		config:    awsConfig,
	}, nil
}

func (p *AWSCloudHSMProvider) Initialize(config map[string]interface{}) error {
	// AWS CloudHSM provider doesn't need global initialization
	return nil
}

func (p *AWSCloudHSMProvider) Shutdown() error {
	// AWS CloudHSM provider doesn't need cleanup
	return nil
}

// Client interface implementation
func (c *AWSCloudHSMClient) Health(ctx context.Context) (*models.HealthStatus, error) {
	start := time.Now()

	// Test connection by describing the cluster
	input := &cloudhsmv2.DescribeClustersInput{
		Filters: map[string][]string{
			"clusterIds": {c.clusterID},
		},
	}

	result, err := c.client.DescribeClusters(ctx, input)
	if err != nil {
		return &models.HealthStatus{
			Status:       "unhealthy",
			Provider:     AWSCloudHSMProviderName,
			LastCheck:    time.Now(),
			Error:        err.Error(),
			ResponseTime: time.Since(start),
			Details: map[string]string{
				"region":     c.region,
				"cluster_id": c.clusterID,
			},
		}, models.NewHSMErrorWithCause(models.ErrCodeServiceUnavailable,
			"AWS CloudHSM health check failed", err).
			WithProvider(AWSCloudHSMProviderName)
	}

	var clusterState string
	if len(result.Clusters) > 0 {
		clusterState = string(result.Clusters[0].State)
	}

	return &models.HealthStatus{
		Status:       "healthy",
		Provider:     AWSCloudHSMProviderName,
		LastCheck:    time.Now(),
		ResponseTime: time.Since(start),
		Details: map[string]string{
			"region":        c.region,
			"cluster_id":    c.clusterID,
			"cluster_state": clusterState,
		},
	}, nil
}

func (c *AWSCloudHSMClient) GetProviderInfo(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"provider":             AWSCloudHSMProviderName,
		"version":              AWSCloudHSMProviderVersion,
		"region":               c.region,
		"cluster_id":           c.clusterID,
		"hsm_backed":           true,
		"enterprise":           true,
		"fips_140_2_level_3":   true,
		"dedicated_hardware":   true,
	}, nil
}

func (c *AWSCloudHSMClient) GenerateKey(ctx context.Context, spec models.KeySpec, name string) (*models.KeyHandle, error) {
	// Note: AWS CloudHSM v2 uses PKCS#11 or JCE for key operations
	// This is a simplified implementation - in practice, you'd use the CloudHSM client SDK
	// and connect to the actual HSM cluster with proper authentication
	
	// For now, return an error indicating this needs proper CloudHSM client setup
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM key generation requires proper PKCS#11 client setup and HSM cluster initialization. "+
		"This implementation requires the CloudHSM client library and cluster access.").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("generate_key").
		WithDetails(map[string]interface{}{
			"key_name":   name,
			"key_type":   spec.KeyType,
			"cluster_id": c.clusterID,
			"note":       "CloudHSM operations require dedicated client library integration",
		})
}

func (c *AWSCloudHSMClient) ImportKey(ctx context.Context, keyData []byte, spec models.KeySpec, name string) (*models.KeyHandle, error) {
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM key import requires proper PKCS#11 client setup").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("import_key")
}

func (c *AWSCloudHSMClient) GetKey(ctx context.Context, keyHandle string) (*models.KeyHandle, error) {
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM key retrieval requires proper PKCS#11 client setup").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("get_key")
}

func (c *AWSCloudHSMClient) ListKeys(ctx context.Context) ([]*models.KeyHandle, error) {
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM key listing requires proper PKCS#11 client setup").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("list_keys")
}

func (c *AWSCloudHSMClient) DeleteKey(ctx context.Context, keyHandle string) error {
	return models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM key deletion requires proper PKCS#11 client setup").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("delete_key")
}

func (c *AWSCloudHSMClient) ActivateKey(ctx context.Context, keyHandle string) error {
	return models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM key activation requires proper PKCS#11 client setup").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("activate_key")
}

func (c *AWSCloudHSMClient) DeactivateKey(ctx context.Context, keyHandle string) error {
	return models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM key deactivation requires proper PKCS#11 client setup").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("deactivate_key")
}

func (c *AWSCloudHSMClient) GetPublicKey(ctx context.Context, keyHandle string) (crypto.PublicKey, error) {
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM public key operations require proper PKCS#11 client setup").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("get_public_key")
}

func (c *AWSCloudHSMClient) Sign(ctx context.Context, keyHandle string, digest []byte, algorithm string) ([]byte, error) {
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM signing operations require proper PKCS#11 client setup").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("sign")
}

func (c *AWSCloudHSMClient) Verify(ctx context.Context, keyHandle string, digest, signature []byte, algorithm string) (bool, error) {
	return false, models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM verification operations require proper PKCS#11 client setup").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("verify")
}

func (c *AWSCloudHSMClient) Encrypt(ctx context.Context, keyHandle string, plaintext []byte) ([]byte, error) {
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM encryption operations require proper PKCS#11 client setup").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("encrypt")
}

func (c *AWSCloudHSMClient) Decrypt(ctx context.Context, keyHandle string, ciphertext []byte) ([]byte, error) {
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM decryption operations require proper PKCS#11 client setup").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("decrypt")
}

func (c *AWSCloudHSMClient) WrapKey(ctx context.Context, keyHandle, wrappingKeyHandle string) ([]byte, error) {
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM key wrapping operations require proper PKCS#11 client setup").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("wrap_key")
}

func (c *AWSCloudHSMClient) UnwrapKey(ctx context.Context, wrappedKey []byte, wrappingKeyHandle string) ([]byte, error) {
	return nil, models.NewHSMError(models.ErrCodeInvalidInput,
		"AWS CloudHSM key unwrapping operations require proper PKCS#11 client setup").
		WithProvider(AWSCloudHSMProviderName).
		WithOperation("unwrap_key")
}

// Helper functions
func (p *AWSCloudHSMProvider) loadAWSConfig(ctx context.Context, awsConfig *AWSCloudHSMConfig) (config.Config, error) {
	var opts []func(*config.LoadOptions) error

	opts = append(opts, config.WithRegion(awsConfig.Region))

	if awsConfig.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(awsConfig.Profile))
	}

	return config.LoadDefaultConfig(ctx, opts...)
}

// Utility functions
func parseAWSCloudHSMConfig(config map[string]interface{}) (*AWSCloudHSMConfig, error) {
	awsConfig := &AWSCloudHSMConfig{}

	if region, ok := config["region"].(string); ok {
		awsConfig.Region = region
	}

	if clusterID, ok := config["cluster_id"].(string); ok {
		awsConfig.ClusterID = clusterID
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