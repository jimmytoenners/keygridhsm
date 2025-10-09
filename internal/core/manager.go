package core

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/jimmy/keygridhsm/internal/audit"
	"github.com/jimmy/keygridhsm/internal/metrics"
	"github.com/jimmy/keygridhsm/pkg/models"
)

// HSMManager provides high-level HSM operations with monitoring, audit, and error handling
type HSMManager struct {
	registry    *ProviderRegistry
	logger      *logrus.Logger
	auditor     audit.Auditor
	metrics     metrics.Collector
	clients     map[string]models.HSMClient
	clientsMux  map[string]*clientMutex
}

type clientMutex struct {
	client models.HSMClient
}

// HSMManagerConfig holds configuration for the HSM manager
type HSMManagerConfig struct {
	Registry *ProviderRegistry
	Logger   *logrus.Logger
	Auditor  audit.Auditor
	Metrics  metrics.Collector
}

// NewHSMManager creates a new HSM manager
func NewHSMManager(config HSMManagerConfig) *HSMManager {
	if config.Registry == nil {
		config.Registry = GetGlobalRegistry()
	}
	
	if config.Logger == nil {
		config.Logger = logrus.New()
	}

	return &HSMManager{
		registry:   config.Registry,
		logger:     config.Logger,
		auditor:    config.Auditor,
		metrics:    config.Metrics,
		clients:    make(map[string]models.HSMClient),
		clientsMux: make(map[string]*clientMutex),
	}
}

// GetClient creates or retrieves an HSM client for the specified provider
func (m *HSMManager) GetClient(ctx context.Context, providerName string, config map[string]interface{}) (models.HSMClient, error) {
	start := time.Now()
	
	// Check if client already exists
	if client, exists := m.clients[providerName]; exists {
		// Test health of existing client
		if health, err := client.Health(ctx); err == nil && health.Status == "healthy" {
			if m.metrics != nil {
				m.metrics.RecordOperation("get_client", providerName, time.Since(start), true, nil)
			}
			return client, nil
		}
		// Remove unhealthy client
		delete(m.clients, providerName)
		delete(m.clientsMux, providerName)
	}

	// Create new client
	client, err := m.registry.CreateClient(providerName, config)
	if err != nil {
		hsmErr := models.NewHSMErrorWithCause(models.ErrCodeProviderUnavailable, 
			fmt.Sprintf("Failed to create client for provider %s", providerName), err).
			WithProvider(providerName).
			WithOperation("get_client")
		
		if m.auditor != nil {
			m.auditor.LogEvent(ctx, models.AuditEvent{
				ID:        uuid.New().String(),
				Timestamp: time.Now(),
				Operation: "get_client",
				Provider:  providerName,
				Success:   false,
				Error:     hsmErr.Error(),
				Duration:  time.Since(start),
			})
		}
		
		if m.metrics != nil {
			m.metrics.RecordOperation("get_client", providerName, time.Since(start), false, hsmErr)
		}
		
		return nil, hsmErr
	}

	// Store client
	m.clients[providerName] = client
	m.clientsMux[providerName] = &clientMutex{client: client}

	if m.auditor != nil {
		m.auditor.LogEvent(ctx, models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Operation: "get_client",
			Provider:  providerName,
			Success:   true,
			Duration:  time.Since(start),
		})
	}

	if m.metrics != nil {
		m.metrics.RecordOperation("get_client", providerName, time.Since(start), true, nil)
	}

	return client, nil
}

// GenerateKey generates a new key using the specified provider
func (m *HSMManager) GenerateKey(ctx context.Context, providerName string, providerConfig map[string]interface{}, spec models.KeySpec, name string) (*models.KeyHandle, error) {
	start := time.Now()
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return nil, err
	}

	keyHandle, err := client.GenerateKey(ctx, spec, name)
	if err != nil {
		hsmErr := models.NewHSMErrorWithCause(models.ErrCodeKeyGenerationFailed, 
			"Key generation failed", err).
			WithProvider(providerName).
			WithOperation("generate_key")
		
		if m.auditor != nil {
			m.auditor.LogEvent(ctx, models.AuditEvent{
				ID:        uuid.New().String(),
				Timestamp: time.Now(),
				Operation: "generate_key",
				Provider:  providerName,
				Success:   false,
				Error:     hsmErr.Error(),
				Duration:  time.Since(start),
				Metadata: map[string]string{
					"key_name": name,
					"key_type": string(spec.KeyType),
				},
			})
		}
		
		if m.metrics != nil {
			m.metrics.RecordOperation("generate_key", providerName, time.Since(start), false, hsmErr)
		}
		
		return nil, hsmErr
	}

	if m.auditor != nil {
		m.auditor.LogEvent(ctx, models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Operation: "generate_key",
			Provider:  providerName,
			KeyID:     keyHandle.ID,
			Success:   true,
			Duration:  time.Since(start),
			Metadata: map[string]string{
				"key_name": name,
				"key_type": string(spec.KeyType),
				"key_size": fmt.Sprintf("%d", spec.KeySize),
			},
		})
	}

	if m.metrics != nil {
		m.metrics.RecordOperation("generate_key", providerName, time.Since(start), true, nil)
	}

	m.logger.WithFields(logrus.Fields{
		"provider":     providerName,
		"key_id":       keyHandle.ID,
		"key_name":     name,
		"key_type":     spec.KeyType,
		"duration_ms":  time.Since(start).Milliseconds(),
	}).Info("Key generated successfully")

	return keyHandle, nil
}

// Sign performs a signing operation using the specified provider
func (m *HSMManager) Sign(ctx context.Context, providerName string, providerConfig map[string]interface{}, request models.SigningRequest) (*models.SigningResponse, error) {
	start := time.Now()
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return nil, err
	}

	response, err := client.Sign(ctx, request)
	if err != nil {
		hsmErr := models.NewHSMErrorWithCause(models.ErrCodeSigningFailed, 
			"Signing operation failed", err).
			WithProvider(providerName).
			WithOperation("sign")
		
		if m.auditor != nil {
			m.auditor.LogEvent(ctx, models.AuditEvent{
				ID:        uuid.New().String(),
				Timestamp: time.Now(),
				Operation: "sign",
				Provider:  providerName,
				KeyID:     request.KeyHandle,
				Success:   false,
				Error:     hsmErr.Error(),
				Duration:  time.Since(start),
			})
		}
		
		if m.metrics != nil {
			m.metrics.RecordOperation("sign", providerName, time.Since(start), false, hsmErr)
		}
		
		return nil, hsmErr
	}

	if m.auditor != nil {
		m.auditor.LogEvent(ctx, models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Operation: "sign",
			Provider:  providerName,
			KeyID:     request.KeyHandle,
			Success:   true,
			Duration:  time.Since(start),
			Metadata: map[string]string{
				"algorithm": response.Algorithm,
				"data_size": fmt.Sprintf("%d", len(request.Data)),
			},
		})
	}

	if m.metrics != nil {
		m.metrics.RecordOperation("sign", providerName, time.Since(start), true, nil)
	}

	return response, nil
}

// Encrypt performs an encryption operation using the specified provider
func (m *HSMManager) Encrypt(ctx context.Context, providerName string, providerConfig map[string]interface{}, request models.EncryptionRequest) (*models.EncryptionResponse, error) {
	start := time.Now()
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return nil, err
	}

	response, err := client.Encrypt(ctx, request)
	if err != nil {
		hsmErr := models.NewHSMErrorWithCause(models.ErrCodeEncryptionFailed, 
			"Encryption operation failed", err).
			WithProvider(providerName).
			WithOperation("encrypt")
		
		if m.auditor != nil {
			m.auditor.LogEvent(ctx, models.AuditEvent{
				ID:        uuid.New().String(),
				Timestamp: time.Now(),
				Operation: "encrypt",
				Provider:  providerName,
				KeyID:     request.KeyHandle,
				Success:   false,
				Error:     hsmErr.Error(),
				Duration:  time.Since(start),
			})
		}
		
		if m.metrics != nil {
			m.metrics.RecordOperation("encrypt", providerName, time.Since(start), false, hsmErr)
		}
		
		return nil, hsmErr
	}

	if m.auditor != nil {
		m.auditor.LogEvent(ctx, models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Operation: "encrypt",
			Provider:  providerName,
			KeyID:     request.KeyHandle,
			Success:   true,
			Duration:  time.Since(start),
			Metadata: map[string]string{
				"algorithm":        response.Algorithm,
				"plaintext_size":   fmt.Sprintf("%d", len(request.Plaintext)),
				"ciphertext_size":  fmt.Sprintf("%d", len(response.Ciphertext)),
			},
		})
	}

	if m.metrics != nil {
		m.metrics.RecordOperation("encrypt", providerName, time.Since(start), true, nil)
	}

	return response, nil
}

// Decrypt performs a decryption operation using the specified provider
func (m *HSMManager) Decrypt(ctx context.Context, providerName string, providerConfig map[string]interface{}, request models.DecryptionRequest) (*models.DecryptionResponse, error) {
	start := time.Now()
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return nil, err
	}

	response, err := client.Decrypt(ctx, request)
	if err != nil {
		hsmErr := models.NewHSMErrorWithCause(models.ErrCodeDecryptionFailed, 
			"Decryption operation failed", err).
			WithProvider(providerName).
			WithOperation("decrypt")
		
		if m.auditor != nil {
			m.auditor.LogEvent(ctx, models.AuditEvent{
				ID:        uuid.New().String(),
				Timestamp: time.Now(),
				Operation: "decrypt",
				Provider:  providerName,
				KeyID:     request.KeyHandle,
				Success:   false,
				Error:     hsmErr.Error(),
				Duration:  time.Since(start),
			})
		}
		
		if m.metrics != nil {
			m.metrics.RecordOperation("decrypt", providerName, time.Since(start), false, hsmErr)
		}
		
		return nil, hsmErr
	}

	if m.auditor != nil {
		m.auditor.LogEvent(ctx, models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Operation: "decrypt",
			Provider:  providerName,
			KeyID:     request.KeyHandle,
			Success:   true,
			Duration:  time.Since(start),
			Metadata: map[string]string{
				"algorithm":        response.Algorithm,
				"ciphertext_size":  fmt.Sprintf("%d", len(request.Ciphertext)),
				"plaintext_size":   fmt.Sprintf("%d", len(response.Plaintext)),
			},
		})
	}

	if m.metrics != nil {
		m.metrics.RecordOperation("decrypt", providerName, time.Since(start), true, nil)
	}

	return response, nil
}

// GetPublicKey retrieves the public key for a given key handle
func (m *HSMManager) GetPublicKey(ctx context.Context, providerName string, providerConfig map[string]interface{}, keyHandle string) (crypto.PublicKey, error) {
	start := time.Now()
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return nil, err
	}

	publicKey, err := client.GetPublicKey(ctx, keyHandle)
	if err != nil {
		hsmErr := models.NewHSMErrorWithCause(models.ErrCodeKeyNotFound, 
			"Failed to retrieve public key", err).
			WithProvider(providerName).
			WithOperation("get_public_key")
		
		if m.metrics != nil {
			m.metrics.RecordOperation("get_public_key", providerName, time.Since(start), false, hsmErr)
		}
		
		return nil, hsmErr
	}

	if m.metrics != nil {
		m.metrics.RecordOperation("get_public_key", providerName, time.Since(start), true, nil)
	}

	return publicKey, nil
}

// ListKeys lists all keys for a given provider
func (m *HSMManager) ListKeys(ctx context.Context, providerName string, providerConfig map[string]interface{}) ([]*models.KeyHandle, error) {
	start := time.Now()
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return nil, err
	}

	keys, err := client.ListKeys(ctx)
	if err != nil {
		hsmErr := models.NewHSMErrorWithCause(models.ErrCodeUnknown, 
			"Failed to list keys", err).
			WithProvider(providerName).
			WithOperation("list_keys")
		
		if m.metrics != nil {
			m.metrics.RecordOperation("list_keys", providerName, time.Since(start), false, hsmErr)
		}
		
		return nil, hsmErr
	}

	if m.metrics != nil {
		m.metrics.RecordOperation("list_keys", providerName, time.Since(start), true, nil)
	}

	return keys, nil
}

// CheckHealth checks the health of a specific provider
func (m *HSMManager) CheckHealth(ctx context.Context, providerName string, providerConfig map[string]interface{}) (*models.HealthStatus, error) {
	start := time.Now()
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return &models.HealthStatus{
			Status:       "unhealthy",
			Provider:     providerName,
			LastCheck:    time.Now(),
			Error:        err.Error(),
			ResponseTime: time.Since(start),
		}, err
	}

	health, err := client.Health(ctx)
	if err != nil {
		health = &models.HealthStatus{
			Status:       "unhealthy",
			Provider:     providerName,
			LastCheck:    time.Now(),
			Error:        err.Error(),
			ResponseTime: time.Since(start),
		}
	} else {
		health.ResponseTime = time.Since(start)
	}

	if m.metrics != nil {
		m.metrics.RecordHealthCheck(providerName, health.Status == "healthy", time.Since(start))
	}

	return health, err
}

// GetKey retrieves a key handle by its ID from the specified provider
func (m *HSMManager) GetKey(ctx context.Context, providerName string, providerConfig map[string]interface{}, keyID string) (*models.KeyHandle, error) {
	start := time.Now()
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return nil, err
	}

	keyHandle, err := client.GetKey(ctx, keyID)
	if err != nil {
		hsmErr := models.NewHSMErrorWithCause(models.ErrCodeKeyNotFound, 
			"Failed to retrieve key", err).
			WithProvider(providerName).
			WithOperation("get_key")
		
		if m.metrics != nil {
			m.metrics.RecordOperation("get_key", providerName, time.Since(start), false, hsmErr)
		}
		
		return nil, hsmErr
	}

	if m.metrics != nil {
		m.metrics.RecordOperation("get_key", providerName, time.Since(start), true, nil)
	}

	return keyHandle, nil
}

// DeleteKey deletes a key from the specified provider
func (m *HSMManager) DeleteKey(ctx context.Context, providerName string, providerConfig map[string]interface{}, keyID string) error {
	start := time.Now()
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return err
	}

	err = client.DeleteKey(ctx, keyID)
	if err != nil {
		hsmErr := models.NewHSMErrorWithCause(models.ErrCodeKeyDeletionFailed, 
			"Failed to delete key", err).
			WithProvider(providerName).
			WithOperation("delete_key")
		
		if m.auditor != nil {
			m.auditor.LogEvent(ctx, models.AuditEvent{
				ID:        uuid.New().String(),
				Timestamp: time.Now(),
				Operation: "delete_key",
				Provider:  providerName,
				KeyID:     keyID,
				Success:   false,
				Error:     hsmErr.Error(),
				Duration:  time.Since(start),
			})
		}
		
		if m.metrics != nil {
			m.metrics.RecordOperation("delete_key", providerName, time.Since(start), false, hsmErr)
		}
		
		return hsmErr
	}

	if m.auditor != nil {
		m.auditor.LogEvent(ctx, models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Operation: "delete_key",
			Provider:  providerName,
			KeyID:     keyID,
			Success:   true,
			Duration:  time.Since(start),
		})
	}

	if m.metrics != nil {
		m.metrics.RecordOperation("delete_key", providerName, time.Since(start), true, nil)
	}

	m.logger.WithFields(logrus.Fields{
		"provider":    providerName,
		"key_id":      keyID,
		"duration_ms": time.Since(start).Milliseconds(),
	}).Info("Key deleted successfully")

	return nil
}

// ActivateKey activates a key in the specified provider
func (m *HSMManager) ActivateKey(ctx context.Context, providerName string, providerConfig map[string]interface{}, keyID string) error {
	start := time.Now()
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return err
	}

	err = client.ActivateKey(ctx, keyID)
	if err != nil {
		hsmErr := models.NewHSMErrorWithCause(models.ErrCodeKeyActivationFailed, 
			"Failed to activate key", err).
			WithProvider(providerName).
			WithOperation("activate_key")
		
		if m.metrics != nil {
			m.metrics.RecordOperation("activate_key", providerName, time.Since(start), false, hsmErr)
		}
		
		return hsmErr
	}

	if m.metrics != nil {
		m.metrics.RecordOperation("activate_key", providerName, time.Since(start), true, nil)
	}

	return nil
}

// DeactivateKey deactivates a key in the specified provider
func (m *HSMManager) DeactivateKey(ctx context.Context, providerName string, providerConfig map[string]interface{}, keyID string) error {
	start := time.Now()
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return err
	}

	err = client.DeactivateKey(ctx, keyID)
	if err != nil {
		hsmErr := models.NewHSMErrorWithCause(models.ErrCodeKeyDeactivationFailed, 
			"Failed to deactivate key", err).
			WithProvider(providerName).
			WithOperation("deactivate_key")
		
		if m.metrics != nil {
			m.metrics.RecordOperation("deactivate_key", providerName, time.Since(start), false, hsmErr)
		}
		
		return hsmErr
	}

	if m.metrics != nil {
		m.metrics.RecordOperation("deactivate_key", providerName, time.Since(start), true, nil)
	}

	return nil
}

// Verify performs a signature verification operation using the specified provider
func (m *HSMManager) Verify(ctx context.Context, providerName string, providerConfig map[string]interface{}, keyHandle string, data, signature []byte, algorithm string) (bool, error) {
	start := time.Now()
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return false, err
	}

	valid, err := client.Verify(ctx, keyHandle, data, signature, algorithm)
	if err != nil {
		hsmErr := models.NewHSMErrorWithCause(models.ErrCodeVerificationFailed, 
			"Verification operation failed", err).
			WithProvider(providerName).
			WithOperation("verify")
		
		if m.metrics != nil {
			m.metrics.RecordOperation("verify", providerName, time.Since(start), false, hsmErr)
		}
		
		return false, hsmErr
	}

	if m.metrics != nil {
		m.metrics.RecordOperation("verify", providerName, time.Since(start), true, nil)
	}

	return valid, nil
}

// SetKeyExpiration sets the expiration time for a key in the specified provider
func (m *HSMManager) SetKeyExpiration(ctx context.Context, providerName string, providerConfig map[string]interface{}, keyID string, expiration time.Time) error {
	start := time.Now()
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return err
	}

	err = client.SetKeyExpiration(ctx, keyID, expiration)
	if err != nil {
		hsmErr := models.NewHSMErrorWithCause(models.ErrCodeKeyNotFound, 
			"Failed to set key expiration", err).
			WithProvider(providerName).
			WithOperation("set_key_expiration")
		
		if m.metrics != nil {
			m.metrics.RecordOperation("set_key_expiration", providerName, time.Since(start), false, hsmErr)
		}
		
		return hsmErr
	}

	if m.auditor != nil {
		m.auditor.LogEvent(ctx, models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Operation: "set_key_expiration",
			Provider:  providerName,
			KeyID:     keyID,
			Success:   true,
			Duration:  time.Since(start),
			Metadata: map[string]string{
				"expiration": expiration.Format(time.RFC3339),
			},
		})
	}

	if m.metrics != nil {
		m.metrics.RecordOperation("set_key_expiration", providerName, time.Since(start), true, nil)
	}

	return nil
}

// CheckProviderHealth checks the health of a specific provider
func (m *HSMManager) CheckProviderHealth(ctx context.Context, providerName string, providerConfig map[string]interface{}) (*models.HealthStatus, error) {
	// This method is an alias for the existing CheckHealth method for backward compatibility
	return m.CheckHealth(ctx, providerName, providerConfig)
}

// ListProviders returns a list of registered provider names
func (m *HSMManager) ListProviders() []string {
	return m.registry.ListProviders()
}

// Close closes all HSM clients
func (m *HSMManager) Close() error {
	var lastErr error
	
	for providerName, client := range m.clients {
		if err := client.Close(); err != nil {
			m.logger.WithFields(logrus.Fields{
				"provider": providerName,
				"error":    err,
			}).Warn("Failed to close HSM client")
			lastErr = err
		}
	}

	// Clear clients map
	m.clients = make(map[string]models.HSMClient)
	m.clientsMux = make(map[string]*clientMutex)

	return lastErr
}
