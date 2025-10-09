// Package core provides the central orchestration layer for HSM operations,
// including provider management, metrics, and audit logging.
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
	registry   *ProviderRegistry
	logger     *logrus.Logger
	auditor    audit.Auditor
	metrics    metrics.Collector
	clients    map[string]models.HSMClient
	clientsMux map[string]*clientMutex
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
			_ = m.auditor.LogEvent(ctx, models.AuditEvent{
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
		_ = m.auditor.LogEvent(ctx, models.AuditEvent{
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
			_ = m.auditor.LogEvent(ctx, models.AuditEvent{
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
		_ = m.auditor.LogEvent(ctx, models.AuditEvent{
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
		"provider":    providerName,
		"key_id":      keyHandle.ID,
		"key_name":    name,
		"key_type":    spec.KeyType,
		"duration_ms": time.Since(start).Milliseconds(),
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
			_ = m.auditor.LogEvent(ctx, models.AuditEvent{
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
		_ = m.auditor.LogEvent(ctx, models.AuditEvent{
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
	return executeWithClientAndReturn(m, ctx, providerName, providerConfig, "encrypt", request.KeyHandle,
		func(client models.HSMClient) (*models.EncryptionResponse, error) {
			return client.Encrypt(ctx, request)
		},
		func(response *models.EncryptionResponse) map[string]string {
			return map[string]string{
				"algorithm":       response.Algorithm,
				"plaintext_size":  fmt.Sprintf("%d", len(request.Plaintext)),
				"ciphertext_size": fmt.Sprintf("%d", len(response.Ciphertext)),
			}
		})
}

// Decrypt performs a decryption operation using the specified provider
func (m *HSMManager) Decrypt(ctx context.Context, providerName string, providerConfig map[string]interface{}, request models.DecryptionRequest) (*models.DecryptionResponse, error) {
	return executeWithClientAndReturn(m, ctx, providerName, providerConfig, "decrypt", request.KeyHandle,
		func(client models.HSMClient) (*models.DecryptionResponse, error) {
			return client.Decrypt(ctx, request)
		},
		func(response *models.DecryptionResponse) map[string]string {
			return map[string]string{
				"algorithm":       response.Algorithm,
				"ciphertext_size": fmt.Sprintf("%d", len(request.Ciphertext)),
				"plaintext_size":  fmt.Sprintf("%d", len(response.Plaintext)),
			}
		})
}

// GetPublicKey retrieves the public key for a given key handle from the specified provider
func (m *HSMManager) GetPublicKey(ctx context.Context, providerName string, providerConfig map[string]interface{}, keyHandle string) (crypto.PublicKey, error) {
	return executeWithClientAndReturn(m, ctx, providerName, providerConfig, "get_public_key", keyHandle,
		func(client models.HSMClient) (crypto.PublicKey, error) {
			return client.GetPublicKey(ctx, keyHandle)
		}, nil)
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
	return executeWithClientAndReturn(m, ctx, providerName, providerConfig, "get_key", keyID,
		func(client models.HSMClient) (*models.KeyHandle, error) {
			return client.GetKey(ctx, keyID)
		}, nil)
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
			_ = m.auditor.LogEvent(ctx, models.AuditEvent{
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
		_ = m.auditor.LogEvent(ctx, models.AuditEvent{
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
	return m.executeWithClient(ctx, providerName, providerConfig, "activate_key", keyID, func(client models.HSMClient) error {
		return client.ActivateKey(ctx, keyID)
	})
}

// DeactivateKey deactivates a key in the specified provider
func (m *HSMManager) DeactivateKey(ctx context.Context, providerName string, providerConfig map[string]interface{}, keyID string) error {
	return m.executeWithClient(ctx, providerName, providerConfig, "deactivate_key", keyID, func(client models.HSMClient) error {
		return client.DeactivateKey(ctx, keyID)
	})
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
		_ = m.auditor.LogEvent(ctx, models.AuditEvent{
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

// operationWrapper wraps HSM operations with common error handling, metrics, and audit logging.
type operationWrapper struct {
	manager      *HSMManager
	ctx          context.Context
	providerName string
	operation    string
	keyID        string
	start        time.Time
}

// newOperationWrapper creates a new operation wrapper.
func (m *HSMManager) newOperationWrapper(ctx context.Context, providerName, operation, keyID string) *operationWrapper {
	return &operationWrapper{
		manager:      m,
		ctx:          ctx,
		providerName: providerName,
		operation:    operation,
		keyID:        keyID,
		start:        time.Now(),
	}
}

// handleError handles operation errors with audit logging and metrics.
func (w *operationWrapper) handleError(err error, errorCode string, message string) error {
	hsmErr := models.NewHSMErrorWithCause(errorCode, message, err).
		WithProvider(w.providerName).
		WithOperation(w.operation)

	if w.manager.auditor != nil {
		_ = w.manager.auditor.LogEvent(w.ctx, models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Operation: w.operation,
			Provider:  w.providerName,
			KeyID:     w.keyID,
			Success:   false,
			Error:     hsmErr.Error(),
			Duration:  time.Since(w.start),
		})
	}

	if w.manager.metrics != nil {
		w.manager.metrics.RecordOperation(w.operation, w.providerName, time.Since(w.start), false, hsmErr)
	}

	return hsmErr
}

// handleSuccess handles successful operations with audit logging and metrics.
func (w *operationWrapper) handleSuccess(metadata map[string]string) {
	if w.manager.auditor != nil {
		_ = w.manager.auditor.LogEvent(w.ctx, models.AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Operation: w.operation,
			Provider:  w.providerName,
			KeyID:     w.keyID,
			Success:   true,
			Duration:  time.Since(w.start),
			Metadata:  metadata,
		})
	}

	if w.manager.metrics != nil {
		w.manager.metrics.RecordOperation(w.operation, w.providerName, time.Since(w.start), true, nil)
	}
}

// executeWithClient executes an operation function with a client, handling common patterns.
func (m *HSMManager) executeWithClient(ctx context.Context, providerName string, providerConfig map[string]interface{}, operation string, keyID string, fn func(models.HSMClient) error) error {
	wrapper := m.newOperationWrapper(ctx, providerName, operation, keyID)
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return err
	}

	if err := fn(client); err != nil {
		return wrapper.handleError(err, getErrorCodeForOperation(operation), fmt.Sprintf("%s operation failed", operation))
	}

	wrapper.handleSuccess(nil)
	return nil
}

// executeWithClientAndReturn executes an operation function that returns a value.
func executeWithClientAndReturn[T any](m *HSMManager, ctx context.Context, providerName string, providerConfig map[string]interface{}, operation string, keyID string, fn func(models.HSMClient) (T, error), metadata func(T) map[string]string) (T, error) {
	wrapper := m.newOperationWrapper(ctx, providerName, operation, keyID)
	var zero T
	
	client, err := m.GetClient(ctx, providerName, providerConfig)
	if err != nil {
		return zero, err
	}

	result, err := fn(client)
	if err != nil {
		return zero, wrapper.handleError(err, getErrorCodeForOperation(operation), fmt.Sprintf("%s operation failed", operation))
	}

	var metadataMap map[string]string
	if metadata != nil {
		metadataMap = metadata(result)
	}
	wrapper.handleSuccess(metadataMap)
	return result, nil
}

// getErrorCodeForOperation returns the appropriate error code for an operation.
func getErrorCodeForOperation(operation string) string {
	switch operation {
	case "activate_key":
		return models.ErrCodeKeyActivationFailed
	case "deactivate_key":
		return models.ErrCodeKeyDeactivationFailed
	case "delete_key":
		return models.ErrCodeKeyDeletionFailed
	case "encrypt":
		return models.ErrCodeEncryptionFailed
	case "decrypt":
		return models.ErrCodeDecryptionFailed
	case "sign":
		return models.ErrCodeSigningFailed
	case "verify":
		return models.ErrCodeVerificationFailed
	case "get_key", "get_public_key":
		return models.ErrCodeKeyNotFound
	default:
		return models.ErrCodeUnknown
	}
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
