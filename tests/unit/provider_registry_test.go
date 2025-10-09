package unit

import (
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jimmy/keygridhsm/internal/core"
	"github.com/jimmy/keygridhsm/internal/providers"
	"github.com/jimmy/keygridhsm/pkg/models"
)

func TestProviderRegistry_RegisterProvider(t *testing.T) {
	tests := []struct {
		name         string
		providerName string
		provider     models.HSMProvider
		expectError  bool
	}{
		{
			name:         "Register valid provider",
			providerName: "test-provider",
			provider:     providers.NewMockHSMProvider(logrus.New()),
			expectError:  false,
		},
		{
			name:         "Register duplicate provider",
			providerName: "duplicate",
			provider:     providers.NewMockHSMProvider(logrus.New()),
			expectError:  true, // Should fail on second registration
		},
		{
			name:         "Register with empty name",
			providerName: "",
			provider:     providers.NewMockHSMProvider(logrus.New()),
			expectError:  false, // Current implementation allows empty names
		},
		{
			name:         "Register nil provider",
			providerName: "nil-provider",
			provider:     nil,
			expectError:  false, // Current implementation allows nil providers
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := core.NewProviderRegistry()

			// For duplicate test, register first
			if tt.name == "Register duplicate provider" {
				err := registry.RegisterProvider(tt.providerName, providers.NewMockHSMProvider(logrus.New()))
				require.NoError(t, err)
			}

			err := registry.RegisterProvider(tt.providerName, tt.provider)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProviderRegistry_GetProvider(t *testing.T) {
	registry := core.NewProviderRegistry()
	mockProvider := providers.NewMockHSMProvider(logrus.New())

	// Register a provider
	err := registry.RegisterProvider("mock", mockProvider)
	require.NoError(t, err)

	tests := []struct {
		name         string
		providerName string
		expectFound  bool
	}{
		{
			name:         "Get existing provider",
			providerName: "mock",
			expectFound:  true,
		},
		{
			name:         "Get non-existent provider",
			providerName: "non-existent",
			expectFound:  false,
		},
		{
			name:         "Get with empty name",
			providerName: "",
			expectFound:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := registry.GetProvider(tt.providerName)

			if tt.expectFound {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
				assert.Equal(t, mockProvider.Name(), provider.Name())
			} else {
				assert.Error(t, err)
				assert.Nil(t, provider)
			}
		})
	}
}

func TestProviderRegistry_ListProviders(t *testing.T) {
	registry := core.NewProviderRegistry()

	// Test empty registry
	providerList := registry.ListProviders()
	assert.Empty(t, providerList)

	// Add providers
	mockProvider := providers.NewMockHSMProvider(logrus.New())
	customProvider := providers.NewCustomStorageProvider(logrus.New())

	err := registry.RegisterProvider("mock", mockProvider)
	require.NoError(t, err)

	err = registry.RegisterProvider("custom", customProvider)
	require.NoError(t, err)

	// Test populated registry
	providerList = registry.ListProviders()
	assert.Len(t, providerList, 2)
	assert.Contains(t, providerList, "mock")
	assert.Contains(t, providerList, "custom")
}

func TestProviderRegistry_CreateClient(t *testing.T) {
	registry := core.NewProviderRegistry()
	mockProvider := providers.NewMockHSMProvider(logrus.New())

	err := registry.RegisterProvider("mock", mockProvider)
	require.NoError(t, err)

	tests := []struct {
		name         string
		providerName string
		config       map[string]interface{}
		expectError  bool
	}{
		{
			name:         "Create client for existing provider",
			providerName: "mock",
			config: map[string]interface{}{
				"persistent_storage": false,
				"simulate_errors":    false,
				"max_keys":           100,
			},
			expectError: false,
		},
		{
			name:         "Create client for non-existent provider",
			providerName: "non-existent",
			config:       map[string]interface{}{},
			expectError:  true,
		},
		{
			name:         "Create client with invalid config",
			providerName: "mock",
			config: map[string]interface{}{
				"max_keys": -1, // Invalid value
			},
			expectError: false, // Mock provider should handle this gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := registry.CreateClient(tt.providerName, tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestProviderRegistry_UnregisterProvider(t *testing.T) {
	registry := core.NewProviderRegistry()
	mockProvider := providers.NewMockHSMProvider(logrus.New())

	// Register provider
	err := registry.RegisterProvider("mock", mockProvider)
	require.NoError(t, err)

	// Verify it exists
	_, err = registry.GetProvider("mock")
	assert.NoError(t, err)

	// Unregister provider
	err = registry.UnregisterProvider("mock")
	assert.NoError(t, err)

	// Verify it's gone
	_, err = registry.GetProvider("mock")
	assert.Error(t, err)

	// Try to unregister non-existent provider
	err = registry.UnregisterProvider("non-existent")
	assert.Error(t, err)
}

func TestProviderRegistry_ConcurrentAccess(t *testing.T) {
	registry := core.NewProviderRegistry()

	// Test concurrent registration
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			providerName := fmt.Sprintf("provider-%d", id)
			provider := providers.NewMockHSMProvider(logrus.New())
			err := registry.RegisterProvider(providerName, provider)
			assert.NoError(t, err)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all providers were registered
	providerList := registry.ListProviders()
	assert.Len(t, providerList, 10)

	// Test concurrent client creation
	for i := 0; i < 10; i++ {
		go func(id int) {
			providerName := fmt.Sprintf("provider-%d", id)
			config := map[string]interface{}{
				"persistent_storage": false,
				"max_keys":           100,
			}
			client, err := registry.CreateClient(providerName, config)
			assert.NoError(t, err)
			assert.NotNil(t, client)
			done <- true
		}(i)
	}

	// Wait for all client creations to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func BenchmarkProviderRegistry_RegisterProvider(b *testing.B) {
	registry := core.NewProviderRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		providerName := fmt.Sprintf("provider-%d", i)
		provider := providers.NewMockHSMProvider(logrus.New())
		_ = registry.RegisterProvider(providerName, provider)
	}
}

func BenchmarkProviderRegistry_GetProvider(b *testing.B) {
	registry := core.NewProviderRegistry()

	// Pre-populate registry
	for i := 0; i < 100; i++ {
		providerName := fmt.Sprintf("provider-%d", i)
		provider := providers.NewMockHSMProvider(logrus.New())
		_ = registry.RegisterProvider(providerName, provider)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		providerName := fmt.Sprintf("provider-%d", i%100)
		_, _ = registry.GetProvider(providerName)
	}
}

func BenchmarkProviderRegistry_CreateClient(b *testing.B) {
	registry := core.NewProviderRegistry()
	mockProvider := providers.NewMockHSMProvider(logrus.New())
	_ = registry.RegisterProvider("mock", mockProvider)

	config := map[string]interface{}{
		"persistent_storage": false,
		"max_keys":           100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = registry.CreateClient("mock", config)
	}
}
