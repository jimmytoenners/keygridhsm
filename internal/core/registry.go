package core

import (
	"context"
	"fmt"
	"sync"

	"github.com/jimmy/keygridhsm/pkg/models"
)

// ProviderRegistry manages the registration and retrieval of HSM providers
type ProviderRegistry struct {
	providers map[string]models.HSMProvider
	mutex     sync.RWMutex
}

// NewProviderRegistry creates a new provider registry
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]models.HSMProvider),
	}
}

// RegisterProvider registers a new HSM provider
func (r *ProviderRegistry) RegisterProvider(name string, provider models.HSMProvider) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("provider %s is already registered", name)
	}

	r.providers[name] = provider
	return nil
}

// GetProvider retrieves a registered HSM provider by name
func (r *ProviderRegistry) GetProvider(name string) (models.HSMProvider, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	provider, exists := r.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s is not registered", name)
	}

	return provider, nil
}

// ListProviders returns a list of all registered provider names
func (r *ProviderRegistry) ListProviders() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}

	return names
}

// UnregisterProvider removes a provider from the registry
func (r *ProviderRegistry) UnregisterProvider(name string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.providers[name]; !exists {
		return fmt.Errorf("provider %s is not registered", name)
	}

	delete(r.providers, name)
	return nil
}

// GetProviderInfo returns information about a specific provider
func (r *ProviderRegistry) GetProviderInfo(name string) (map[string]interface{}, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	provider, exists := r.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s is not registered", name)
	}

	info := map[string]interface{}{
		"name":         provider.Name(),
		"version":      provider.Version(),
		"capabilities": provider.Capabilities(),
	}

	return info, nil
}

// GetAllProvidersInfo returns information about all registered providers
func (r *ProviderRegistry) GetAllProvidersInfo() map[string]interface{} {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	info := make(map[string]interface{})
	for name, provider := range r.providers {
		info[name] = map[string]interface{}{
			"name":         provider.Name(),
			"version":      provider.Version(),
			"capabilities": provider.Capabilities(),
		}
	}

	return info
}

// ValidateProviderConfig validates the configuration for a specific provider
func (r *ProviderRegistry) ValidateProviderConfig(name string, config map[string]interface{}) error {
	provider, err := r.GetProvider(name)
	if err != nil {
		return err
	}

	return provider.ValidateConfig(config)
}

// CreateClient creates a new HSM client for the specified provider
func (r *ProviderRegistry) CreateClient(name string, config map[string]interface{}) (models.HSMClient, error) {
	provider, err := r.GetProvider(name)
	if err != nil {
		return nil, err
	}

	if err := provider.ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration for provider %s: %w", name, err)
	}

	return provider.CreateClient(config)
}

// HealthCheck performs a basic health check on a provider
func (r *ProviderRegistry) HealthCheck(ctx context.Context, name string) (bool, error) {
	_, err := r.GetProvider(name)
	if err != nil {
		return false, err
	}

	// For now, just check if provider exists and can be retrieved
	// In a more complete implementation, this could create a temporary client and test it
	return true, nil
}

// Default global registry instance
var globalRegistry *ProviderRegistry
var registryOnce sync.Once

// GetGlobalRegistry returns the global provider registry instance
func GetGlobalRegistry() *ProviderRegistry {
	registryOnce.Do(func() {
		globalRegistry = NewProviderRegistry()
	})
	return globalRegistry
}

// RegisterGlobalProvider registers a provider with the global registry
func RegisterGlobalProvider(name string, provider models.HSMProvider) error {
	return GetGlobalRegistry().RegisterProvider(name, provider)
}

// GetGlobalProvider retrieves a provider from the global registry
func GetGlobalProvider(name string) (models.HSMProvider, error) {
	return GetGlobalRegistry().GetProvider(name)
}

// CreateGlobalClient creates a client using the global registry
func CreateGlobalClient(name string, config map[string]interface{}) (models.HSMClient, error) {
	return GetGlobalRegistry().CreateClient(name, config)
}
