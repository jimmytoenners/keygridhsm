package models

import (
	"context"
	"crypto"
	"time"
)

// KeyType represents the type of cryptographic key
type KeyType string

const (
	KeyTypeRSA     KeyType = "RSA"
	KeyTypeECDSA   KeyType = "ECDSA"
	KeyTypeEd25519 KeyType = "Ed25519"
	KeyTypeAES     KeyType = "AES"
)

// KeyUsage represents the intended usage of a key
type KeyUsage string

const (
	KeyUsageSign    KeyUsage = "sign"
	KeyUsageVerify  KeyUsage = "verify"
	KeyUsageEncrypt KeyUsage = "encrypt"
	KeyUsageDecrypt KeyUsage = "decrypt"
	KeyUsageWrap    KeyUsage = "wrap"
	KeyUsageUnwrap  KeyUsage = "unwrap"
	KeyUsageDerive  KeyUsage = "derive"
)

// KeyState represents the state of a key in the HSM
type KeyState string

const (
	KeyStateActive     KeyState = "active"
	KeyStateInactive   KeyState = "inactive"
	KeyStateCompromised KeyState = "compromised"
	KeyStateDestroyed  KeyState = "destroyed"
)

// KeySpec defines the specification for generating keys
type KeySpec struct {
	KeyType       KeyType    `json:"key_type"`
	KeySize       int        `json:"key_size"`
	Algorithm     string     `json:"algorithm"`
	Usage         []KeyUsage `json:"usage"`
	Extractable   bool       `json:"extractable"`
	ExportPolicy  string     `json:"export_policy,omitempty"`
	KeyExpiration *time.Time `json:"key_expiration,omitempty"`
}

// KeyHandle represents a reference to a key stored in the HSM
type KeyHandle struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	KeyType       KeyType    `json:"key_type"`
	KeySize       int        `json:"key_size"`
	Algorithm     string     `json:"algorithm"`
	Usage         []KeyUsage `json:"usage"`
	State         KeyState   `json:"state"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Label         string     `json:"label,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	ProviderID    string     `json:"provider_id"`
	ProviderKeyID string     `json:"provider_key_id"`
}

// SigningRequest represents a request to sign data
type SigningRequest struct {
	KeyHandle     string            `json:"key_handle"`
	Data          []byte            `json:"data"`
	Algorithm     string            `json:"algorithm,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// SigningResponse represents the response from a signing operation
type SigningResponse struct {
	Signature []byte            `json:"signature"`
	Algorithm string            `json:"algorithm"`
	KeyID     string            `json:"key_id"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// EncryptionRequest represents a request to encrypt data
type EncryptionRequest struct {
	KeyHandle     string            `json:"key_handle"`
	Plaintext     []byte            `json:"plaintext"`
	Algorithm     string            `json:"algorithm,omitempty"`
	AAD           []byte            `json:"aad,omitempty"` // Additional Authenticated Data for AEAD
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// EncryptionResponse represents the response from an encryption operation
type EncryptionResponse struct {
	Ciphertext []byte            `json:"ciphertext"`
	IV         []byte            `json:"iv,omitempty"`
	Tag        []byte            `json:"tag,omitempty"` // Authentication tag for AEAD
	Algorithm  string            `json:"algorithm"`
	KeyID      string            `json:"key_id"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// DecryptionRequest represents a request to decrypt data
type DecryptionRequest struct {
	KeyHandle     string            `json:"key_handle"`
	Ciphertext    []byte            `json:"ciphertext"`
	IV            []byte            `json:"iv,omitempty"`
	Tag           []byte            `json:"tag,omitempty"` // Authentication tag for AEAD
	AAD           []byte            `json:"aad,omitempty"` // Additional Authenticated Data for AEAD
	Algorithm     string            `json:"algorithm,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// DecryptionResponse represents the response from a decryption operation
type DecryptionResponse struct {
	Plaintext []byte            `json:"plaintext"`
	Algorithm string            `json:"algorithm"`
	KeyID     string            `json:"key_id"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// KeyWrapRequest represents a request to wrap a key
type KeyWrapRequest struct {
	KEKHandle     string            `json:"kek_handle"` // Key Encryption Key handle
	KeyToWrap     []byte            `json:"key_to_wrap"`
	Algorithm     string            `json:"algorithm,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// KeyWrapResponse represents the response from a key wrap operation
type KeyWrapResponse struct {
	WrappedKey []byte            `json:"wrapped_key"`
	Algorithm  string            `json:"algorithm"`
	KEKId      string            `json:"kek_id"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// KeyUnwrapRequest represents a request to unwrap a key
type KeyUnwrapRequest struct {
	KEKHandle     string            `json:"kek_handle"` // Key Encryption Key handle
	WrappedKey    []byte            `json:"wrapped_key"`
	Algorithm     string            `json:"algorithm,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// KeyUnwrapResponse represents the response from a key unwrap operation
type KeyUnwrapResponse struct {
	UnwrappedKey []byte            `json:"unwrapped_key"`
	Algorithm    string            `json:"algorithm"`
	KEKId        string            `json:"kek_id"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// HealthStatus represents the health status of an HSM provider
type HealthStatus struct {
	Status      string            `json:"status"`
	Provider    string            `json:"provider"`
	LastCheck   time.Time         `json:"last_check"`
	Details     map[string]string `json:"details,omitempty"`
	Error       string            `json:"error,omitempty"`
	ResponseTime time.Duration    `json:"response_time"`
}

// HSMOperationResult represents the result of any HSM operation
type HSMOperationResult struct {
	Success      bool              `json:"success"`
	OperationID  string            `json:"operation_id"`
	Provider     string            `json:"provider"`
	Duration     time.Duration     `json:"duration"`
	Error        string            `json:"error,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// AuditEvent represents an audit event for HSM operations
type AuditEvent struct {
	ID          string            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	Operation   string            `json:"operation"`
	Provider    string            `json:"provider"`
	KeyID       string            `json:"key_id,omitempty"`
	Success     bool              `json:"success"`
	Error       string            `json:"error,omitempty"`
	UserID      string            `json:"user_id,omitempty"`
	ClientIP    string            `json:"client_ip,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	Duration    time.Duration     `json:"duration"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// HSMClient defines the interface for interacting with an HSM
type HSMClient interface {
	// Health and Status
	Health(ctx context.Context) (*HealthStatus, error)
	GetProviderInfo(ctx context.Context) (map[string]interface{}, error)
	
	// Key Management
	GenerateKey(ctx context.Context, spec KeySpec, name string) (*KeyHandle, error)
	ImportKey(ctx context.Context, keyData []byte, spec KeySpec, name string) (*KeyHandle, error)
	GetKey(ctx context.Context, keyHandle string) (*KeyHandle, error)
	ListKeys(ctx context.Context) ([]*KeyHandle, error)
	DeleteKey(ctx context.Context, keyHandle string) error
	
	// Key State Management
	ActivateKey(ctx context.Context, keyHandle string) error
	DeactivateKey(ctx context.Context, keyHandle string) error
	SetKeyExpiration(ctx context.Context, keyHandle string, expiration time.Time) error
	
	// Cryptographic Operations
	GetPublicKey(ctx context.Context, keyHandle string) (crypto.PublicKey, error)
	Sign(ctx context.Context, request SigningRequest) (*SigningResponse, error)
	Verify(ctx context.Context, keyHandle string, data, signature []byte, algorithm string) (bool, error)
	Encrypt(ctx context.Context, request EncryptionRequest) (*EncryptionResponse, error)
	Decrypt(ctx context.Context, request DecryptionRequest) (*DecryptionResponse, error)
	
	// Key Wrapping
	WrapKey(ctx context.Context, request KeyWrapRequest) (*KeyWrapResponse, error)
	UnwrapKey(ctx context.Context, request KeyUnwrapRequest) (*KeyUnwrapResponse, error)
	
	// Connection Management
	Close() error
}

// HSMProvider defines the interface for HSM provider implementations
type HSMProvider interface {
	// Provider Information
	Name() string
	Version() string
	Capabilities() []string
	
	// Client Creation
	CreateClient(config map[string]interface{}) (HSMClient, error)
	ValidateConfig(config map[string]interface{}) error
	
	// Provider-specific operations
	Initialize(config map[string]interface{}) error
	Shutdown() error
}