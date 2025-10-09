package models

import (
	"fmt"
)

// HSMError represents an HSM-specific error
type HSMError struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Provider  string                 `json:"provider,omitempty"`
	Operation string                 `json:"operation,omitempty"`
	Cause     error                  `json:"-"`
}

func (e *HSMError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("HSM error [%s]: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("HSM error [%s]: %s", e.Code, e.Message)
}

func (e *HSMError) Unwrap() error {
	return e.Cause
}

// Error codes
const (
	// General errors
	ErrCodeUnknown             = "UNKNOWN"
	ErrCodeInvalidInput        = "INVALID_INPUT"
	ErrCodeInvalidConfig       = "INVALID_CONFIG"
	ErrCodeProviderNotFound    = "PROVIDER_NOT_FOUND"
	ErrCodeProviderUnavailable = "PROVIDER_UNAVAILABLE"

	// Authentication and authorization errors
	ErrCodeAuthenticationFailed = "AUTHENTICATION_FAILED"
	ErrCodeAuthorizationFailed  = "AUTHORIZATION_FAILED"
	ErrCodeInvalidCredentials   = "INVALID_CREDENTIALS"
	ErrCodeTokenExpired         = "TOKEN_EXPIRED"

	// Key management errors
	ErrCodeKeyNotFound           = "KEY_NOT_FOUND"
	ErrCodeKeyAlreadyExists      = "KEY_ALREADY_EXISTS"
	ErrCodeKeyGenerationFailed   = "KEY_GENERATION_FAILED"
	ErrCodeKeyImportFailed       = "KEY_IMPORT_FAILED"
	ErrCodeKeyDeletionFailed     = "KEY_DELETION_FAILED"
	ErrCodeKeyActivationFailed   = "KEY_ACTIVATION_FAILED"
	ErrCodeKeyDeactivationFailed = "KEY_DEACTIVATION_FAILED"
	ErrCodeKeyInactive           = "KEY_INACTIVE"
	ErrCodeKeyExpired            = "KEY_EXPIRED"
	ErrCodeKeyCompromised        = "KEY_COMPROMISED"
	ErrCodeInvalidKeySpec        = "INVALID_KEY_SPEC"
	ErrCodeInvalidKeyUsage       = "INVALID_KEY_USAGE"

	// Cryptographic operation errors
	ErrCodeSigningFailed      = "SIGNING_FAILED"
	ErrCodeVerificationFailed = "VERIFICATION_FAILED"
	ErrCodeEncryptionFailed   = "ENCRYPTION_FAILED"
	ErrCodeDecryptionFailed   = "DECRYPTION_FAILED"
	ErrCodeKeyWrapFailed      = "KEY_WRAP_FAILED"
	ErrCodeKeyUnwrapFailed    = "KEY_UNWRAP_FAILED"
	ErrCodeInvalidSignature   = "INVALID_SIGNATURE"
	ErrCodeInvalidAlgorithm   = "INVALID_ALGORITHM"

	// Network and connectivity errors
	ErrCodeNetworkError       = "NETWORK_ERROR"
	ErrCodeTimeoutError       = "TIMEOUT_ERROR"
	ErrCodeConnectionFailed   = "CONNECTION_FAILED"
	ErrCodeServiceUnavailable = "SERVICE_UNAVAILABLE"

	// Rate limiting and quota errors
	ErrCodeRateLimitExceeded = "RATE_LIMIT_EXCEEDED"
	ErrCodeQuotaExceeded     = "QUOTA_EXCEEDED"
	ErrCodeTooManyRequests   = "TOO_MANY_REQUESTS"

	// Provider-specific errors
	ErrCodeAzureKeyVaultError = "AZURE_KEYVAULT_ERROR"
	ErrCodeCustomStorageError = "CUSTOM_STORAGE_ERROR"
	ErrCodeMockHSMError       = "MOCK_HSM_ERROR"
)

// Predefined errors
var (
	ErrProviderNotRegistered = &HSMError{Code: ErrCodeProviderNotFound, Message: "HSM provider not registered"}
	ErrInvalidConfiguration  = &HSMError{Code: ErrCodeInvalidConfig, Message: "Invalid provider configuration"}
	ErrKeyNotFound           = &HSMError{Code: ErrCodeKeyNotFound, Message: "Key not found"}
	ErrKeyAlreadyExists      = &HSMError{Code: ErrCodeKeyAlreadyExists, Message: "Key already exists"}
	ErrAuthenticationFailed  = &HSMError{Code: ErrCodeAuthenticationFailed, Message: "Authentication failed"}
	ErrAuthorizationFailed   = &HSMError{Code: ErrCodeAuthorizationFailed, Message: "Authorization failed"}
	ErrServiceUnavailable    = &HSMError{Code: ErrCodeServiceUnavailable, Message: "HSM service unavailable"}
	ErrInvalidKeySpec        = &HSMError{Code: ErrCodeInvalidKeySpec, Message: "Invalid key specification"}
	ErrSigningFailed         = &HSMError{Code: ErrCodeSigningFailed, Message: "Signing operation failed"}
	ErrEncryptionFailed      = &HSMError{Code: ErrCodeEncryptionFailed, Message: "Encryption operation failed"}
	ErrDecryptionFailed      = &HSMError{Code: ErrCodeDecryptionFailed, Message: "Decryption operation failed"}
	ErrInvalidSignature      = &HSMError{Code: ErrCodeInvalidSignature, Message: "Invalid signature"}
)

// NewHSMError creates a new HSM error
func NewHSMError(code, message string) *HSMError {
	return &HSMError{
		Code:    code,
		Message: message,
	}
}

// NewHSMErrorWithCause creates a new HSM error with a cause
func NewHSMErrorWithCause(code, message string, cause error) *HSMError {
	return &HSMError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// NewHSMErrorWithDetails creates a new HSM error with details
func NewHSMErrorWithDetails(code, message string, details map[string]interface{}) *HSMError {
	return &HSMError{
		Code:    code,
		Message: message,
		Details: details,
	}
}

// WithProvider adds provider information to the error
func (e *HSMError) WithProvider(provider string) *HSMError {
	e.Provider = provider
	return e
}

// WithOperation adds operation information to the error
func (e *HSMError) WithOperation(operation string) *HSMError {
	e.Operation = operation
	return e
}

// WithDetails adds details to the error
func (e *HSMError) WithDetails(details map[string]interface{}) *HSMError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	for k, v := range details {
		e.Details[k] = v
	}
	return e
}

// WithCause adds a cause to the error
func (e *HSMError) WithCause(cause error) *HSMError {
	e.Cause = cause
	return e
}

// IsHSMError checks if an error is an HSMError
func IsHSMError(err error) bool {
	_, ok := err.(*HSMError)
	return ok
}

// AsHSMError returns the underlying HSMError if possible
func AsHSMError(err error) (*HSMError, bool) {
	hsmErr, ok := err.(*HSMError)
	return hsmErr, ok
}

// HasErrorCode checks if an error has a specific error code
func HasErrorCode(err error, code string) bool {
	if hsmErr, ok := AsHSMError(err); ok {
		return hsmErr.Code == code
	}
	return false
}

// IsTemporaryError checks if an error is temporary and operations can be retried
func IsTemporaryError(err error) bool {
	if hsmErr, ok := AsHSMError(err); ok {
		switch hsmErr.Code {
		case ErrCodeNetworkError, ErrCodeTimeoutError, ErrCodeConnectionFailed,
			ErrCodeServiceUnavailable, ErrCodeRateLimitExceeded, ErrCodeTooManyRequests:
			return true
		}
	}
	return false
}

// IsAuthenticationError checks if an error is related to authentication
func IsAuthenticationError(err error) bool {
	if hsmErr, ok := AsHSMError(err); ok {
		switch hsmErr.Code {
		case ErrCodeAuthenticationFailed, ErrCodeAuthorizationFailed,
			ErrCodeInvalidCredentials, ErrCodeTokenExpired:
			return true
		}
	}
	return false
}

// IsKeyError checks if an error is related to key operations
func IsKeyError(err error) bool {
	if hsmErr, ok := AsHSMError(err); ok {
		switch hsmErr.Code {
		case ErrCodeKeyNotFound, ErrCodeKeyAlreadyExists, ErrCodeKeyGenerationFailed,
			ErrCodeKeyImportFailed, ErrCodeKeyDeletionFailed, ErrCodeKeyInactive,
			ErrCodeKeyExpired, ErrCodeKeyCompromised, ErrCodeInvalidKeySpec,
			ErrCodeInvalidKeyUsage:
			return true
		}
	}
	return false
}

// IsCryptographicError checks if an error is related to cryptographic operations
func IsCryptographicError(err error) bool {
	if hsmErr, ok := AsHSMError(err); ok {
		switch hsmErr.Code {
		case ErrCodeSigningFailed, ErrCodeVerificationFailed, ErrCodeEncryptionFailed,
			ErrCodeDecryptionFailed, ErrCodeKeyWrapFailed, ErrCodeKeyUnwrapFailed,
			ErrCodeInvalidSignature, ErrCodeInvalidAlgorithm:
			return true
		}
	}
	return false
}
