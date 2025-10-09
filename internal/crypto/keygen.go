// Package crypto provides cryptographic utilities shared across the KeyGrid HSM system,
// including key generation, signing, and verification operations.
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/jimmy/keygridhsm/pkg/models"
)

// GenerateKeyPair generates a cryptographic key pair based on the provided key specification.
// This function is used across multiple HSM providers to avoid code duplication.
func GenerateKeyPair(spec models.KeySpec) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch spec.KeyType {
	case models.KeyTypeRSA:
		privateKey, err := rsa.GenerateKey(rand.Reader, spec.KeySize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		return privateKey, &privateKey.PublicKey, nil

	case models.KeyTypeECDSA:
		var curve elliptic.Curve
		switch spec.KeySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, nil, fmt.Errorf("unsupported ECDSA key size: %d", spec.KeySize)
		}

		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		return privateKey, &privateKey.PublicKey, nil

	case models.KeyTypeEd25519:
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
		}
		return privateKey, publicKey, nil

	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", spec.KeyType)
	}
}

// ValidateKeySpec validates the key specification parameters.
func ValidateKeySpec(spec models.KeySpec) error {
	switch spec.KeyType {
	case models.KeyTypeRSA:
		if spec.KeySize < 2048 {
			return fmt.Errorf("RSA key size must be at least 2048 bits, got %d", spec.KeySize)
		}
		if spec.KeySize > 8192 {
			return fmt.Errorf("RSA key size must be at most 8192 bits, got %d", spec.KeySize)
		}
	case models.KeyTypeECDSA:
		if spec.KeySize != 256 && spec.KeySize != 384 && spec.KeySize != 521 {
			return fmt.Errorf("ECDSA key size must be 256, 384, or 521, got %d", spec.KeySize)
		}
	case models.KeyTypeEd25519:
		// Ed25519 has a fixed key size, ignore the KeySize field
		if spec.KeySize != 0 && spec.KeySize != 256 {
			return fmt.Errorf("Ed25519 key size should be 0 or 256, got %d", spec.KeySize)
		}
	default:
		return fmt.Errorf("unsupported key type: %s", spec.KeyType)
	}
	return nil
}

// GetKeySize returns the actual key size for the generated key.
func GetKeySize(key crypto.PrivateKey) (int, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k.N.BitLen(), nil
	case *ecdsa.PrivateKey:
		return k.Curve.Params().BitSize, nil
	case ed25519.PrivateKey:
		return 256, nil
	default:
		return 0, fmt.Errorf("unsupported key type: %T", key)
	}
}
