// Package crypto implements BankSec Lab's cryptographic profiles. Only
// the "standard" profile (real, maintained Go stdlib implementations) is
// implemented in this task; "weak-educational" (Task 18), "pqc" (Tasks
// 19-20) arrive later. No production cryptographic primitive is ever
// implemented from scratch here -- see CRYPTOGRAPHY.md's binding rule.
package crypto

import (
	"banksec-lab/internal/apperr"
	"banksec-lab/internal/domain"
)

// Engine provides the cryptographic operations BankSec Lab needs, each
// dispatched by the active CryptoProfileName.
type Engine interface {
	Encrypt(profile domain.CryptoProfileName, key, plaintext []byte) ([]byte, error)
	Decrypt(profile domain.CryptoProfileName, key, ciphertext []byte) ([]byte, error)
	Sign(profile domain.CryptoProfileName, key, msg []byte) ([]byte, error)
	Verify(profile domain.CryptoProfileName, pubkey, msg, sig []byte) (bool, error)
	MAC(profile domain.CryptoProfileName, key, msg []byte) ([]byte, error)
}

// ErrProfileNotImplemented is returned by every Engine method for a
// profile name this build does not (yet) implement.
var ErrProfileNotImplemented = apperr.New(apperr.CodeValidation, "crypto profile not implemented")

type engine struct{}

// NewEngine constructs the default Engine.
func NewEngine() Engine {
	return engine{}
}

func (engine) Encrypt(profile domain.CryptoProfileName, key, plaintext []byte) ([]byte, error) {
	switch profile {
	case "standard":
		return standardEncrypt(key, plaintext)
	case "weak-educational":
		return weakECBEncrypt(key, plaintext)
	case "pqc":
		return pqcKEMEncrypt(key, plaintext)
	default:
		return nil, ErrProfileNotImplemented
	}
}

func (engine) Decrypt(profile domain.CryptoProfileName, key, ciphertext []byte) ([]byte, error) {
	switch profile {
	case "standard":
		return standardDecrypt(key, ciphertext)
	case "weak-educational":
		return weakECBDecrypt(key, ciphertext)
	case "pqc":
		return pqcKEMDecrypt(key, ciphertext)
	default:
		return nil, ErrProfileNotImplemented
	}
}

func (engine) Sign(profile domain.CryptoProfileName, key, msg []byte) ([]byte, error) {
	switch profile {
	case "standard":
		return standardSign(key, msg)
	case "weak-educational":
		return toyRSASign(msg), nil
	case "pqc":
		return pqcDSASign(key, msg)
	default:
		return nil, ErrProfileNotImplemented
	}
}

func (engine) Verify(profile domain.CryptoProfileName, pubkey, msg, sig []byte) (bool, error) {
	switch profile {
	case "standard":
		return standardVerify(pubkey, msg, sig)
	case "weak-educational":
		return toyRSAVerify(msg, sig), nil
	case "pqc":
		return pqcDSAVerify(pubkey, msg, sig)
	default:
		return false, ErrProfileNotImplemented
	}
}

func (engine) MAC(profile domain.CryptoProfileName, key, msg []byte) ([]byte, error) {
	switch profile {
	case "standard":
		return standardMAC(key, msg), nil
	case "weak-educational":
		return weakMAC(key, msg), nil
	default:
		return nil, ErrProfileNotImplemented
	}
}
