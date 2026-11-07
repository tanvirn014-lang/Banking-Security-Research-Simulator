package crypto

import (
	"crypto/mlkem"
	"encoding/binary"

	"banksec-lab/internal/apperr"
)

// The "pqc" profile's Encrypt/Decrypt use ML-KEM-768 (NIST FIPS 203, via
// the Go 1.27.3 standard library's crypto/mlkem -- confirmed present via
// `go doc crypto/mlkem`; no third-party dependency needed for this half
// of the PQC profile) as a KEM-then-AEAD construction: encapsulate a
// shared secret against the recipient's public key, then encrypt the
// payload under that secret using the same AES-GCM implementation as the
// standard profile (internal/crypto/standard.go).
//
// The shared secret is used directly as the AES-256-GCM key, with no
// separate derivation step (e.g. HKDF): mlkem.SharedKeySize is 32 bytes,
// already a uniformly random value fit for direct use as a single AES-256
// key. HKDF would only earn its complexity if multiple distinct keys
// needed deriving from one secret, which is not the case here.
//
// Wire framing for the combined ciphertext blob (Decrypt receives this as
// one []byte, so the KEM ciphertext and the AEAD ciphertext must be
// packed together):
//
//	[4-byte BE length of the ML-KEM ciphertext][ML-KEM ciphertext][AES-GCM ciphertext]
//
// Encrypt's key parameter is the recipient's ML-KEM-768 encapsulation
// (public) key bytes; Decrypt's key parameter is the recipient's
// decapsulation key seed (DecapsulationKey768.Bytes()).

func pqcKEMEncrypt(pubKeyBytes, plaintext []byte) ([]byte, error) {
	ek, err := mlkem.NewEncapsulationKey768(pubKeyBytes)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeValidation, "invalid ML-KEM-768 encapsulation key", err)
	}
	sharedSecret, kemCiphertext := ek.Encapsulate()

	aeadCiphertext, err := standardEncrypt(sharedSecret, plaintext)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "AES-GCM seal under ML-KEM shared secret", err)
	}

	out := make([]byte, 4+len(kemCiphertext)+len(aeadCiphertext))
	binary.BigEndian.PutUint32(out[:4], uint32(len(kemCiphertext)))
	copy(out[4:], kemCiphertext)
	copy(out[4+len(kemCiphertext):], aeadCiphertext)
	return out, nil
}

func pqcKEMDecrypt(privKeySeed, blob []byte) ([]byte, error) {
	if len(blob) < 4 {
		return nil, apperr.New(apperr.CodeValidation, "pqc ciphertext too short to contain a KEM-ciphertext length prefix")
	}
	kemLen := binary.BigEndian.Uint32(blob[:4])
	if int(kemLen) > len(blob)-4 {
		return nil, apperr.New(apperr.CodeValidation, "pqc ciphertext: invalid KEM ciphertext length")
	}
	kemCiphertext := blob[4 : 4+kemLen]
	aeadCiphertext := blob[4+kemLen:]

	dk, err := mlkem.NewDecapsulationKey768(privKeySeed)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeValidation, "invalid ML-KEM-768 decapsulation key seed", err)
	}
	sharedSecret, err := dk.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeConflict, "ML-KEM-768 decapsulation failed", err)
	}

	return standardDecrypt(sharedSecret, aeadCiphertext)
}
