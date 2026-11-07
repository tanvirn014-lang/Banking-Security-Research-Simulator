package crypto

import (
	"crypto/aes"
	"crypto/sha256"
	"math/big"

	"banksec-lab/internal/apperr"
)

// The "weak-educational" profile. Every construct here is DELIBERATELY
// BROKEN, per CRYPTOGRAPHY.md §1.1 -- these are not bugs, they are
// labeled, bounded toy demonstrations for the Milestone 8 cryptographic
// attack scenario. Never use any of this for anything but that
// demonstration; none of it provides real security.

// --- Encrypt/Decrypt: AES in ECB mode -------------------------------
//
// Each 16-byte block is encrypted independently with the raw AES block
// cipher -- no IV, no chaining, no authentication. Identical plaintext
// blocks produce identical ciphertext blocks (pattern leakage), and a
// modified ciphertext decrypts "successfully" into garbage instead of
// being rejected (no integrity check at all). PKCS#7 padding is used only
// so Encrypt/Decrypt round-trip for arbitrary-length input; it has
// nothing to do with the demonstrated weakness.

func weakECBEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeValidation, "invalid AES key", err)
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	return ciphertext, nil
}

func weakECBDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeValidation, "invalid AES key", err)
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, apperr.New(apperr.CodeValidation, "ciphertext is not a whole number of AES blocks")
	}
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(plaintext[i:i+aes.BlockSize], ciphertext[i:i+aes.BlockSize])
	}
	return pkcs7Unpad(plaintext)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, apperr.New(apperr.CodeValidation, "cannot unpad empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > len(data) {
		return nil, apperr.New(apperr.CodeValidation, "invalid PKCS#7 padding")
	}
	return data[:len(data)-padLen], nil
}

// --- Sign/Verify: toy RSA --------------------------------------------
//
// A single, fixed, globally-known 20-bit modulus from two small fixed
// primes -- itself part of the demonstrated weakness (no per-identity
// key material at all). The key/pubkey parameters passed to Sign/Verify
// are accepted for Engine interface conformance but unused: there is
// only ever this one toy key pair. Signatures are textbook RSA (digest
// reduced mod n, no padding scheme) over a SHA-256 digest -- not a real
// signature scheme, just enough structure to sign and verify.
var (
	toyRSAP = big.NewInt(997)
	toyRSAQ = big.NewInt(1009)
	toyRSAN = new(big.Int).Mul(toyRSAP, toyRSAQ)
	toyRSAE = big.NewInt(17)
	toyRSAD = computeToyRSAD()
)

// ToyRSAPublicKey returns the weak-educational profile's single, fixed,
// globally-known toy RSA public key (modulus and public exponent) --
// there is no per-identity key material at all, by design (see this
// file's own doc comment). Exported so an attack scenario can obtain the
// public key the way a real attacker against real RSA would (e.g. from
// a certificate), then genuinely factor it, rather than the attack
// needing to already know the private factors in advance.
func ToyRSAPublicKey() (n, e *big.Int) {
	return new(big.Int).Set(toyRSAN), new(big.Int).Set(toyRSAE)
}

func computeToyRSAD() *big.Int {
	one := big.NewInt(1)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(toyRSAP, one),
		new(big.Int).Sub(toyRSAQ, one),
	)
	d := new(big.Int).ModInverse(toyRSAE, phi)
	if d == nil {
		panic("toy RSA: fixed exponent is not invertible mod phi(n) -- fix the fixed primes/exponent")
	}
	return d
}

func toyRSADigest(msg []byte) *big.Int {
	h := sha256.Sum256(msg)
	digest := new(big.Int).SetBytes(h[:])
	return digest.Mod(digest, toyRSAN)
}

func toyRSASign(msg []byte) []byte {
	sig := new(big.Int).Exp(toyRSADigest(msg), toyRSAD, toyRSAN)
	return sig.Bytes()
}

func toyRSAVerify(msg, sig []byte) bool {
	sigInt := new(big.Int).SetBytes(sig)
	computed := new(big.Int).Exp(sigInt, toyRSAE, toyRSAN)
	return computed.Cmp(toyRSADigest(msg)) == 0
}

// --- MAC: HMAC-SHA-256 with a truncated, tiled key --------------------
//
// Only the first 4 bytes of the supplied key are used (or fewer, if
// shorter), tiled to fill a 32-byte HMAC key. This collapses the
// effective keyspace to at most 2^32 regardless of the caller's actual
// key length -- the weak key-derivation being demonstrated. The hash
// itself (SHA-256) is unchanged.

const weakMACTruncatedLen = 4

func weakMAC(key, msg []byte) []byte {
	truncLen := weakMACTruncatedLen
	if len(key) < truncLen {
		truncLen = len(key)
	}
	truncated := key[:truncLen]
	if len(truncated) == 0 {
		truncated = []byte{0}
	}
	weakKey := make([]byte, 32)
	for i := range weakKey {
		weakKey[i] = truncated[i%len(truncated)]
	}
	return standardMAC(weakKey, msg) // the hash (HMAC-SHA-256) is real; only the key is weakened
}
