package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"banksec-lab/internal/apperr"
)

// The "standard" profile uses only Go stdlib implementations: AES-GCM,
// Ed25519, HMAC-SHA-256. No primitive here is implemented from scratch.

func standardEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeValidation, "invalid AES key", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "construct AES-GCM", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "generate nonce", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func standardDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeValidation, "invalid AES key", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "construct AES-GCM", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, apperr.New(apperr.CodeValidation, "ciphertext shorter than nonce")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeConflict, "AES-GCM authentication failed", err)
	}
	return plaintext, nil
}

func standardSign(key, msg []byte) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, apperr.New(apperr.CodeValidation,
			fmt.Sprintf("invalid Ed25519 private key size: got %d, want %d", len(key), ed25519.PrivateKeySize))
	}
	return ed25519.Sign(ed25519.PrivateKey(key), msg), nil
}

func standardVerify(pubkey, msg, sig []byte) (bool, error) {
	if len(pubkey) != ed25519.PublicKeySize {
		return false, apperr.New(apperr.CodeValidation,
			fmt.Sprintf("invalid Ed25519 public key size: got %d, want %d", len(pubkey), ed25519.PublicKeySize))
	}
	return ed25519.Verify(ed25519.PublicKey(pubkey), msg, sig), nil
}

func standardMAC(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func standardGenerateKeyPair() (private, public []byte, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, apperr.Wrap(apperr.CodeInternal, "generate X25519 key pair", err)
	}
	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

func standardDeriveSharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeValidation, "invalid X25519 private key", err)
	}
	peerPub, err := curve.NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeValidation, "invalid X25519 peer public key", err)
	}
	secret, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeValidation, "X25519 ECDH failed", err)
	}
	return secret, nil
}
