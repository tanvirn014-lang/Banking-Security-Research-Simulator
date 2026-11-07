package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	e := NewEngine()
	key := make([]byte, 32) // AES-256 key
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	ct, err := e.Encrypt("standard", key, []byte("synthetic-plaintext"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := e.Decrypt("standard", key, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != "synthetic-plaintext" {
		t.Fatalf("got %q", pt)
	}
}

func TestEncrypt_InvalidKeySizeRejected(t *testing.T) {
	e := NewEngine()
	badKey := make([]byte, 7) // not a valid AES key size (16/24/32)

	if _, err := e.Encrypt("standard", badKey, []byte("x")); err == nil {
		t.Fatal("expected an error for an invalid AES key size, got none")
	}
}

func TestDecrypt_ModifiedCiphertextRejected(t *testing.T) {
	e := NewEngine()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	ct, err := e.Encrypt("standard", key, []byte("synthetic-plaintext"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 0xFF // flip a bit in the GCM tag/ciphertext tail

	if _, err := e.Decrypt("standard", key, tampered); err == nil {
		t.Fatal("expected AES-GCM to reject a modified ciphertext, got no error")
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	e := NewEngine()

	sig, err := e.Sign("standard", priv, []byte("msg"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := e.Verify("standard", pub, []byte("msg"), sig)
	if err != nil || !ok {
		t.Fatalf("Verify: ok=%v err=%v", ok, err)
	}
}

func TestVerify_ModifiedMessageRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	e := NewEngine()

	sig, err := e.Sign("standard", priv, []byte("original message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := e.Verify("standard", pub, []byte("a different message"), sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("expected Verify to reject a signature over a modified message")
	}
}

func TestVerify_InvalidKeyRejected(t *testing.T) {
	e := NewEngine()
	badPub := make([]byte, 5) // not a valid Ed25519 public key size (32 bytes)

	if _, err := e.Verify("standard", badPub, []byte("msg"), make([]byte, ed25519.SignatureSize)); err == nil {
		t.Fatal("expected an error for an invalid public key size, got none")
	}
}

func TestMAC_TamperDetected(t *testing.T) {
	e := NewEngine()
	key := []byte("synthetic-mac-key")

	tag, err := e.MAC("standard", key, []byte("original"))
	if err != nil {
		t.Fatalf("MAC: %v", err)
	}
	tag2, err := e.MAC("standard", key, []byte("tampered"))
	if err != nil {
		t.Fatalf("MAC: %v", err)
	}
	if bytes.Equal(tag, tag2) {
		t.Fatal("MAC did not change for different input")
	}
}

func TestUnimplementedProfile(t *testing.T) {
	// pqc's MAC has no symmetric-MAC equivalent defined (its Encrypt/
	// Decrypt use ML-KEM, its Sign/Verify use ML-DSA -- see Task 21 for
	// how pqc authenticates protocol frames instead); every other
	// profile/method combination is implemented as of Task 20.
	e := NewEngine()

	_, err := e.MAC("pqc", make([]byte, 32), []byte("x"))
	if !errors.Is(err, ErrProfileNotImplemented) {
		t.Fatalf("expected ErrProfileNotImplemented, got %v", err)
	}
}
