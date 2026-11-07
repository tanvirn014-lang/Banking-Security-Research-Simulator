package crypto

import (
	"bytes"
	"crypto/mlkem"
	"testing"
)

func TestMLKEM_EncryptDecrypt_RoundTrip(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}
	e := NewEngine()

	ct, err := e.Encrypt("pqc", dk.EncapsulationKey().Bytes(), []byte("synthetic-pqc-plaintext"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := e.Decrypt("pqc", dk.Bytes(), ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != "synthetic-pqc-plaintext" {
		t.Fatalf("got %q", pt)
	}
}

func TestMLKEM_TamperedCiphertextFails(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}
	e := NewEngine()

	ct, err := e.Encrypt("pqc", dk.EncapsulationKey().Bytes(), []byte("synthetic-pqc-plaintext"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 0xFF // flip a bit in the AES-GCM tail (the auth tag)

	if _, err := e.Decrypt("pqc", dk.Bytes(), tampered); err == nil {
		t.Fatal("expected a tampered pqc ciphertext to fail to decrypt (AEAD integrity)")
	}
}

func TestMLKEM_WrongRecipientKeyFails(t *testing.T) {
	dkA, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768 A: %v", err)
	}
	dkB, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768 B: %v", err)
	}
	e := NewEngine()

	ct, err := e.Encrypt("pqc", dkA.EncapsulationKey().Bytes(), []byte("synthetic-pqc-plaintext"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := e.Decrypt("pqc", dkB.Bytes(), ct); err == nil {
		t.Fatal("expected decryption with the wrong recipient's key to fail")
	}
}
