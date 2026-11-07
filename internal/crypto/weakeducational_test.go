package crypto

import (
	"bytes"
	"math/big"
	"testing"
)

func TestECBMode_RepeatsBlocksForRepeatedPlaintext(t *testing.T) {
	e := NewEngine()
	key := make([]byte, 16)
	block := bytes.Repeat([]byte{0x42}, 16)
	plaintext := append(bytes.Clone(block), block...) // two identical 16-byte blocks

	ct, err := e.Encrypt("weak-educational", key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ct) < 32 {
		t.Fatalf("expected at least 32 bytes of ciphertext, got %d", len(ct))
	}
	if !bytes.Equal(ct[0:16], ct[16:32]) {
		t.Fatal("expected ECB mode to produce identical ciphertext blocks for identical plaintext blocks (this is the demonstrated weakness)")
	}
}

func TestECBMode_RoundTrip(t *testing.T) {
	e := NewEngine()
	key := make([]byte, 16)
	plaintext := []byte("synthetic-plaintext-for-ecb")

	ct, err := e.Encrypt("weak-educational", key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := e.Decrypt("weak-educational", key, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("got %q, want %q", pt, plaintext)
	}
}

func TestECBMode_ModifiedCiphertextGoesUndetected(t *testing.T) {
	// Unlike the standard profile's AES-GCM, ECB mode has no integrity
	// check at all -- a modified ciphertext decrypts "successfully" into
	// garbage instead of returning an error. This absence of detection
	// is itself the demonstrated weakness, not an oversight.
	e := NewEngine()
	key := make([]byte, 16)
	plaintext := bytes.Repeat([]byte{0x01}, 32)

	ct, err := e.Encrypt("weak-educational", key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := bytes.Clone(ct)
	tampered[0] ^= 0xFF

	_, err = e.Decrypt("weak-educational", key, tampered)
	if err != nil {
		t.Fatalf("expected ECB decrypt of a tampered ciphertext to succeed (no authentication), got error: %v", err)
	}
}

func TestToyRSA_SignVerify_RoundTrip(t *testing.T) {
	e := NewEngine()

	sig, err := e.Sign("weak-educational", nil, []byte("synthetic message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := e.Verify("weak-educational", nil, []byte("synthetic message"), sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected the toy RSA signature to verify")
	}
}

// TestToyRSAPublicKey_MatchesInternalModulus is the regression test for
// Milestone 8's cryptographic attack scenario: ToyRSAPublicKey must
// expose the same modulus/exponent Sign/Verify actually use internally,
// since "globally-known" (this file's own doc comment) is meaningless if
// what's exposed doesn't match what's really used.
func TestToyRSAPublicKey_MatchesInternalModulus(t *testing.T) {
	n, e := ToyRSAPublicKey()
	if n.Cmp(toyRSAN) != 0 {
		t.Fatalf("ToyRSAPublicKey's n=%v does not match the internal toyRSAN=%v", n, toyRSAN)
	}
	if e.Cmp(toyRSAE) != 0 {
		t.Fatalf("ToyRSAPublicKey's e=%v does not match the internal toyRSAE=%v", e, toyRSAE)
	}
}

func TestToyRSA_FactorableWithinBudget(t *testing.T) {
	const maxTrials = 1_000_000
	n := new(big.Int).Set(toyRSAN)

	found := false
	for i := int64(2); i <= maxTrials; i++ {
		candidate := big.NewInt(i)
		if new(big.Int).Mod(n, candidate).Sign() == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected the toy RSA modulus to be factorable within %d trial divisions (this is the acceptance criterion for 'weak')", maxTrials)
	}
}

func TestWeakMAC_StillChangesWithInput(t *testing.T) {
	e := NewEngine()
	key := []byte("synthetic-weak-key")

	tag1, err := e.MAC("weak-educational", key, []byte("original"))
	if err != nil {
		t.Fatalf("MAC: %v", err)
	}
	tag2, err := e.MAC("weak-educational", key, []byte("tampered"))
	if err != nil {
		t.Fatalf("MAC: %v", err)
	}
	if bytes.Equal(tag1, tag2) {
		t.Fatal("expected the weak MAC to still change with input (it's weak, not broken)")
	}
}
