package crypto

import (
	"crypto/mldsa"
	"testing"
)

func newTestMLDSAKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return sk
}

func TestMLDSA_SignVerify_RoundTrip(t *testing.T) {
	sk := newTestMLDSAKey(t)
	e := NewEngine()

	sig, err := e.Sign("pqc", sk.Bytes(), []byte("synthetic message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := e.Verify("pqc", sk.PublicKey().Bytes(), []byte("synthetic message"), sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected the ML-DSA signature to verify")
	}
}

func TestMLDSA_TamperedMessageFailsVerify(t *testing.T) {
	sk := newTestMLDSAKey(t)
	e := NewEngine()

	sig, err := e.Sign("pqc", sk.Bytes(), []byte("original message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := e.Verify("pqc", sk.PublicKey().Bytes(), []byte("a different message"), sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for a modified message")
	}
}

func TestMLDSA_InvalidPublicKeyRejected(t *testing.T) {
	e := NewEngine()
	badPub := make([]byte, 5) // not a valid ML-DSA-44 public key encoding

	if _, err := e.Verify("pqc", badPub, []byte("msg"), make([]byte, mldsa.MLDSA44().SignatureSize())); err == nil {
		t.Fatal("expected an error for an invalid ML-DSA public key, got none")
	}
}

func TestMLDSA_SigningIsDeterministic(t *testing.T) {
	// Reproducibility: the same key and message must always produce the
	// same signature, consistent with ARCHITECTURE.md's reproducibility
	// principle (and unlike the standard profile's Ed25519, which the
	// stdlib's crypto/ed25519.Sign already makes deterministic too -- this
	// test documents that pqc deliberately preserves that property via
	// SignDeterministic rather than the randomized Sign).
	sk := newTestMLDSAKey(t)
	e := NewEngine()

	sig1, err := e.Sign("pqc", sk.Bytes(), []byte("synthetic message"))
	if err != nil {
		t.Fatalf("Sign (1): %v", err)
	}
	sig2, err := e.Sign("pqc", sk.Bytes(), []byte("synthetic message"))
	if err != nil {
		t.Fatalf("Sign (2): %v", err)
	}
	if string(sig1) != string(sig2) {
		t.Fatal("expected ML-DSA signing to be deterministic for the same key and message")
	}
}

func TestMLDSA_KeyReuseAcrossMessagesStillVerifiesIndependently(t *testing.T) {
	// A key reuse scenario: the same key pair signs two different
	// messages; each signature must verify only against its own message.
	sk := newTestMLDSAKey(t)
	e := NewEngine()
	pub := sk.PublicKey().Bytes()

	sigA, err := e.Sign("pqc", sk.Bytes(), []byte("message A"))
	if err != nil {
		t.Fatalf("Sign A: %v", err)
	}
	sigB, err := e.Sign("pqc", sk.Bytes(), []byte("message B"))
	if err != nil {
		t.Fatalf("Sign B: %v", err)
	}

	okA, err := e.Verify("pqc", pub, []byte("message A"), sigA)
	if err != nil || !okA {
		t.Fatalf("expected sigA to verify against message A: ok=%v err=%v", okA, err)
	}
	okB, err := e.Verify("pqc", pub, []byte("message B"), sigB)
	if err != nil || !okB {
		t.Fatalf("expected sigB to verify against message B: ok=%v err=%v", okB, err)
	}
	crossOK, err := e.Verify("pqc", pub, []byte("message A"), sigB)
	if err != nil {
		t.Fatalf("Verify (cross): %v", err)
	}
	if crossOK {
		t.Fatal("expected sigB to NOT verify against message A")
	}
}
