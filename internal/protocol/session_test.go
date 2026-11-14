package protocol

import (
	"bytes"
	"errors"
	"testing"

	"banksec-lab/internal/crypto"
)

func TestSession_BothSidesDeriveTheSameKey(t *testing.T) {
	e := crypto.NewEngine()

	for _, profile := range []string{"standard", "weak-educational"} {
		t.Run(profile, func(t *testing.T) {
			clientPriv, clientPub, err := e.GenerateKeyPair(cryptoName(profile))
			if err != nil {
				t.Fatalf("client keypair: %v", err)
			}
			serverPriv, serverPub, err := e.GenerateKeyPair(cryptoName(profile))
			if err != nil {
				t.Fatalf("server keypair: %v", err)
			}

			clientKey, err := deriveSessionKey(e, cryptoName(profile), clientPriv, serverPub)
			if err != nil {
				t.Fatalf("client derive: %v", err)
			}
			serverKey, err := deriveSessionKey(e, cryptoName(profile), serverPriv, clientPub)
			if err != nil {
				t.Fatalf("server derive: %v", err)
			}

			if !bytes.Equal(clientKey, serverKey) {
				t.Fatalf("the two sides derived different session keys: %x vs %x", clientKey, serverKey)
			}
			if len(clientKey) != sessionKeyLen {
				t.Fatalf("session key is %d bytes, want %d", len(clientKey), sessionKeyLen)
			}
		})
	}
}

// The derived key must be usable as an AES key for the profile's own
// cipher. This matters most for weak-educational, whose raw DH secret
// comes from a tiny group and is far too small to use directly.
func TestSession_DerivedKeyWorksWithTheProfilesCipher(t *testing.T) {
	e := crypto.NewEngine()

	for _, profile := range []string{"standard", "weak-educational"} {
		t.Run(profile, func(t *testing.T) {
			priv, pub, _ := e.GenerateKeyPair(cryptoName(profile))
			key, err := deriveSessionKey(e, cryptoName(profile), priv, pub)
			if err != nil {
				t.Fatalf("derive: %v", err)
			}

			plaintext := []byte("synthetic banking payload")
			ct, err := e.Encrypt(cryptoName(profile), key, plaintext)
			if err != nil {
				t.Fatalf("encrypt under the derived key: %v", err)
			}
			back, err := e.Decrypt(cryptoName(profile), key, ct)
			if err != nil {
				t.Fatalf("decrypt under the derived key: %v", err)
			}
			if !bytes.Equal(bytes.TrimRight(back, "\x00"), bytes.TrimRight(plaintext, "\x00")) {
				t.Fatalf("round trip failed: %q", back)
			}
		})
	}
}

// Different exchanges must yield different session keys, or every
// connection would share one key and the key exchange would be
// decorative.
func TestSession_DifferentExchangesYieldDifferentKeys(t *testing.T) {
	e := crypto.NewEngine()

	privA, _, _ := e.GenerateKeyPair("standard")
	_, pubB, _ := e.GenerateKeyPair("standard")
	_, pubC, _ := e.GenerateKeyPair("standard")

	keyAB, err := deriveSessionKey(e, "standard", privA, pubB)
	if err != nil {
		t.Fatalf("derive AB: %v", err)
	}
	keyAC, err := deriveSessionKey(e, "standard", privA, pubC)
	if err != nil {
		t.Fatalf("derive AC: %v", err)
	}

	if bytes.Equal(keyAB, keyAC) {
		t.Fatal("two different exchanges produced the same session key")
	}
}

// The session key must not simply be the raw shared secret: it is
// domain-separated, so that a secret used for one purpose cannot be
// mistaken for a key used for another.
func TestSession_KeyIsNotTheRawSharedSecret(t *testing.T) {
	e := crypto.NewEngine()

	priv, pub, _ := e.GenerateKeyPair("standard")
	raw, err := e.DeriveSharedSecret("standard", priv, pub)
	if err != nil {
		t.Fatalf("DeriveSharedSecret: %v", err)
	}
	derived, err := deriveSessionKey(e, "standard", priv, pub)
	if err != nil {
		t.Fatalf("deriveSessionKey: %v", err)
	}

	if bytes.Equal(raw, derived) {
		t.Fatal("the session key is the raw shared secret, with no derivation step")
	}
}

// pqc has no DeriveSharedSecret -- its key establishment is ML-KEM
// encapsulation, which does not fit this shape. It must say so clearly
// rather than silently producing a key.
func TestSession_PQCIsReportedUnsupportedNotSilentlyKeyed(t *testing.T) {
	e := crypto.NewEngine()

	_, err := deriveSessionKey(e, "pqc", make([]byte, 32), make([]byte, 32))
	if err == nil {
		t.Fatal("pqc has no key agreement of this shape and must not yield a session key")
	}
	if !errors.Is(err, crypto.ErrProfileNotImplemented) {
		t.Fatalf("expected ErrProfileNotImplemented, got %v", err)
	}
}

func TestSession_SupportsWireEncryptionReportsTheRealSet(t *testing.T) {
	for _, profile := range []string{"standard", "weak-educational"} {
		if !supportsWireEncryption(cryptoName(profile)) {
			t.Fatalf("%s has key agreement and must support wire encryption", profile)
		}
	}
	if supportsWireEncryption("pqc") {
		t.Fatal("pqc has no key agreement of this shape; claiming wire encryption would be false")
	}
	if supportsWireEncryption("nonsense") {
		t.Fatal("an unknown profile must not be reported as supporting wire encryption")
	}
}
