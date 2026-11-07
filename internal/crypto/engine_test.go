package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"banksec-lab/internal/domain"
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

func TestKeyExchange_RoundTrip_Standard(t *testing.T) {
	e := NewEngine()
	privA, pubA, err := e.GenerateKeyPair("standard")
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	privB, pubB, err := e.GenerateKeyPair("standard")
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}

	secretA, err := e.DeriveSharedSecret("standard", privA, pubB)
	if err != nil {
		t.Fatalf("DeriveSharedSecret A: %v", err)
	}
	secretB, err := e.DeriveSharedSecret("standard", privB, pubA)
	if err != nil {
		t.Fatalf("DeriveSharedSecret B: %v", err)
	}
	if !bytes.Equal(secretA, secretB) {
		t.Fatalf("both sides must derive the same shared secret: got %x and %x", secretA, secretB)
	}
}

func TestKeyExchange_Standard_GenerateKeyPairNeverRepeats(t *testing.T) {
	e := NewEngine()
	priv1, _, err := e.GenerateKeyPair("standard")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv2, _, err := e.GenerateKeyPair("standard")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if bytes.Equal(priv1, priv2) {
		t.Fatal("two GenerateKeyPair calls produced the same private key")
	}
}

func TestKeyExchange_Standard_RejectsWrongWidthPrivateKey(t *testing.T) {
	e := NewEngine()
	if _, err := e.DeriveSharedSecret("standard", make([]byte, 31), make([]byte, 32)); err == nil {
		t.Fatal("expected an error for a wrong-width X25519 private key, got none")
	}
}

func TestKeyExchange_Standard_RejectsWrongLengthPeerPublicKey(t *testing.T) {
	e := NewEngine()
	priv, _, err := e.GenerateKeyPair("standard")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	for _, badLen := range []int{0, 16, 33} {
		if _, err := e.DeriveSharedSecret("standard", priv, make([]byte, badLen)); err == nil {
			t.Fatalf("expected an error for a %d-byte peer public key, got none", badLen)
		}
	}
}

func TestKeyExchange_Standard_AllZeroPeerPublicKeyRejected(t *testing.T) {
	// The well-known all-zero X25519 u-coordinate is a low-order point:
	// crypto/ecdh.PrivateKey.ECDH documents that it returns an error
	// when the computed shared secret would be all-zero.
	e := NewEngine()
	priv, _, err := e.GenerateKeyPair("standard")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	zeroPub := make([]byte, 32)
	if _, err := e.DeriveSharedSecret("standard", priv, zeroPub); err == nil {
		t.Fatal("expected an error for an all-zero X25519 peer public key, got none")
	}
}

// The weak-educational subtest has an inherent, negligible flake
// probability (~1/toyDHQ, roughly 2e-6) since two independently
// generated public keys could theoretically collide in that small toy
// group; the standard subtest's 256-bit X25519 keyspace has no such
// practical concern.
func TestKeyExchange_WrongPeerKeyProducesDifferentSecret(t *testing.T) {
	for _, profile := range []domain.CryptoProfileName{"weak-educational", "standard"} {
		t.Run(string(profile), func(t *testing.T) {
			e := NewEngine()
			privA, _, err := e.GenerateKeyPair(profile)
			if err != nil {
				t.Fatalf("GenerateKeyPair A: %v", err)
			}
			_, pubB, err := e.GenerateKeyPair(profile)
			if err != nil {
				t.Fatalf("GenerateKeyPair B: %v", err)
			}
			_, pubC, err := e.GenerateKeyPair(profile)
			if err != nil {
				t.Fatalf("GenerateKeyPair C: %v", err)
			}

			secretAB, err := e.DeriveSharedSecret(profile, privA, pubB)
			if err != nil {
				t.Fatalf("DeriveSharedSecret A+B: %v", err)
			}
			secretAC, err := e.DeriveSharedSecret(profile, privA, pubC)
			if err != nil {
				t.Fatalf("DeriveSharedSecret A+C: %v", err)
			}
			if bytes.Equal(secretAB, secretAC) {
				t.Fatal("deriving against two different peer public keys produced the same secret")
			}
		})
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
