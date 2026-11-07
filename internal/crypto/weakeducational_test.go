package crypto

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	"banksec-lab/internal/quantum"
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

func TestToyDHParams_SafePrimeAndSubgroupGenerator(t *testing.T) {
	p, g := ToyDHPublicParams()
	if !p.ProbablyPrime(20) {
		t.Fatalf("toyDHP is not prime: %s", p)
	}
	if !toyDHQ.ProbablyPrime(20) {
		t.Fatalf("toyDHQ is not prime: %s", toyDHQ)
	}
	wantP := new(big.Int).Add(new(big.Int).Mul(toyDHQ, big.NewInt(2)), big.NewInt(1))
	if p.Cmp(wantP) != 0 {
		t.Fatalf("toyDHP must equal 2*toyDHQ+1: p=%s, 2q+1=%s", p, wantP)
	}
	if g.Cmp(big.NewInt(1)) == 0 {
		t.Fatal("toyDHG must not be 1 (the trivial subgroup)")
	}
	if new(big.Int).Exp(g, toyDHQ, p).Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("toyDHG^toyDHQ mod toyDHP must equal 1 (g must generate the order-q subgroup)")
	}
}

func TestToyDHParams_WithinDiscreteLogBudget(t *testing.T) {
	p, _ := ToyDHPublicParams()
	if p.Cmp(big.NewInt(quantum.MaxDiscreteLogModulus)) >= 0 {
		t.Fatalf("toyDHP (%s) must be below quantum.MaxDiscreteLogModulus (%d): BSGS cost is governed by p itself, not toyDHQ", p, quantum.MaxDiscreteLogModulus)
	}
}

func TestToyDHPublicParams_ReturnsDefensiveCopies(t *testing.T) {
	p1, g1 := ToyDHPublicParams()
	p1.SetInt64(0)
	g1.SetInt64(0)
	p2, g2 := ToyDHPublicParams()
	if p2.Sign() == 0 || g2.Sign() == 0 {
		t.Fatal("mutating a value returned by ToyDHPublicParams must not affect package state (defensive-copy requirement, matching ToyRSAPublicKey)")
	}
}

func TestKeyExchange_RoundTrip_WeakEducational(t *testing.T) {
	e := NewEngine()
	privA, pubA, err := e.GenerateKeyPair("weak-educational")
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	privB, pubB, err := e.GenerateKeyPair("weak-educational")
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}

	secretA, err := e.DeriveSharedSecret("weak-educational", privA, pubB)
	if err != nil {
		t.Fatalf("DeriveSharedSecret A: %v", err)
	}
	secretB, err := e.DeriveSharedSecret("weak-educational", privB, pubA)
	if err != nil {
		t.Fatalf("DeriveSharedSecret B: %v", err)
	}
	if !bytes.Equal(secretA, secretB) {
		t.Fatalf("both sides must derive the same shared secret: got %x and %x", secretA, secretB)
	}
}

// This test has an inherent, negligible flake probability (~1/toyDHQ,
// roughly 2e-6) since the toy group's private exponent space is small
// by design (unlike the standard profile's 256-bit X25519 keyspace,
// where a collision is not a practical concern) -- noted here, not
// treated as something to eliminate.
func TestKeyExchange_WeakEducational_GenerateKeyPairNeverRepeats(t *testing.T) {
	e := NewEngine()
	priv1, _, err := e.GenerateKeyPair("weak-educational")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv2, _, err := e.GenerateKeyPair("weak-educational")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if bytes.Equal(priv1, priv2) {
		t.Fatal("two GenerateKeyPair calls produced the same private key")
	}
}

func TestKeyExchange_WeakEducational_FixedWidthEncoding(t *testing.T) {
	e := NewEngine()
	p, _ := ToyDHPublicParams()
	wantLen := len(p.Bytes())
	for i := 0; i < 20; i++ {
		priv, pub, err := e.GenerateKeyPair("weak-educational")
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		if len(priv) != wantLen || len(pub) != wantLen {
			t.Fatalf("iteration %d: expected fixed width %d, got private=%d public=%d", i, wantLen, len(priv), len(pub))
		}
	}
}

func TestKeyExchange_WeakEducational_RejectsWrongWidthPrivateKey(t *testing.T) {
	e := NewEngine()
	_, pub, err := e.GenerateKeyPair("weak-educational")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	tooShort := make([]byte, len(pub)-1)
	if _, err := e.DeriveSharedSecret("weak-educational", tooShort, pub); err == nil {
		t.Fatal("expected an error for a wrong-width private key, got none")
	}
}

func TestKeyExchange_WeakEducational_RejectsInvalidPeerPublicKey(t *testing.T) {
	e := NewEngine()
	priv, _, err := e.GenerateKeyPair("weak-educational")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	p, g := ToyDHPublicParams()
	_ = g
	width := len(p.Bytes())

	one := make([]byte, width)
	one[width-1] = 1 // y = 1, the trivial element

	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	pMinus1Bytes := make([]byte, width)
	pMinus1.FillBytes(pMinus1Bytes) // y = p-1, the order-2 element

	// A generator of the FULL group (order 2*toyDHQ), not the order-q
	// subgroup: g^2 mod p has order toyDHQ already (stays in-subgroup),
	// so use a value known NOT to satisfy y^q mod p == 1 -- p-2 works
	// for any safe prime where g itself is a subgroup generator, since
	// the full group has even order 2q and p-2's order must be checked
	// against q; compute it directly rather than assume.
	notInSubgroup := new(big.Int).Sub(p, big.NewInt(2))
	for new(big.Int).Exp(notInSubgroup, toyDHQ, p).Cmp(big.NewInt(1)) == 0 {
		notInSubgroup.Sub(notInSubgroup, big.NewInt(1))
	}
	notInSubgroupBytes := make([]byte, width)
	notInSubgroup.FillBytes(notInSubgroupBytes)

	zero := make([]byte, width) // y = 0

	pPlus5 := new(big.Int).Add(p, big.NewInt(5))
	pPlus5Bytes := make([]byte, width)
	pPlus5.FillBytes(pPlus5Bytes) // y >= p

	cases := map[string][]byte{
		"empty":                     nil,
		"wrong width (short)":       one[1:],
		"wrong width (long)":        append(bytes.Clone(one), 0),
		"y=0":                       zero,
		"y=1":                       one,
		"y=p-1":                     pMinus1Bytes,
		"y>=p":                      pPlus5Bytes,
		"y not in order-q subgroup": notInSubgroupBytes,
	}
	for name, peerPub := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := e.DeriveSharedSecret("weak-educational", priv, peerPub); !errors.Is(err, ErrWeakDHInvalidPeerPublicKey) {
				t.Fatalf("expected ErrWeakDHInvalidPeerPublicKey, got %v", err)
			}
		})
	}
}

// TestKeyExchange_WeakEducational_RejectsOutOfRangePrivateKey is the
// regression test for a security review minor finding: privateKey was
// only validated for byte width, so an all-zero buffer (x=0) or x=toyDHQ
// -- neither of which GenerateKeyPair would ever produce, but both of
// which a caller could pass by mistake (e.g. a zeroed buffer) -- silently
// derived a predictable, trivial shared secret (g^0 mod p = 1) instead
// of being rejected. Cheap defense-in-depth: privateKey must be in
// [2, toyDHQ-1], matching the range GenerateKeyPair actually produces.
func TestKeyExchange_WeakEducational_RejectsOutOfRangePrivateKey(t *testing.T) {
	e := NewEngine()
	_, pub, err := e.GenerateKeyPair("weak-educational")
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	width := len(pub)

	zero := make([]byte, width) // x=0
	one := make([]byte, width)
	one[width-1] = 1 // x=1, below the [2, toyDHQ-1] range

	for name, priv := range map[string][]byte{"x=0": zero, "x=1": one} {
		t.Run(name, func(t *testing.T) {
			if _, err := e.DeriveSharedSecret("weak-educational", priv, pub); err == nil {
				t.Fatal("expected an error for an out-of-range private key, got none")
			}
		})
	}
}

func TestKeyExchange_PQCReturnsNotImplemented(t *testing.T) {
	e := NewEngine()
	if _, _, err := e.GenerateKeyPair("pqc"); !errors.Is(err, ErrProfileNotImplemented) {
		t.Fatalf("GenerateKeyPair: expected ErrProfileNotImplemented, got %v", err)
	}
	if _, err := e.DeriveSharedSecret("pqc", []byte("x"), []byte("y")); !errors.Is(err, ErrProfileNotImplemented) {
		t.Fatalf("DeriveSharedSecret: expected ErrProfileNotImplemented, got %v", err)
	}
}

// TestToyDH_DiscreteLogSolvableWithinBudget mirrors
// TestToyRSA_FactorableWithinBudget: it proves the chosen toy DH
// parameters are actually solvable by internal/quantum's own classical
// baby-step-giant-step baseline, not merely small enough in principle
// (TestToyDHParams_WithinDiscreteLogBudget only checks toyDHP's size
// against the bound -- this test actually runs the algorithm and
// confirms it recovers the real private exponent, catching a
// parameter-sizing mistake at this layer rather than only discovering
// it later via the crypto-dh-discrete-log attack scenario).
func TestToyDH_DiscreteLogSolvableWithinBudget(t *testing.T) {
	private, public, err := weakDHGenerateKeyPair()
	if err != nil {
		t.Fatalf("weakDHGenerateKeyPair: %v", err)
	}
	p, g := ToyDHPublicParams()
	wantExponent := new(big.Int).SetBytes(private).Int64()
	publicInt := new(big.Int).SetBytes(public).Int64()

	recovered, _, err := quantum.DiscreteLogBabyStepGiantStep(context.Background(), int(g.Int64()), int(publicInt), int(p.Int64()))
	if err != nil {
		t.Fatalf("DiscreteLogBabyStepGiantStep: %v", err)
	}
	if int64(recovered) != wantExponent {
		t.Fatalf("recovered exponent %d does not match the real private exponent %d", recovered, wantExponent)
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
