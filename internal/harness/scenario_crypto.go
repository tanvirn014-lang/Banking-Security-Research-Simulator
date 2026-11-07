package harness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math/big"
	"math/rand"

	"banksec-lab/internal/crypto"
	"banksec-lab/internal/quantum"
)

// errWeakDHPrimitiveMismatch indicates the weak-educational DH
// primitive itself failed to agree with itself (both legitimate
// parties derived different secrets) -- a bug in the primitive, not
// something the discrete-log attack below is meant to detect or
// exploit.
var errWeakDHPrimitiveMismatch = errors.New("harness: weak-educational DH round trip produced mismatched shared secrets")

// errDHParameterOutOfRange is returned when p, g, or pubA does not fit
// in an int64. big.Int.Int64 is undefined (in practice, a silent
// low-bits truncation) for an out-of-range value -- without this guard,
// a sufficiently large p could truncate to a small, plausible-looking
// value that passes every downstream check and produces a wrong answer
// instead of an honest error.
var errDHParameterOutOfRange = errors.New("harness: recoverWeakDHSharedSecret: p, g, or pubA does not fit in an int64")

// All three scenarios in this file target internal/crypto directly, not
// env.Client/env.Priv/Oracle: they are passive, standalone cryptanalysis
// against the weak-educational profile's own primitives
// (ATTACK_SURFACES.md §5), not attacks that need to pass through the
// backend/protocol/keystore. "Detection: N/A for the cryptanalysis
// itself... a passive mathematical attack, not an observable system
// event" (ATTACK_SURFACES.md §5). The weak-educational-vs-standard
// distinction these scenarios fork on is a different axis entirely from
// the hardened-vs-vulnerable SecurityProfile axis every other Milestone
// 8 scenario uses.

// ToyRSAFactorAndForgeScenarioID identifies the toy RSA scenario.
const ToyRSAFactorAndForgeScenarioID = "crypto-toy-rsa-factor-forge"

// toyRSAMaxTrials bounds the brute-force factoring attempt, matching
// internal/crypto's own TestToyRSA_FactorableWithinBudget budget.
const toyRSAMaxTrials = 1_000_000

// NewToyRSAFactorAndForgeScenario brute-force factors the weak-
// educational profile's fixed, globally-known RSA modulus
// (crypto.ToyRSAPublicKey), recovers the private exponent, and forges a
// signature for a chosen message -- verified through the real
// crypto.Engine.Verify path, not by re-deriving the same digest
// construction a second time and trusting it blindly. Under a
// standard-profile Environment, the technique is inapplicable (there is
// no RSA modulus to factor at all for Ed25519); Exec reports this
// explicitly rather than attempting something meaningless.
func NewToyRSAFactorAndForgeScenario() Scenario {
	var applicable bool
	var forgedVerifies bool
	var trialsUsed int64

	return Scenario{
		ID:              ToyRSAFactorAndForgeScenarioID,
		Category:        "cryptographic",
		TargetComponent: "crypto",
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
			if env.Profile.CryptoProfile != "weak-educational" {
				applicable = false
				return nil
			}
			applicable = true

			n, e := crypto.ToyRSAPublicKey()

			var p *big.Int
			for i := int64(2); i <= toyRSAMaxTrials; i++ {
				trialsUsed = i - 1
				candidate := big.NewInt(i)
				if new(big.Int).Mod(n, candidate).Sign() == 0 {
					p = candidate
					break
				}
			}
			if p == nil {
				return nil // not factored within budget -- forgedVerifies stays false
			}
			q := new(big.Int).Div(n, p)

			one := big.NewInt(1)
			phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
			d := new(big.Int).ModInverse(e, phi)
			if d == nil {
				return nil
			}

			msg := []byte("forged by attack scenario")
			h := sha256.Sum256(msg)
			digest := new(big.Int).Mod(new(big.Int).SetBytes(h[:]), n)
			forgedSig := new(big.Int).Exp(digest, d, n)

			engine := crypto.NewEngine()
			ok, err := engine.Verify("weak-educational", nil, msg, forgedSig.Bytes())
			if err != nil {
				return err
			}
			forgedVerifies = ok
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			if !applicable {
				return false, nil, nil
			}
			return forgedVerifies, Evidence{EvidenceComputationalCost: trialsUsed}, nil
		},
	}
}

// ECBPatternLeakageScenarioID identifies the ECB pattern-leakage
// scenario.
const ECBPatternLeakageScenarioID = "crypto-ecb-pattern-leakage"

// NewECBPatternLeakageScenario encrypts identical repeated plaintext
// blocks under both weak-educational (ECB) and standard (AES-GCM),
// directly via crypto.Engine, and checks whether the ciphertext's own
// blocks repeat too -- ECB's defining weakness. Success is weak
// -educational leaking the pattern; standard not leaking it is recorded
// as contrastive evidence, not a separate pass/fail axis (there is only
// one Scenario, one Success value -- the point being demonstrated is the
// difference, so both halves run every time).
//
// Like NewToyRSAFactorAndForgeScenario, applicability is gated on
// env.Profile.CryptoProfile == "weak-educational": the technique being
// demonstrated is ECB's structural weakness in *that* profile, not a
// property of whatever Environment happens to run the scenario. Without
// this gate, the scenario reported Success=true even when run against a
// hardened/standard-profile Environment that has no weak-educational
// mode at all -- the two inline crypto.Engine calls work regardless of
// env.Profile, so nothing about the Environment under test was actually
// being exercised (security review finding M1).
func NewECBPatternLeakageScenario() Scenario {
	const blockSize = 16
	var applicable bool
	var weakLeaked, standardLeaked bool

	return Scenario{
		ID:              ECBPatternLeakageScenarioID,
		Category:        "cryptographic",
		TargetComponent: "crypto",
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
			if env.Profile.CryptoProfile != "weak-educational" {
				applicable = false
				return nil
			}
			applicable = true

			engine := crypto.NewEngine()
			block := bytes.Repeat([]byte{0x5a}, blockSize)
			plaintext := bytes.Repeat(block, 4) // four identical blocks

			weakKey := make([]byte, blockSize)
			weakCT, err := engine.Encrypt("weak-educational", weakKey, plaintext)
			if err != nil {
				return err
			}
			weakLeaked = blocksRepeat(weakCT, blockSize)

			standardKey := make([]byte, 32)
			standardCT, err := engine.Encrypt("standard", standardKey, plaintext)
			if err != nil {
				return err
			}
			standardLeaked = blocksRepeat(standardCT, blockSize)
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			if !applicable {
				return false, nil, nil
			}
			return weakLeaked && !standardLeaked, nil, nil
		},
	}
}

// recoverWeakDHSharedSecret recovers the shared secret a passive
// eavesdropper could compute, using ONLY values such an eavesdropper
// could actually observe: the public group parameters and both
// parties' public keys. Its signature has no parameter through which a
// private key could be passed, and the scenario below has exactly one
// call site, which never passes one -- the guarantee is this
// signature-and-single-call-site shape, not a type-system distinction
// between public and private values (both are plain *big.Int; nothing
// stops a caller from passing a private exponent where a public value
// is expected, the way nothing stops that for any other *big.Int
// parameter in this codebase).
func recoverWeakDHSharedSecret(ctx context.Context, p, g, pubA, pubB *big.Int) (sharedSecret *big.Int, operationCount int, err error) {
	if !p.IsInt64() || !g.IsInt64() || !pubA.IsInt64() {
		return nil, 0, errDHParameterOutOfRange
	}
	recoveredExponent, trace, err := quantum.DiscreteLogBabyStepGiantStep(ctx, int(g.Int64()), int(pubA.Int64()), int(p.Int64()))
	if err != nil {
		return nil, 0, err
	}
	secret := new(big.Int).Exp(pubB, big.NewInt(int64(recoveredExponent)), p)
	return secret, trace.OperationCount, nil
}

// DiffieHellmanDiscreteLogScenarioID identifies the DH-discrete-log
// scenario.
const DiffieHellmanDiscreteLogScenarioID = "crypto-dh-discrete-log"

// dhDiscreteLogSucceeded reports whether the attack is proven
// successful. completed must be true only when Exec ran all the way to
// its last step without error -- never inferred from recoveredSecret/
// realSecret alone, since both are nil (and therefore bytes.Equal) if
// Exec returned early, which must never be reported as a success
// (security review finding: Verify previously compared the two byte
// slices directly, so an early Exec error read as Success=true).
func dhDiscreteLogSucceeded(completed bool, recoveredSecret, realSecret []byte) bool {
	return completed && bytes.Equal(recoveredSecret, realSecret)
}

// NewDiffieHellmanDiscreteLogScenario recovers a discrete logarithm in
// the weak-educational profile's deliberately small, fixed, documented
// toy DH group (crypto.ToyDHPublicParams), chosen to fit
// internal/quantum's existing baby-step-giant-step budget, and uses it
// to derive the same shared secret the legitimate parties computed --
// using only values a passive eavesdropper would have observed
// (recoverWeakDHSharedSecret above). This is NOT a break of
// Diffie-Hellman in general, NOT a statement about real-world DH group
// sizes, and NOT a quantum result: no quantum.Shor/circuit code is
// used here, only the classical BSGS baseline. Under a standard-profile
// Environment, the technique is inapplicable (there is no DH group to
// attack, only X25519); Exec reports this explicitly rather than
// attempting something meaningless.
func NewDiffieHellmanDiscreteLogScenario() Scenario {
	var applicable bool
	var completed bool
	var recoveredSecretBytes, realSecretBytes []byte
	var operationCount int

	return Scenario{
		ID:              DiffieHellmanDiscreteLogScenarioID,
		Category:        "cryptographic",
		TargetComponent: "crypto",
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
			if env.Profile.CryptoProfile != "weak-educational" {
				applicable = false
				return nil
			}
			applicable = true

			engine := crypto.NewEngine()
			privA, pubA, err := engine.GenerateKeyPair("weak-educational")
			if err != nil {
				return err
			}
			privB, pubB, err := engine.GenerateKeyPair("weak-educational")
			if err != nil {
				return err
			}

			secretA, err := engine.DeriveSharedSecret("weak-educational", privA, pubB)
			if err != nil {
				return err
			}
			secretB, err := engine.DeriveSharedSecret("weak-educational", privB, pubA)
			if err != nil {
				return err
			}
			if !bytes.Equal(secretA, secretB) {
				return errWeakDHPrimitiveMismatch
			}
			realSecretBytes = secretA

			p, g := crypto.ToyDHPublicParams()
			pubAInt := new(big.Int).SetBytes(pubA)
			pubBInt := new(big.Int).SetBytes(pubB)

			recovered, ops, err := recoverWeakDHSharedSecret(ctx, p, g, pubAInt, pubBInt)
			if err != nil {
				return err
			}
			operationCount = ops
			recoveredSecretBytes = make([]byte, len(secretA))
			recovered.FillBytes(recoveredSecretBytes)
			completed = true
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			if !applicable {
				return false, nil, nil
			}
			return dhDiscreteLogSucceeded(completed, recoveredSecretBytes, realSecretBytes), Evidence{EvidenceComputationalCost: int64(operationCount)}, nil
		},
	}
}

// blocksRepeat reports whether ciphertext contains at least two
// identical blockSize-byte blocks among its first few blocks.
func blocksRepeat(ciphertext []byte, blockSize int) bool {
	seen := make(map[string]bool)
	for i := 0; i+blockSize <= len(ciphertext) && i < blockSize*8; i += blockSize {
		block := string(ciphertext[i : i+blockSize])
		if seen[block] {
			return true
		}
		seen[block] = true
	}
	return false
}
