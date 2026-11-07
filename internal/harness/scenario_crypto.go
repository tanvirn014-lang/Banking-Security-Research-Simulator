package harness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math/big"
	"math/rand"

	"banksec-lab/internal/crypto"
)

// Both scenarios in this file target internal/crypto directly, not
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
