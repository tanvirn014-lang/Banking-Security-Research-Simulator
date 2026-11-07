package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"

	"banksec-lab/internal/domain"
	"banksec-lab/internal/keystore"
)

// KeyExposureScenarioID identifies the key-material-exposure scenario.
const KeyExposureScenarioID = "key-exposure"

// NewKeyExposureScenario generates a test key (GenerateTestKey -- see
// its doc comment for why a fixture helper is needed here), then reads
// it back via env.Priv.RawKeyBytes, simulating insider access: the
// unlock/decrypt path is not available through PrivilegedAccess, so
// this returns plaintext-at-rest in vulnerable mode but still-wrapped
// ciphertext in hardened mode. Success is the stolen bytes matching the
// known plaintext exactly.
//
// Verify does not use the Oracle: there is nothing a *read-only*
// channel could tell it about raw key material without that channel
// becoming privileged itself (see oracle.go's own doc comment on why
// KeySnapshot never returns material). The comparison is between what
// Exec captured (the attack's actual result) and the test's own known
// ground truth -- the honest shape of this particular attack, not a
// weakening of "never trust Exec's own claim": Exec makes no success
// claim at all here, only Verify decides, from data Exec gathered.
func NewKeyExposureScenario() Scenario {
	var stolenBytes, knownPlaintext []byte

	return Scenario{
		ID:              KeyExposureScenarioID,
		Category:        "key-management",
		TargetComponent: "keystore",
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
			meta, material, err := env.GenerateTestKey(ctx, domain.CryptoProfileName("standard"))
			if err != nil {
				return fmt.Errorf("generate test key: %w", err)
			}
			knownPlaintext = material

			raw, err := env.Priv.RawKeyBytes(ctx, meta.ID)
			if err != nil {
				return fmt.Errorf("RawKeyBytes: %w", err)
			}
			stolenBytes = raw
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			if len(stolenBytes) == 0 || len(knownPlaintext) == 0 {
				return false, nil, fmt.Errorf("test bug: Exec did not capture both stolenBytes and knownPlaintext")
			}
			if !bytes.Equal(stolenBytes, knownPlaintext) {
				return false, nil, nil
			}
			return true, Evidence{EvidenceDataLeakedBytes: int64(len(stolenBytes))}, nil
		},
	}
}

// KeyRevocationScenarioID identifies the key-revocation scenario.
const KeyRevocationScenarioID = "key-revocation"

// NewKeyRevocationScenario is not a hardened-vs-vulnerable differential
// like every other Milestone 8 scenario: revocation must reject a
// revoked key's material for new operations in *every* mode -- there is
// no profile setting that should ever make a revoked key usable again.
// ATTACK_SURFACES.md §4 itself frames this as the harness *verifying* a
// security property, not an attack that differs by mode. Success here
// (from the attacker's perspective) would be GetTestKey -- the normal,
// intended access path -- returning a revoked key's material anyway.
func NewKeyRevocationScenario() Scenario {
	var getErr error
	var getAttempted bool

	return Scenario{
		ID:              KeyRevocationScenarioID,
		Category:        "key-management",
		TargetComponent: "keystore",
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
			meta, _, err := env.GenerateTestKey(ctx, domain.CryptoProfileName("standard"))
			if err != nil {
				return fmt.Errorf("generate test key: %w", err)
			}
			if err := env.RevokeTestKey(ctx, meta.ID); err != nil {
				return fmt.Errorf("revoke test key: %w", err)
			}

			_, _, getErr = env.GetTestKey(ctx, meta.ID)
			getAttempted = true
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			if !getAttempted {
				// Exec failed before ever reaching the post-revocation Get
				// attempt -- an attack-infrastructure failure, not a
				// (successful or unsuccessful) attack. Previously this
				// fell through to the "anything else means bypass" branch
				// below and reported Success=true even though revocation
				// was never actually exercised (security review finding
				// I3).
				return false, nil, fmt.Errorf("exec did not reach the post-revocation Get attempt")
			}
			if errors.Is(getErr, keystore.ErrKeyRevoked) {
				return false, nil, nil
			}
			// Anything else -- nil error (material returned despite
			// revocation) or a different error -- means revocation was
			// NOT correctly enforced for this "new operation".
			return true, nil, nil
		},
	}
}
