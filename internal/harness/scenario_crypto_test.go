package harness

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	"banksec-lab/internal/config"
	"banksec-lab/internal/crypto"
)

func weakEducationalTestProfile() config.SecurityProfile {
	return config.SecurityProfile{
		Name:                     "weak-educational-test",
		CryptoProfile:            "weak-educational",
		MinAcceptedCryptoProfile: "weak-educational",
		ProtocolAuthEnforced:     true,
		AuthzEnforced:            true,
		AtomicityEnforced:        true,
		KeystoreEncryptedAtRest:  false,
		AuditHashChained:         false,
	}
}

func newWeakEducationalEnvironment(t *testing.T) *Environment {
	t.Helper()
	env, err := NewLocalEnvironment(weakEducationalTestProfile())
	if err != nil {
		t.Fatalf("NewLocalEnvironment: %v", err)
	}
	t.Cleanup(func() {
		if err := env.Close(); err != nil {
			t.Errorf("Environment.Close: %v", err)
		}
	})
	return env
}

func TestScenario_ToyRSAFactorAndForge_SucceedsWithinBudget(t *testing.T) {
	env := newWeakEducationalEnvironment(t)
	r := NewRunner()
	s := NewToyRSAFactorAndForgeScenario()

	result, err := r.Run(context.Background(), s, env, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected the toy RSA modulus to be factored and a forged signature to verify within budget, got Success=false (result=%+v)", result)
	}
	if result.ComputationalCost == nil || *result.ComputationalCost <= 0 || *result.ComputationalCost > toyRSAMaxTrials {
		t.Fatalf("expected a positive ComputationalCost within the %d-trial budget, got %v", toyRSAMaxTrials, result.ComputationalCost)
	}
}

func TestScenario_ToyRSAFactorAndForge_InfeasibleUnderStandardProfile(t *testing.T) {
	// hardened.json configures crypto_profile=standard.
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()
	s := NewToyRSAFactorAndForgeScenario()

	result, err := r.Run(context.Background(), s, env, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Success {
		t.Fatalf("expected the toy-RSA-specific technique to be inapplicable under a standard-profile environment, got Success=true")
	}
}

func TestScenario_ECBPatternLeakage_WeakLeaksStandardDoesNot(t *testing.T) {
	env := newWeakEducationalEnvironment(t)
	r := NewRunner()
	s := NewECBPatternLeakageScenario()

	result, err := r.Run(context.Background(), s, env, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected ECB pattern leakage to be observed under weak-educational while standard shows none, got Success=false")
	}
}

// TestScenario_ECBPatternLeakage_InapplicableUnderStandardProfile is the
// regression test for security review finding M1: Verify previously
// reported Success=true regardless of the Environment's own
// CryptoProfile, because both inline crypto.Engine calls hardcode their
// own profile names and never consult env.Profile at all -- so nothing
// about the Environment under test was actually being exercised when
// run against a hardened/standard-profile Environment.
func TestScenario_ECBPatternLeakage_InapplicableUnderStandardProfile(t *testing.T) {
	// hardened.json configures crypto_profile=standard.
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()
	s := NewECBPatternLeakageScenario()

	result, err := r.Run(context.Background(), s, env, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Success {
		t.Fatalf("expected the ECB-specific technique to be inapplicable under a standard-profile environment, got Success=true")
	}
}

func TestRecoverWeakDHSharedSecret_UsesOnlyPublicValues(t *testing.T) {
	engine := crypto.NewEngine()
	privA, pubA, err := engine.GenerateKeyPair("weak-educational")
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	privB, pubB, err := engine.GenerateKeyPair("weak-educational")
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}
	realSecret, err := engine.DeriveSharedSecret("weak-educational", privA, pubB)
	if err != nil {
		t.Fatalf("DeriveSharedSecret: %v", err)
	}
	_ = privB // not passed to recoverWeakDHSharedSecret below -- the point of this test

	p, g := crypto.ToyDHPublicParams()
	pubAInt := new(big.Int).SetBytes(pubA)
	pubBInt := new(big.Int).SetBytes(pubB)

	recovered, _, err := recoverWeakDHSharedSecret(context.Background(), p, g, pubAInt, pubBInt)
	if err != nil {
		t.Fatalf("recoverWeakDHSharedSecret: %v", err)
	}

	recoveredBytes := make([]byte, len(p.Bytes()))
	recovered.FillBytes(recoveredBytes)
	if !bytes.Equal(recoveredBytes, realSecret) {
		t.Fatalf("recovered secret %x does not match real secret %x", recoveredBytes, realSecret)
	}
}

// TestRecoverWeakDHSharedSecret_RejectsPOutOfInt64Range is the
// regression test for a security review minor finding: p was converted
// via the bare p.Int64(), whose result is undefined (and, in practice,
// a silent low-bits truncation) when p does not fit in an int64. A
// sufficiently large p could truncate to a small, plausible-looking
// value that passes every check downstream, producing a wrong answer
// instead of an honest error.
func TestRecoverWeakDHSharedSecret_RejectsPOutOfInt64Range(t *testing.T) {
	// p's low 64 bits equal 500000 (a small, otherwise-plausible
	// modulus), but p itself is far outside int64 range.
	hugeP := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 70), big.NewInt(500000))
	g := big.NewInt(3)
	pubA := big.NewInt(12345)
	pubB := big.NewInt(67890)

	if _, _, err := recoverWeakDHSharedSecret(context.Background(), hugeP, g, pubA, pubB); !errors.Is(err, errDHParameterOutOfRange) {
		t.Fatalf("expected errDHParameterOutOfRange for a p that does not fit in an int64, got %v (risk: silent low-bits truncation producing a wrong answer)", err)
	}
}

func TestRecoverWeakDHSharedSecret_RespectsContextCancellation(t *testing.T) {
	engine := crypto.NewEngine()
	_, pubA, err := engine.GenerateKeyPair("weak-educational")
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	_, pubB, err := engine.GenerateKeyPair("weak-educational")
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}
	p, g := crypto.ToyDHPublicParams()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = recoverWeakDHSharedSecret(ctx, p, g, new(big.Int).SetBytes(pubA), new(big.Int).SetBytes(pubB))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from an already-canceled context, got %v", err)
	}
}

func TestScenario_DiffieHellmanDiscreteLog_SucceedsWithinBudget(t *testing.T) {
	env := newWeakEducationalEnvironment(t)
	r := NewRunner()
	s := NewDiffieHellmanDiscreteLogScenario()

	result, err := r.Run(context.Background(), s, env, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected the attacker's recovered secret to match the real shared secret, got Success=false (result=%+v)", result)
	}
	if result.ComputationalCost == nil || *result.ComputationalCost <= 0 {
		t.Fatalf("expected a positive ComputationalCost, got %v", result.ComputationalCost)
	}
}

// TestDHDiscreteLogSucceeded_FailsClosedWhenAttackDidNotComplete is the
// regression test for a security review finding (Important): Verify
// previously returned bytes.Equal(recoveredSecretBytes, realSecretBytes)
// directly, and bytes.Equal(nil, nil) is true in Go. If Exec set
// applicable=true but then errored (or returned early via
// errWeakDHPrimitiveMismatch) before either byte slice was assigned,
// Verify reported Success=true for an attack that never actually ran --
// turning the scenario's own primitive-sanity-check failure into a
// reported successful attack. dhDiscreteLogSucceeded must report false
// whenever the attack did not run to completion, regardless of what the
// (possibly still-nil) byte slices compare as.
func TestDHDiscreteLogSucceeded_FailsClosedWhenAttackDidNotComplete(t *testing.T) {
	if dhDiscreteLogSucceeded(false, nil, nil) {
		t.Fatal("expected false when the attack did not complete, even though both byte slices are nil (and therefore equal)")
	}
}

func TestDHDiscreteLogSucceeded_TrueOnlyWhenCompletedAndSecretsMatch(t *testing.T) {
	if !dhDiscreteLogSucceeded(true, []byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Fatal("expected true when the attack completed and the recovered secret matches the real one")
	}
	if dhDiscreteLogSucceeded(true, []byte{1, 2, 3}, []byte{4, 5, 6}) {
		t.Fatal("expected false when the attack completed but the recovered secret does not match the real one")
	}
}

func TestScenario_DiffieHellmanDiscreteLog_InfeasibleUnderStandardProfile(t *testing.T) {
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()
	s := NewDiffieHellmanDiscreteLogScenario()

	result, err := r.Run(context.Background(), s, env, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Success {
		t.Fatal("expected the DH-discrete-log technique to be inapplicable under a standard-profile environment, got Success=true")
	}
}
