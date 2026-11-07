package harness

import (
	"context"
	"testing"

	"banksec-lab/internal/config"
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
