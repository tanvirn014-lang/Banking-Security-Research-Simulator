package harness

import (
	"context"
	"testing"
)

func TestScenario_KeyExposure_PlaintextVulnerable_CiphertextHardened(t *testing.T) {
	cases := []struct {
		name        string
		configPath  string
		wantSuccess bool
	}{
		{"hardened", "../../configs/hardened.json", false},
		{"vulnerable", "../../configs/vulnerable.json", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnvironment(t, tc.configPath)
			r := NewRunner()
			s := NewKeyExposureScenario()

			result, err := r.Run(context.Background(), s, env, 1)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if result.Success != tc.wantSuccess {
				t.Fatalf("profile %q: expected Success=%v, got %v (result=%+v)", tc.name, tc.wantSuccess, result.Success, result)
			}
			if tc.wantSuccess && (result.DataLeakedBytes == nil || *result.DataLeakedBytes <= 0) {
				t.Fatalf("expected a positive DataLeakedBytes on successful exposure, got %v", result.DataLeakedBytes)
			}
		})
	}
}

// TestScenario_KeyRevocation_AlwaysRejected deliberately does not follow
// the hardened-vs-vulnerable pattern every other Milestone 8 test uses:
// see NewKeyRevocationScenario's doc comment for why revocation must be
// enforced in every mode, with no profile-driven exception.
func TestScenario_KeyRevocation_AlwaysRejected(t *testing.T) {
	for _, configPath := range []string{"../../configs/hardened.json", "../../configs/vulnerable.json"} {
		t.Run(configPath, func(t *testing.T) {
			env := newTestEnvironment(t, configPath)
			r := NewRunner()
			s := NewKeyRevocationScenario()

			result, err := r.Run(context.Background(), s, env, 1)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if result.Success {
				t.Fatalf("expected revocation to always be enforced (Success=false) under %s, got Success=true", configPath)
			}
		})
	}
}

// TestScenario_KeyRevocation_ExecFailure_ReturnsErrorNotSuccess is the
// regression test for security review finding I3: Verify previously
// treated "any getErr other than ErrKeyRevoked, including nil" as a
// revocation bypass -- so if Exec failed before ever reaching the
// post-revocation Get attempt (e.g. GenerateTestKey itself failing),
// getErr stayed at its zero value nil, and Verify reported Success=true
// ("revocation bypassed") even though revocation was never exercised at
// all.
func TestScenario_KeyRevocation_ExecFailure_ReturnsErrorNotSuccess(t *testing.T) {
	env := newTestEnvironment(t, "../../configs/hardened.json")
	env.keystore.Close() // GenerateTestKey will now fail immediately

	r := NewRunner()
	if _, err := r.Run(context.Background(), NewKeyRevocationScenario(), env, 1); err == nil {
		t.Fatalf("expected Run to report an error when Exec never reached the post-revocation Get attempt, got nil")
	}
}
