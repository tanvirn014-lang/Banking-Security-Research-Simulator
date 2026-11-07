package harness

import (
	"context"
	"math/rand"
	"testing"

	"banksec-lab/internal/protocol"
)

// TestRunner_NeverTrustsExecClaimOverOracle is the framework's central
// guarantee: a stub Exec that claims success via a side channel the
// Oracle never sees must still produce Success=false, because Verify
// (not Exec's return value) is the only thing Runner ever trusts.
func TestRunner_NeverTrustsExecClaimOverOracle(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	execClaimedSuccess := false // a side channel the Oracle cannot see
	s := Scenario{
		ID: "test-stub-never-trusted",
		Exec: func(ctx context.Context, client protocol.Client, priv PrivilegedAccess, rnd *rand.Rand) error {
			execClaimedSuccess = true // "I did it!" -- but nothing real happened
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			// Deliberately ignores execClaimedSuccess and checks only
			// real, Oracle-observable state (which never changed).
			state, err := o.LedgerSnapshot(ctx)
			if err != nil {
				return false, nil, err
			}
			return len(state.Entries) > 0, nil, nil
		},
	}

	result, err := r.Run(ctx, s, env, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !execClaimedSuccess {
		t.Fatalf("test bug: Exec's side channel was never even set")
	}
	if result.Success {
		t.Fatalf("expected Success=false despite Exec's unverified claim of success, got true")
	}
}

// TestScenario_StopCondHaltsRepeatedAttempts proves the Runner actually
// loops Exec+Verify until StopCond says stop, rather than always
// stopping after one attempt.
func TestScenario_StopCondHaltsRepeatedAttempts(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	const wantAttempts = 5
	attempts := 0
	s := Scenario{
		ID: "test-stopcond",
		Exec: func(ctx context.Context, client protocol.Client, priv PrivilegedAccess, rnd *rand.Rand) error {
			attempts++
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			return attempts >= wantAttempts, Evidence{"attempts": int64(attempts)}, nil
		},
		StopCond: func(e Evidence) bool {
			n, _ := e["attempts"].(int64)
			return n >= wantAttempts
		},
	}

	result, err := r.Run(ctx, s, env, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if attempts != wantAttempts {
		t.Fatalf("expected Exec to run %d times, ran %d", wantAttempts, attempts)
	}
	if result.Attempts != wantAttempts {
		t.Fatalf("expected Result.Attempts=%d, got %d", wantAttempts, result.Attempts)
	}
	if !result.Success {
		t.Fatalf("expected Success=true once the stop condition's own threshold was reached")
	}
}

func TestRegistry_RegisterAndDiscover(t *testing.T) {
	reg := NewRegistry()

	a := Scenario{ID: "a", Category: "application"}
	b := Scenario{ID: "b", Category: "protocol"}
	c := Scenario{ID: "c", Category: "application"}

	for _, s := range []Scenario{a, b, c} {
		if err := reg.Register(s); err != nil {
			t.Fatalf("Register(%s): %v", s.ID, err)
		}
	}

	if len(reg.All()) != 3 {
		t.Fatalf("expected 3 registered scenarios, got %d", len(reg.All()))
	}
	got, ok := reg.ByID("b")
	if !ok || got.ID != "b" {
		t.Fatalf("expected ByID(\"b\") to find it, got ok=%v got=%+v", ok, got)
	}
	if _, ok := reg.ByID("no-such-id"); ok {
		t.Fatalf("expected ByID of an unregistered ID to report ok=false")
	}
	app := reg.ByCategory("application")
	if len(app) != 2 {
		t.Fatalf("expected 2 scenarios in category 'application', got %d", len(app))
	}
}

// TestRegistry_RequiredConfigNotSharedWithCaller is the regression test
// for security review finding M5: RequiredConfig is a map (a reference
// type), so storing/returning a Scenario value by itself still aliases
// the caller's own map -- mutating a map obtained from Register's
// argument or from a ByID/All/ByCategory read could silently corrupt
// the registry's own stored copy.
func TestRegistry_RequiredConfigNotSharedWithCaller(t *testing.T) {
	reg := NewRegistry()

	original := map[string]string{"crypto_profile": "standard"}
	if err := reg.Register(Scenario{ID: "shared-config", RequiredConfig: original}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	original["crypto_profile"] = "mutated-after-register"

	got, ok := reg.ByID("shared-config")
	if !ok {
		t.Fatalf("expected to find the registered scenario")
	}
	if got.RequiredConfig["crypto_profile"] != "standard" {
		t.Fatalf("expected the registry's stored RequiredConfig to be unaffected by mutating the caller's original map, got %v", got.RequiredConfig)
	}

	got.RequiredConfig["crypto_profile"] = "mutated-via-returned-copy"
	again, _ := reg.ByID("shared-config")
	if again.RequiredConfig["crypto_profile"] != "standard" {
		t.Fatalf("expected mutating a map returned by ByID to not affect the registry's stored copy, got %v", again.RequiredConfig)
	}
}

func TestRegistry_DuplicateIDRejected(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(Scenario{ID: "dup"}); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := reg.Register(Scenario{ID: "dup"}); err == nil {
		t.Fatalf("expected registering a duplicate ID to fail")
	}
	if len(reg.All()) != 1 {
		t.Fatalf("expected the duplicate registration to have no effect, got %d scenarios", len(reg.All()))
	}
}
