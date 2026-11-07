package harness

import (
	"context"
	"math/rand"
	"testing"
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
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
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
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
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

	factories := []func() Scenario{
		func() Scenario { return Scenario{ID: "a", Category: "application"} },
		func() Scenario { return Scenario{ID: "b", Category: "protocol"} },
		func() Scenario { return Scenario{ID: "c", Category: "application"} },
	}

	for _, f := range factories {
		if err := reg.Register(f); err != nil {
			t.Fatalf("Register(%s): %v", f().ID, err)
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
// type), so returning a Scenario value by itself still aliases whatever
// map a factory happens to close over -- mutating a map read back from
// ByID/All/ByCategory must not corrupt what a later read sees.
func TestRegistry_RequiredConfigNotSharedWithCaller(t *testing.T) {
	reg := NewRegistry()

	factory := func() Scenario {
		return Scenario{ID: "shared-config", RequiredConfig: map[string]string{"crypto_profile": "standard"}}
	}
	if err := reg.Register(factory); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok := reg.ByID("shared-config")
	if !ok {
		t.Fatalf("expected to find the registered scenario")
	}
	got.RequiredConfig["crypto_profile"] = "mutated-via-returned-copy"

	again, _ := reg.ByID("shared-config")
	if again.RequiredConfig["crypto_profile"] != "standard" {
		t.Fatalf("expected mutating a map returned by one ByID call to not affect a later one, got %v", again.RequiredConfig)
	}
}

func TestRegistry_DuplicateIDRejected(t *testing.T) {
	reg := NewRegistry()
	factory := func() Scenario { return Scenario{ID: "dup"} }
	if err := reg.Register(factory); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := reg.Register(factory); err == nil {
		t.Fatalf("expected registering a duplicate ID to fail")
	}
	if len(reg.All()) != 1 {
		t.Fatalf("expected the duplicate registration to have no effect, got %d scenarios", len(reg.All()))
	}
}

// TestRegistry_LookupsAreIndependent is the regression test for security
// review finding I2: a Scenario value returned by ByID previously shared
// its Exec/Verify closures' captured state with every other copy of the
// same registered ID -- two separate ByID lookups of the same scenario,
// run sequentially or concurrently, raced on or leaked results into each
// other's state. Register now stores a factory and calls it fresh per
// lookup, so each returned Scenario has its own independent state.
func TestRegistry_LookupsAreIndependent(t *testing.T) {
	reg := NewRegistry()
	factory := func() Scenario {
		var seen bool
		return Scenario{
			ID: "independent-lookup",
			Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
				if seen {
					t.Fatalf("test bug: this factory call's Exec ran more than once")
				}
				seen = true
				return nil
			},
			Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
				return seen, nil, nil
			},
		}
	}
	if err := reg.Register(factory); err != nil {
		t.Fatalf("Register: %v", err)
	}

	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	first, ok := reg.ByID("independent-lookup")
	if !ok {
		t.Fatalf("expected to find the registered scenario")
	}
	firstResult, err := r.Run(context.Background(), first, env, 1)
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if !firstResult.Success {
		t.Fatalf("expected the first lookup's own run to succeed, got Success=false")
	}

	// A second, independent lookup must start with fresh state (seen=false
	// again inside its own factory call), not inherit the first lookup's
	// already-true seen.
	second, ok := reg.ByID("independent-lookup")
	if !ok {
		t.Fatalf("expected to find the registered scenario")
	}
	secondResult, err := r.Run(context.Background(), second, env, 1)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !secondResult.Success {
		t.Fatalf("expected the second, independent lookup's own run to also succeed on its own Exec, got Success=false")
	}
}
