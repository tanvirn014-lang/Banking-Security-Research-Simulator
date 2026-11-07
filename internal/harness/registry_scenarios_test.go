package harness

import (
	"context"
	"sync"
	"testing"
)

// TestRegisterAllScenarios_NoCollisionsAllCategoriesPresent confirms
// every Milestone 8 scenario registers cleanly (no duplicate IDs -- a
// real risk when 11 scenarios are added incrementally across 5 separate
// files) and that attack discovery by category actually reflects all
// five groups.
func TestRegisterAllScenarios_NoCollisionsAllCategoriesPresent(t *testing.T) {
	reg := NewRegistry()
	if err := RegisterAllScenarios(reg); err != nil {
		t.Fatalf("RegisterAllScenarios: %v", err)
	}

	all := reg.All()
	if len(all) != 11 {
		t.Fatalf("expected 11 registered scenarios, got %d: %+v", len(all), all)
	}

	wantCounts := map[string]int{
		"application":    2,
		"protocol":       3,
		"ledger":         2,
		"key-management": 2,
		"cryptographic":  2,
	}
	for category, want := range wantCounts {
		got := len(reg.ByCategory(category))
		if got != want {
			t.Fatalf("category %q: expected %d scenarios, got %d", category, want, got)
		}
	}

	for _, id := range []string{
		ConcurrentOverdraftScenarioID, AuthzBypassScenarioID,
		ReplayScenarioID, TamperScenarioID, DowngradeScenarioID,
		LedgerTamperScenarioID, AuditTamperScenarioID,
		KeyExposureScenarioID, KeyRevocationScenarioID,
		ToyRSAFactorAndForgeScenarioID, ECBPatternLeakageScenarioID,
	} {
		if _, ok := reg.ByID(id); !ok {
			t.Fatalf("expected ByID(%q) to find a registered scenario", id)
		}
	}
}

// TestRegisterAllScenarios_ConcurrentLookupsDontRace is the regression
// test for security review finding I2's concrete reproduction: two
// concurrent ByID lookups of the same real, registered scenario (the
// reviewer's own example) racing on shared closure-captured state
// (`-race` reported two WARNING: DATA RACE before the factory-based
// Registry fix). Both runs are started together behind a barrier and
// must each report their own correct result against their own
// Environment.
func TestRegisterAllScenarios_ConcurrentLookupsDontRace(t *testing.T) {
	reg := NewRegistry()
	if err := RegisterAllScenarios(reg); err != nil {
		t.Fatalf("RegisterAllScenarios: %v", err)
	}

	hardenedEnv := newTestEnvironment(t, "../../configs/hardened.json")
	vulnerableEnv := newTestEnvironment(t, "../../configs/vulnerable.json")
	r := NewRunner()

	run := func(env *Environment, wantSuccess bool) func() {
		return func() {
			s, ok := reg.ByID(KeyExposureScenarioID)
			if !ok {
				t.Errorf("expected to find %q", KeyExposureScenarioID)
				return
			}
			result, err := r.Run(context.Background(), s, env, 1)
			if err != nil {
				t.Errorf("Run: %v", err)
				return
			}
			if result.Success != wantSuccess {
				t.Errorf("expected Success=%v, got %v", wantSuccess, result.Success)
			}
		}
	}

	var start sync.WaitGroup
	start.Add(1)
	var wg sync.WaitGroup
	for _, fn := range []func(){run(hardenedEnv, false), run(vulnerableEnv, true)} {
		wg.Add(1)
		go func(fn func()) {
			defer wg.Done()
			start.Wait()
			fn()
		}(fn)
	}
	start.Done()
	wg.Wait()
}
