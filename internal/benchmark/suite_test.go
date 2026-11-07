package benchmark

import (
	"context"
	"errors"
	"math/rand"
	"testing"

	"banksec-lab/internal/harness"
)

func TestRunSuite_CoversEveryRegisteredScenario(t *testing.T) {
	vulnerable, hardened := loadTestProfiles(t)
	runner := harness.NewRunner()

	reg := harness.NewRegistry()
	if err := reg.Register(harness.NewLedgerTamperScenario); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Register(harness.NewAuditTamperScenario); err != nil {
		t.Fatalf("Register: %v", err)
	}

	results, err := RunSuite(context.Background(), runner, reg, vulnerable, hardened, 1, 1)
	if err != nil {
		t.Fatalf("RunSuite: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected one RawResults entry per registered scenario (2), got %d", len(results))
	}
	for _, id := range []string{harness.LedgerTamperScenarioID, harness.AuditTamperScenarioID} {
		raw, ok := results[id]
		if !ok {
			t.Fatalf("expected results for registered scenario %q, got keys %v", id, keysOf(results))
		}
		if len(raw) != 2 { // 1 rep x 2 modes
			t.Fatalf("scenario %q: expected 2 raw runs (1 rep x 2 modes), got %d", id, len(raw))
		}
	}
}

func TestRunSuite_EmptyRegistryReturnsEmptyResults(t *testing.T) {
	vulnerable, hardened := loadTestProfiles(t)
	runner := harness.NewRunner()
	reg := harness.NewRegistry()

	results, err := RunSuite(context.Background(), runner, reg, vulnerable, hardened, 1, 1)
	if err != nil {
		t.Fatalf("RunSuite: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no results for an empty registry, got %d", len(results))
	}
}

func TestRunSuite_RespectsContextCancellation(t *testing.T) {
	vulnerable, hardened := loadTestProfiles(t)
	runner := harness.NewRunner()
	reg := harness.NewRegistry()
	if err := reg.Register(harness.NewLedgerTamperScenario); err != nil {
		t.Fatalf("Register: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunSuite(ctx, runner, reg, vulnerable, hardened, 1, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected an already-cancelled context to be reported, got %v", err)
	}
}

// TestRunSuite_PreservesPartialResultsOnScenarioFailure is the
// regression test for security review finding M7: RunSuite's own doc
// comment already claimed "stops and returns what it collected so far
// plus that error", but the code didn't actually store the failing
// scenario's partial RawResults into the returned map before returning
// -- discarding everything RunComparative had already collected for
// that scenario.
func TestRunSuite_PreservesPartialResultsOnScenarioFailure(t *testing.T) {
	vulnerable, hardened := loadTestProfiles(t)
	runner := harness.NewRunner()
	reg := harness.NewRegistry()

	var callCount int
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cancels ctx itself right after its first run's own Verify
	// completes, so RunComparative returns a 1-run PARTIAL RawResults
	// plus context.Canceled for this scenario, deterministically (no
	// wall-clock race).
	newScenario := func() harness.Scenario {
		return harness.Scenario{
			ID:       "benchmark-suite-test-interrupted",
			Category: "test",
			Exec:     func(ctx context.Context, env *harness.Environment, rnd *rand.Rand) error { return nil },
			Verify: func(ctx context.Context, o harness.Oracle) (bool, harness.Evidence, error) {
				callCount++
				if callCount == 1 {
					cancel()
				}
				return false, nil, nil
			},
		}
	}
	if err := reg.Register(newScenario); err != nil {
		t.Fatalf("Register: %v", err)
	}

	results, err := RunSuite(ctx, runner, reg, vulnerable, hardened, 5, 1) // reps=5, but ctx cancels after run #1
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	raw, ok := results["benchmark-suite-test-interrupted"]
	if !ok {
		t.Fatalf("expected the interrupted scenario's PARTIAL results to still be present in the returned map, got keys=%v", keysOf(results))
	}
	if len(raw) == 0 {
		t.Fatalf("expected at least 1 partial raw run preserved, got 0")
	}
}

func keysOf(m map[string]RawResults) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
