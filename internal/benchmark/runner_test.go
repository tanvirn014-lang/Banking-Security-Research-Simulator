package benchmark

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"banksec-lab/internal/config"
	"banksec-lab/internal/harness"
)

func loadTestProfiles(t *testing.T) (vulnerable, hardened config.SecurityProfile) {
	t.Helper()
	v, err := config.Load("../../configs/vulnerable.json")
	if err != nil {
		t.Fatalf("config.Load(vulnerable): %v", err)
	}
	h, err := config.Load("../../configs/hardened.json")
	if err != nil {
		t.Fatalf("config.Load(hardened): %v", err)
	}
	return v, h
}

func TestRunComparative_PreservesAllRawRuns_IncludingFailures(t *testing.T) {
	vulnerable, hardened := loadTestProfiles(t)
	runner := harness.NewRunner()

	const reps = 3
	raw, err := RunComparative(context.Background(), runner, harness.NewLedgerTamperScenario, vulnerable, hardened, reps, 1)
	if err != nil {
		t.Fatalf("RunComparative: %v", err)
	}
	// 2 modes x reps runs each.
	if len(raw) != 2*reps {
		t.Fatalf("expected %d raw runs (2 modes x %d reps), got %d", 2*reps, reps, len(raw))
	}

	var vulnCount, hardCount int
	for _, run := range raw {
		if run.RunID == "" {
			t.Fatalf("expected every raw run to have a non-empty RunID, got %+v", run)
		}
		if run.Timestamp.IsZero() {
			t.Fatalf("expected every raw run to have a non-zero Timestamp, got %+v", run)
		}
		if run.ScenarioID != harness.LedgerTamperScenarioID {
			t.Fatalf("expected ScenarioID=%q, got %q", harness.LedgerTamperScenarioID, run.ScenarioID)
		}
		switch run.Mode {
		case "vulnerable":
			vulnCount++
		case "hardened":
			hardCount++
		default:
			t.Fatalf("unexpected Mode %q", run.Mode)
		}
	}
	if vulnCount != reps || hardCount != reps {
		t.Fatalf("expected %d vulnerable and %d hardened runs, got %d and %d", reps, reps, vulnCount, hardCount)
	}
}

func TestRunComparative_PreservesFailedRuns(t *testing.T) {
	vulnerable, hardened := loadTestProfiles(t)
	runner := harness.NewRunner()
	// A Scenario with a nil Verify is rejected by harness.Runner itself
	// (runner.go: "Verify must not be nil") -- a reliable, real failure
	// mode to confirm RunComparative preserves rather than discards.
	newScenario := func() harness.Scenario {
		return harness.Scenario{ID: "benchmark-test-always-fails", Category: "test"}
	}

	raw, err := RunComparative(context.Background(), runner, newScenario, vulnerable, hardened, 1, 1)
	if err != nil {
		t.Fatalf("RunComparative itself should not error just because individual runs failed: %v", err)
	}
	if len(raw) != 2 {
		t.Fatalf("expected both the vulnerable and hardened failed runs preserved, got %d", len(raw))
	}
	for _, run := range raw {
		if run.RunErr == nil {
			t.Fatalf("expected RunErr to be recorded for a Scenario with nil Verify, got nil (run=%+v)", run)
		}
	}
}

// TestRunComparative_CallsNewScenarioFreshForEveryRun is the first of
// two regression tests for security review finding C1 (Critical): an
// earlier version of RunComparative took a single harness.Scenario
// VALUE and reused it across all 2*reps runs, instead of calling a
// constructor function fresh for each one. This test confirms
// newScenario is invoked exactly once PER RUN, not once total and not
// once per rep.
func TestRunComparative_CallsNewScenarioFreshForEveryRun(t *testing.T) {
	vulnerable, hardened := loadTestProfiles(t)
	runner := harness.NewRunner()

	var factoryCalls int
	newScenario := func() harness.Scenario {
		factoryCalls++
		return harness.Scenario{
			ID:       "benchmark-test-factory-count",
			Category: "test",
			Verify:   func(ctx context.Context, o harness.Oracle) (bool, harness.Evidence, error) { return false, nil, nil },
		}
	}

	const reps = 3
	if _, err := RunComparative(context.Background(), runner, newScenario, vulnerable, hardened, reps, 1); err != nil {
		t.Fatalf("RunComparative: %v", err)
	}
	if factoryCalls != 2*reps {
		t.Fatalf("expected newScenario to be called once per run (%d = 2 modes x %d reps), got %d calls", 2*reps, reps, factoryCalls)
	}
}

// TestRunComparative_DoesNotLeakClosureStateBetweenRuns is the second,
// more direct regression test for C1: it reproduces the exact failure
// mode the review found -- a run whose Exec never reaches completion
// (simulating any real infrastructure hiccup) must report that honestly
// via its OWN fresh closure state, never silently inheriting a PRIOR
// run's "exec succeeded" state because the two runs shared one Scenario
// instance.
func TestRunComparative_DoesNotLeakClosureStateBetweenRuns(t *testing.T) {
	vulnerable, hardened := loadTestProfiles(t)
	runner := harness.NewRunner()

	var callIndex int
	newScenario := func() harness.Scenario {
		var reachedExec bool
		return harness.Scenario{
			ID:       "benchmark-test-closure-leak",
			Category: "test",
			Exec: func(ctx context.Context, env *harness.Environment, rnd *rand.Rand) error {
				callIndex++
				if callIndex == 2 { // simulate an infrastructure failure on exactly the SECOND run
					return fmt.Errorf("simulated exec failure")
				}
				reachedExec = true
				return nil
			},
			Verify: func(ctx context.Context, o harness.Oracle) (bool, harness.Evidence, error) {
				if !reachedExec {
					// Correct behavior for a FRESH instance whose own
					// Exec never completed. Under the pre-fix shared
					// -instance design, this branch would incorrectly
					// never trigger for run #2, since reachedExec would
					// already be true from run #1's own successful Exec.
					return false, nil, fmt.Errorf("this instance's own exec did not reach completion")
				}
				return true, nil, nil
			},
		}
	}

	raw, err := RunComparative(context.Background(), runner, newScenario, vulnerable, hardened, 2, 1)
	if err != nil {
		t.Fatalf("RunComparative: %v", err)
	}
	if len(raw) != 4 {
		t.Fatalf("expected 4 raw runs, got %d", len(raw))
	}
	// raw[1] is the second run overall (vulnerable rep0, hardened rep0,
	// vulnerable rep1, hardened rep1 -- callIndex==2 lands on hardened rep0).
	if raw[1].RunErr == nil {
		t.Fatalf("expected run #2 (index 1)'s own simulated Exec failure to surface as RunErr via its OWN instance's reachedExec, got nil -- closure state leaked from a different run's instance")
	}
	for i, run := range raw {
		if i == 1 {
			continue
		}
		if run.RunErr != nil {
			t.Fatalf("run %d: expected no error (only run index 1 simulates a failure), got %v", i, run.RunErr)
		}
	}
}

func TestRunComparative_SameSeed_SameInitialState(t *testing.T) {
	vulnerable, hardened := loadTestProfiles(t)
	runner := harness.NewRunner()

	raw1, err := RunComparative(context.Background(), runner, harness.NewLedgerTamperScenario, vulnerable, hardened, 2, 42)
	if err != nil {
		t.Fatalf("RunComparative run 1: %v", err)
	}
	raw2, err := RunComparative(context.Background(), runner, harness.NewLedgerTamperScenario, vulnerable, hardened, 2, 42)
	if err != nil {
		t.Fatalf("RunComparative run 2: %v", err)
	}
	if len(raw1) != len(raw2) {
		t.Fatalf("expected the same number of raw runs, got %d and %d", len(raw1), len(raw2))
	}
	for i := range raw1 {
		if raw1[i].Result.Success != raw2[i].Result.Success {
			t.Fatalf("run %d: expected identical Success under the same seed, got %v and %v", i, raw1[i].Result.Success, raw2[i].Result.Success)
		}
		if raw1[i].Mode != raw2[i].Mode {
			t.Fatalf("run %d: expected identical Mode ordering under the same seed, got %q and %q", i, raw1[i].Mode, raw2[i].Mode)
		}
		// The within-rep seed pairing itself: RunID embeds the seed
		// value RunComparative actually used for this run, so comparing
		// it across both invocations confirms the SAME seed+rep value
		// was used both times, not merely that two runs happened to
		// agree by coincidence.
		if raw1[i].RunID != raw2[i].RunID {
			t.Fatalf("run %d: expected an identical RunID (same scenario/mode/rep/seed), got %q and %q", i, raw1[i].RunID, raw2[i].RunID)
		}
	}
}

func TestRunComparative_RespectsContextCancellation(t *testing.T) {
	vulnerable, hardened := loadTestProfiles(t)
	runner := harness.NewRunner()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunComparative(ctx, runner, harness.NewLedgerTamperScenario, vulnerable, hardened, 1, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected an already-cancelled context to be reported, got %v", err)
	}
}

// TestRunComparative_RejectsDuplicateModeNames is the regression test
// for security review finding I3: vulnerable and hardened sharing a
// Name would make harness.Result.TargetConfiguration identical for both
// modes, silently erasing which profile actually ran each row.
func TestRunComparative_RejectsDuplicateModeNames(t *testing.T) {
	vulnerable, _ := loadTestProfiles(t)
	collidingHardened := vulnerable // same Name as vulnerable
	runner := harness.NewRunner()

	if _, err := RunComparative(context.Background(), runner, harness.NewLedgerTamperScenario, vulnerable, collidingHardened, 1, 1); !errors.Is(err, ErrDuplicateModeNames) {
		t.Fatalf("expected ErrDuplicateModeNames, got %v", err)
	}
}
