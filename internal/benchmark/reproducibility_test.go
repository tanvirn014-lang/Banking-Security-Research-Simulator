package benchmark

import (
	"context"
	"fmt"
	"testing"

	"banksec-lab/internal/harness"
)

// TestBenchmark_SameSeed_IdenticalNonTimingFields is Task 49's required
// reproducibility test: same seed -> identical raw results on every
// NON-timing, non-bookkeeping field. ExecutionTimeMS is expected to
// vary run to run (real wall-clock measurement); RunID/Timestamp are
// per-invocation bookkeeping (RunID embeds the rep/seed, so it IS
// identical across runs here, but Timestamp is real wall-clock and
// is NOT), neither a "logical outcome" of the experiment itself.
//
// Correction found while writing this test (not in the task's own
// instructions, which name only ExecutionTimeMS as the timing
// exception): DetectionLatencyMS is ALSO a real wall-clock measurement
// (harness.Evidence's detection_latency_ms = the Detection Engine's own
// detection event Timestamp minus the scenario's own tamperedAt
// Timestamp, both real time.Now() calls -- internal/harness's
// scenario_ledger.go), not something the seed parameter controls at
// all. It is excluded from the strict-equality comparison below for the
// same reason ExecutionTimeMS is.
func TestBenchmark_SameSeed_IdenticalNonTimingFields(t *testing.T) {
	vulnerable, hardened := loadTestProfiles(t)
	runner := harness.NewRunner()

	raw1, err := RunComparative(context.Background(), runner, harness.NewLedgerTamperScenario, vulnerable, hardened, 5, 7)
	if err != nil {
		t.Fatalf("RunComparative run 1: %v", err)
	}
	raw2, err := RunComparative(context.Background(), runner, harness.NewLedgerTamperScenario, vulnerable, hardened, 5, 7)
	if err != nil {
		t.Fatalf("RunComparative run 2: %v", err)
	}

	if len(raw1) != len(raw2) {
		t.Fatalf("expected identical-length raw results, got %d and %d", len(raw1), len(raw2))
	}
	for i := range raw1 {
		r1, r2 := raw1[i].Result, raw2[i].Result
		if r1.AttackID != r2.AttackID ||
			r1.TargetConfiguration != r2.TargetConfiguration ||
			r1.AttackType != r2.AttackType ||
			r1.Success != r2.Success ||
			r1.Attempts != r2.Attempts {
			t.Fatalf("run %d: expected identical non-timing fields under the same seed, got %+v and %+v", i, r1, r2)
		}
		// Only PRESENCE (nil vs. non-nil) is compared for
		// TimeToCompromiseMS/DetectionLatencyMS -- WHETHER a tamper was
		// detected/compromised is a logical outcome the seed controls;
		// the exact real-time latency value is not (see this test's own
		// doc comment).
		if (r1.TimeToCompromiseMS == nil) != (r2.TimeToCompromiseMS == nil) {
			t.Fatalf("run %d: expected identical TimeToCompromiseMS PRESENCE, got %s and %s", i, formatOptionalInt64(r1.TimeToCompromiseMS), formatOptionalInt64(r2.TimeToCompromiseMS))
		}
		if (r1.DetectionLatencyMS == nil) != (r2.DetectionLatencyMS == nil) {
			t.Fatalf("run %d: expected identical DetectionLatencyMS PRESENCE, got %s and %s", i, formatOptionalInt64(r1.DetectionLatencyMS), formatOptionalInt64(r2.DetectionLatencyMS))
		}
		// ExecutionTimeMS/DetectionLatencyMS/TimeToCompromiseMS's exact
		// VALUES are deliberately NOT compared: real wall-clock
		// measurement is expected to vary run to run even under an
		// identical seed and configuration.
		if raw1[i].RunID != raw2[i].RunID {
			t.Fatalf("run %d: expected identical RunID (it's derived from scenario/mode/rep/seed, all identical here), got %q and %q", i, raw1[i].RunID, raw2[i].RunID)
		}
	}
}

func formatOptionalInt64(v *int64) string {
	if v == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%d", *v)
}
