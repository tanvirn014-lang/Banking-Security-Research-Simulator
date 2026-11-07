package harness

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"banksec-lab/internal/protocol"
)

func TestRunner_PopulatesResultFromEvidence(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	s := Scenario{
		ID:       "test-populate",
		Category: "test",
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			return true, Evidence{
				EvidenceDataLeakedBytes:    int64(42),
				EvidenceRecordsCompromised: 3,
			}, nil
		},
	}

	result, err := r.Run(ctx, s, env, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected Success=true, got %+v", result)
	}
	if result.AttackID != "test-populate" || result.AttackType != "test" {
		t.Fatalf("expected AttackID/AttackType to come from the Scenario, got %+v", result)
	}
	if result.TargetConfiguration != "hardened" {
		t.Fatalf("expected TargetConfiguration=hardened, got %q", result.TargetConfiguration)
	}
	if result.DataLeakedBytes == nil || *result.DataLeakedBytes != 42 {
		t.Fatalf("expected DataLeakedBytes=42, got %v", result.DataLeakedBytes)
	}
	if result.RecordsCompromised == nil || *result.RecordsCompromised != 3 {
		t.Fatalf("expected RecordsCompromised=3, got %v", result.RecordsCompromised)
	}
	if result.Seed == nil || *result.Seed != 1 {
		t.Fatalf("expected Seed=1, got %v", result.Seed)
	}
}

func TestRunner_InapplicableFieldsStayNil(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	s := Scenario{
		ID: "test-nil-fields",
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			return false, Evidence{}, nil
		},
	}

	result, err := r.Run(ctx, s, env, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.TimeToCompromiseMS != nil || result.DataLeakedBytes != nil || result.RecordsCompromised != nil ||
		result.DetectionLatencyMS != nil || result.ComputationalCost != nil || result.MemoryUsageBytes != nil {
		t.Fatalf("expected every evidence-derived field to stay nil when no Evidence key was set, got %+v", result)
	}
}

func TestRunner_SameSeed_SameRandomSequenceObservedByExec(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	observe := func(seed int64) int64 {
		var observed int64
		s := Scenario{
			ID: "test-seed",
			Exec: func(ctx context.Context, client protocol.Client, priv PrivilegedAccess, rnd *rand.Rand) error {
				observed = rnd.Int63()
				return nil
			},
			Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) { return false, nil, nil },
		}
		if _, err := r.Run(ctx, s, env, seed); err != nil {
			t.Fatalf("Run: %v", err)
		}
		return observed
	}

	a1 := observe(42)
	a2 := observe(42)
	b := observe(43)

	if a1 != a2 {
		t.Fatalf("expected the same seed to produce the same random sequence, got %d then %d", a1, a2)
	}
	if a1 == b {
		t.Fatalf("expected a different seed to (almost certainly) produce a different value, both were %d", a1)
	}
}

func TestRunner_PanicInExec_ReturnsErrorInsteadOfCrashing(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	s := Scenario{
		ID: "test-panic",
		Exec: func(ctx context.Context, client protocol.Client, priv PrivilegedAccess, rnd *rand.Rand) error {
			panic("deliberate test panic")
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) { return false, nil, nil },
	}

	result, err := r.Run(ctx, s, env, 1)
	if err != nil {
		t.Fatalf("expected Run itself to return no error (Exec's panic is swallowed internally, not propagated as Run's own error), got %v", err)
	}
	if result.Success {
		t.Fatalf("expected Success=false after a panicking Exec, got true")
	}
}

func TestRunner_TimeoutExceeded_ReturnsErrorNotHang(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	s := Scenario{
		ID:      "test-timeout",
		Timeout: 50 * time.Millisecond,
		Exec: func(ctx context.Context, client protocol.Client, priv PrivilegedAccess, rnd *rand.Rand) error {
			<-ctx.Done() // honors cancellation, but the test below also
			// covers a non-cooperative Exec via the goroutine-based
			// deadline enforcement in runExecWithDeadline.
			return ctx.Err()
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) { return false, nil, nil },
	}

	runStart := time.Now()
	// Exec itself consumes the whole Timeout budget, so Verify (which
	// shares the same per-attempt deadline -- Timeout bounds "one
	// Exec+Verify attempt", not Exec alone) has none left and reports
	// its own context-deadline error; Run surfaces that rather than
	// masking it as a clean Success=false.
	if _, err := r.Run(ctx, s, env, 1); err == nil {
		t.Fatalf("expected Run to report Verify's context-deadline error once Exec consumed the whole Timeout, got nil")
	}
	if elapsed := time.Since(runStart); elapsed > time.Second {
		t.Fatalf("expected Run to return promptly after a 50ms Timeout, took %v", elapsed)
	}
}

func TestRunner_NonCooperativeExec_StillBoundedByTimeout(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	s := Scenario{
		ID:      "test-noncooperative",
		Timeout: 50 * time.Millisecond,
		Exec: func(ctx context.Context, client protocol.Client, priv PrivilegedAccess, rnd *rand.Rand) error {
			// Deliberately ignores ctx -- a hostile/buggy attack
			// implementation that never checks for cancellation.
			time.Sleep(10 * time.Second)
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) { return false, nil, nil },
	}

	runStart := time.Now()
	// The leaked, non-cooperative Exec consumes the whole Timeout
	// budget too, so Verify's own deadline is already gone by the time
	// it runs -- same reasoning as TestRunner_TimeoutExceeded_ReturnsErrorNotHang.
	if _, err := r.Run(ctx, s, env, 1); err == nil {
		t.Fatalf("expected Run to report Verify's context-deadline error, got nil")
	}
	if elapsed := time.Since(runStart); elapsed > time.Second {
		t.Fatalf("expected Run to return promptly even though Exec ignores ctx, took %v", elapsed)
	}
}
