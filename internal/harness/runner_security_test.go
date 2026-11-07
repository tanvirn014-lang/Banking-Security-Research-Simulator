package harness

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"banksec-lab/internal/protocol"
)

// TestRunner_ExecutionTimeMS_Populated is the regression test for
// security review finding C2: Run's un-named local `result` was
// returned by value before the deferred ExecutionTimeMS assignment ran,
// so the field silently stayed 0 in every Result the common benchmark
// schema ever produced.
func TestRunner_ExecutionTimeMS_Populated(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	s := Scenario{
		ID: "test-exectime",
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			time.Sleep(50 * time.Millisecond)
			return false, nil, nil
		},
	}

	result, err := r.Run(ctx, s, env, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExecutionTimeMS < 40 {
		t.Fatalf("expected ExecutionTimeMS to reflect at least the 50ms Verify sleep, got %d", result.ExecutionTimeMS)
	}
}

// TestRunner_NilVerify_ReturnsErrorNotPanic is part of finding C3: a
// Scenario with no Verify previously nil-pointer-panicked out of Run
// instead of failing cleanly -- and Verify is never optional (Runner's
// whole guarantee depends on it).
func TestRunner_NilVerify_ReturnsErrorNotPanic(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	_, err := r.Run(ctx, Scenario{ID: "test-nil-verify"}, env, 1)
	if err == nil {
		t.Fatalf("expected an error for a Scenario with a nil Verify, got none")
	}
}

// TestRunner_PrereqsPanic_ReturnsError, TestRunner_VerifyPanic_ReturnsError,
// and TestRunner_StopCondPanic_ReturnsError are the rest of finding C3:
// only Exec's panics were recovered; a panic in Prereqs, Verify, or
// StopCond crashed the whole Run (and, in a real batch/benchmark run,
// the whole batch).
func TestRunner_PrereqsPanic_ReturnsError(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	s := Scenario{
		ID:      "test-prereqs-panic",
		Prereqs: func(ctx context.Context, o Oracle) (bool, error) { panic("prereqs boom") },
		Verify:  func(ctx context.Context, o Oracle) (bool, Evidence, error) { return false, nil, nil },
	}
	if _, err := r.Run(ctx, s, env, 1); err == nil {
		t.Fatalf("expected Run to return an error instead of propagating Prereqs's panic")
	}
}

func TestRunner_VerifyPanic_ReturnsError(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	s := Scenario{
		ID:     "test-verify-panic",
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) { panic("verify boom") },
	}
	if _, err := r.Run(ctx, s, env, 1); err == nil {
		t.Fatalf("expected Run to return an error instead of propagating Verify's panic")
	}
}

func TestRunner_StopCondPanic_ReturnsError(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	s := Scenario{
		ID:       "test-stopcond-panic",
		Verify:   func(ctx context.Context, o Oracle) (bool, Evidence, error) { return false, nil, nil },
		StopCond: func(e Evidence) bool { panic("stopcond boom") },
	}
	if _, err := r.Run(ctx, s, env, 1); err == nil {
		t.Fatalf("expected Run to return an error instead of propagating StopCond's panic")
	}
}

// TestRunner_VerifyBoundedByTimeout is the regression test for finding
// I1: Scenario.Timeout's doc comment says it "bounds one Exec+Verify
// attempt", but only Exec was ever actually bounded -- a hanging Verify
// could block Run indefinitely regardless of Timeout.
func TestRunner_VerifyBoundedByTimeout(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	s := Scenario{
		ID:      "test-verify-timeout",
		Timeout: 50 * time.Millisecond,
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			<-ctx.Done()
			return false, nil, ctx.Err()
		},
	}

	runStart := time.Now()
	if _, err := r.Run(ctx, s, env, 1); err == nil {
		t.Fatalf("expected Run to report Verify's context-deadline error, got nil")
	}
	if elapsed := time.Since(runStart); elapsed > time.Second {
		t.Fatalf("expected Run to return promptly once Verify's own ctx honored the 50ms Timeout, took %v", elapsed)
	}
}

// TestRunner_EvidenceWrongType_ReturnsError is the regression test for
// finding M1: a documented Evidence key present with an unsupported
// type (e.g. a string) was silently indistinguishable from the key
// being absent -- the Result field just stayed nil either way, with no
// signal that something was actually wrong with the Scenario's Verify.
func TestRunner_EvidenceWrongType_ReturnsError(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	s := Scenario{
		ID: "test-evidence-wrong-type",
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			return true, Evidence{EvidenceDataLeakedBytes: "not-a-number"}, nil
		},
	}

	if _, err := r.Run(ctx, s, env, 1); err == nil {
		t.Fatalf("expected Run to report an error for a wrong-typed Evidence value, got nil")
	}
}

// TestRunner_EvidenceResetBetweenAttempts is the regression test for
// finding M2: applyEvidence only ever set fields, never cleared them --
// evidence from a successful attempt N stayed in Result even if
// attempt N+1 (the one that actually determined the final Success) set
// no Evidence at all, misattributing stale data to the final outcome.
func TestRunner_EvidenceResetBetweenAttempts(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	attempt := 0
	s := Scenario{
		ID: "test-evidence-reset",
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			attempt++
			if attempt == 1 {
				return true, Evidence{EvidenceRecordsCompromised: int64(50)}, nil
			}
			return false, Evidence{}, nil
		},
		StopCond: func(e Evidence) bool { return attempt >= 2 },
	}

	result, err := r.Run(ctx, s, env, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Success {
		t.Fatalf("expected the final attempt's Success=false to win, got true")
	}
	if result.RecordsCompromised != nil {
		t.Fatalf("expected RecordsCompromised to be cleared since the final attempt set no such evidence, got %v", *result.RecordsCompromised)
	}
}

// TestRunner_AlreadyCancelledContext_StopsImmediately is part of finding
// M3: Run's attempt loop didn't check ctx at the top, so an
// already-cancelled context still launched a full defaultMaxAttempts
// worth of Exec calls before giving up.
func TestRunner_AlreadyCancelledContext_StopsImmediately(t *testing.T) {
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	env := newTestEnvironment(t, "../../configs/hardened.json")
	r := NewRunner()

	execCalls := 0
	s := Scenario{
		ID: "test-precancelled",
		Exec: func(ctx context.Context, client protocol.Client, priv PrivilegedAccess, rnd *rand.Rand) error {
			execCalls++
			return nil
		},
		Verify:   func(ctx context.Context, o Oracle) (bool, Evidence, error) { return false, nil, nil },
		StopCond: func(e Evidence) bool { return false }, // would otherwise loop to the attempt cap
	}

	start := time.Now()
	if _, err := r.Run(cancelledCtx, s, env, 1); err == nil {
		t.Fatalf("expected Run to report the already-cancelled context, got nil")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("expected Run to stop almost immediately on an already-cancelled ctx, took %v", elapsed)
	}
	if execCalls > 1 {
		t.Fatalf("expected at most 1 Exec call against an already-cancelled context, got %d", execCalls)
	}
}
