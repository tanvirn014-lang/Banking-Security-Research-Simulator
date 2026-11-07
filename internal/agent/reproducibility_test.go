package agent

import (
	"context"
	"testing"
	"time"

	"banksec-lab/internal/harness"
	"banksec-lab/internal/testsupport"
)

// TestAgent_SameSeed_SameActionSequence is Task 45's required
// reproducibility test: given a fixed Clock (internal/testsupport.FixedClock)
// and the same seed, two entirely separate Agent.Run invocations (fresh
// Policy, fresh Agent, fresh DecisionLog) must produce field-by-field
// identical DecisionLog sequences. This is this package's concrete
// instance of the project's established
// seed-parameterized-reproducibility convention
// (internal/harness.Runner, internal/quantum.Shor/Grover).
func TestAgent_SameSeed_SameActionSequence(t *testing.T) {
	kinds := []ActionKind{"attack-a", "attack-b", "attack-c"}
	reg := newFakeRegistry("attack-a", "attack-b", "attack-c")
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	runOnce := func() []Decision {
		env := &harness.Environment{Oracle: fakeOracle{}}
		policy := NewDeterministicPolicy(kinds)
		a := NewAgent(policy, kinds, reg, env, 3)
		a.Clock = testsupport.FixedClock(fixedTime)
		runner := &fakeRunner{}
		if _, _, err := a.Run(context.Background(), runner, 7); err != nil {
			t.Fatalf("Run: %v", err)
		}
		return a.DecisionLog
	}

	log1 := runOnce()
	log2 := runOnce()

	if len(log1) != len(log2) {
		t.Fatalf("expected identical-length decision logs, got %d and %d", len(log1), len(log2))
	}
	for i := range log1 {
		if log1[i].Action != log2[i].Action {
			t.Fatalf("decision %d: expected identical Action, got %+v and %+v", i, log1[i].Action, log2[i].Action)
		}
		if !log1[i].Timestamp.Equal(log2[i].Timestamp) {
			t.Fatalf("decision %d: expected identical (fixed-clock) Timestamp, got %v and %v", i, log1[i].Timestamp, log2[i].Timestamp)
		}
	}
}
