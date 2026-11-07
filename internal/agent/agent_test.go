package agent

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/harness"
	"banksec-lab/internal/keystore"
	"banksec-lab/internal/ledger"
)

// fakeOracle is a minimal, hand-built harness.Oracle -- no real SQLite
// stores involved -- so Agent's own loop logic (budget, decision log,
// stop conditions, seed plumbing) can be unit-tested in isolation from
// internal/harness's (separately, already-reviewed) store wiring.
type fakeOracle struct {
	snapshot ledger.State
	events   []audit.Event
}

func (f fakeOracle) LedgerSnapshot(ctx context.Context) (ledger.State, error) {
	return f.snapshot, nil
}
func (f fakeOracle) KeySnapshot(ctx context.Context, keyID string) (keystore.KeyMeta, error) {
	return keystore.KeyMeta{}, nil
}
func (f fakeOracle) AuditEventsSince(ctx context.Context, t time.Time) ([]audit.Event, error) {
	return f.events, nil
}

// recordingOracle wraps fakeOracle and records the `since` argument
// every AuditEventsSince call received, for TestAgent_RecentAuditSinceRunBeginsNotEpoch.
type recordingOracle struct {
	fakeOracle
	sinceCalls []time.Time
}

func (r *recordingOracle) AuditEventsSince(ctx context.Context, t time.Time) ([]audit.Event, error) {
	r.sinceCalls = append(r.sinceCalls, t)
	return r.fakeOracle.events, nil
}

// erroringOracle always fails -- for TestAgent_PropagatesOracleErrorInsteadOfEmptyObservation.
type erroringOracle struct{}

func (erroringOracle) LedgerSnapshot(ctx context.Context) (ledger.State, error) {
	return ledger.State{}, errors.New("simulated oracle failure")
}
func (erroringOracle) KeySnapshot(ctx context.Context, keyID string) (keystore.KeyMeta, error) {
	return keystore.KeyMeta{}, nil
}
func (erroringOracle) AuditEventsSince(ctx context.Context, t time.Time) ([]audit.Event, error) {
	return nil, nil
}

// fakeRegistry is a minimal, hand-built harness.Registry over a fixed
// set of Scenario stubs (no Exec/Verify needed -- fakeRunner below never
// calls them), so Agent.Run's resolution of ActionKind -> Scenario can
// be tested without any real attack logic.
type fakeRegistry struct {
	byID map[string]harness.Scenario
}

func newFakeRegistry(ids ...string) *fakeRegistry {
	r := &fakeRegistry{byID: make(map[string]harness.Scenario, len(ids))}
	for _, id := range ids {
		r.byID[id] = harness.Scenario{ID: id, Category: "test"}
	}
	return r
}

func (r *fakeRegistry) Register(factory func() harness.Scenario) error {
	s := factory()
	r.byID[s.ID] = s
	return nil
}
func (r *fakeRegistry) All() []harness.Scenario {
	out := make([]harness.Scenario, 0, len(r.byID))
	for _, s := range r.byID {
		out = append(out, s)
	}
	return out
}
func (r *fakeRegistry) ByID(id string) (harness.Scenario, bool) {
	s, ok := r.byID[id]
	return s, ok
}
func (r *fakeRegistry) ByCategory(category string) []harness.Scenario {
	var out []harness.Scenario
	for _, s := range r.byID {
		if s.Category == category {
			out = append(out, s)
		}
	}
	return out
}

// fakeRunner records every (scenario ID, seed) it was asked to run and
// returns a canned harness.Result, letting agent_test.go assert exactly
// what Agent.Run asked the Runner to do without any real scenario
// execution.
type fakeRunner struct {
	calls      []fakeRunnerCall
	resultFunc func(s harness.Scenario, seed int64) harness.Result
	err        error
}

type fakeRunnerCall struct {
	scenarioID string
	seed       int64
}

func (r *fakeRunner) Run(ctx context.Context, s harness.Scenario, env *harness.Environment, seed int64) (harness.Result, error) {
	r.calls = append(r.calls, fakeRunnerCall{scenarioID: s.ID, seed: seed})
	if r.err != nil {
		return harness.Result{}, r.err
	}
	if r.resultFunc != nil {
		return r.resultFunc(s, seed), nil
	}
	return harness.Result{AttackID: s.ID, Success: false, ExecutionTimeMS: 1}, nil
}

func TestAgent_StopsAtBudget(t *testing.T) {
	reg := newFakeRegistry("attack-a", "attack-b", "attack-c", "attack-d")
	env := &harness.Environment{Oracle: fakeOracle{}}
	policy := NewDeterministicPolicy([]ActionKind{"attack-a", "attack-b", "attack-c", "attack-d"})
	a := NewAgent(policy, []ActionKind{"attack-a", "attack-b", "attack-c", "attack-d"}, reg, env, 2)
	runner := &fakeRunner{}

	results, report, err := a.Run(context.Background(), runner, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected exactly Budget=2 results, got %d", len(results))
	}
	if report.Attempts != 2 {
		t.Fatalf("expected report.Attempts=2, got %d", report.Attempts)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected exactly 2 runner calls, got %d: %+v", len(runner.calls), runner.calls)
	}
	if runner.calls[0].scenarioID != "attack-a" || runner.calls[1].scenarioID != "attack-b" {
		t.Fatalf("expected attack-a then attack-b in fixed order, got %+v", runner.calls)
	}
}

func TestAgent_DecisionLogRecordsEveryStep(t *testing.T) {
	reg := newFakeRegistry("attack-a", "attack-b")
	env := &harness.Environment{Oracle: fakeOracle{}}
	policy := NewDeterministicPolicy([]ActionKind{"attack-a", "attack-b"})
	a := NewAgent(policy, []ActionKind{"attack-a", "attack-b"}, reg, env, 2)
	runner := &fakeRunner{}

	if _, _, err := a.Run(context.Background(), runner, 1); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(a.DecisionLog) != 2 {
		t.Fatalf("expected 2 decision log entries, got %d: %+v", len(a.DecisionLog), a.DecisionLog)
	}
	if a.DecisionLog[0].Action.Kind != "attack-a" || a.DecisionLog[1].Action.Kind != "attack-b" {
		t.Fatalf("expected decision log to record each chosen Action in order, got %+v", a.DecisionLog)
	}
	for i, d := range a.DecisionLog {
		if d.Timestamp.IsZero() {
			t.Fatalf("expected decision %d to have a non-zero Timestamp", i)
		}
	}
}

func TestAgent_StopsCleanlyWhenActionsExhausted(t *testing.T) {
	reg := newFakeRegistry("attack-a")
	env := &harness.Environment{Oracle: fakeOracle{}}
	policy := NewDeterministicPolicy([]ActionKind{"attack-a"})
	a := NewAgent(policy, []ActionKind{"attack-a"}, reg, env, 100) // big budget, only 1 action exists
	runner := &fakeRunner{}

	results, report, err := a.Run(context.Background(), runner, 1)
	if err != nil {
		t.Fatalf("Run: expected a clean stop (ErrNoActionsRemain is not a failure), got %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 result before actions were exhausted, got %d", len(results))
	}
	if report.ObservationCount != 2 {
		t.Fatalf("expected ObservationCount=2 (one that acted, one that found nothing left), got %d", report.ObservationCount)
	}
	if report.ActionCallCount != 1 {
		t.Fatalf("expected ActionCallCount=1, got %d", report.ActionCallCount)
	}
}

func TestAgent_PropagatesUnknownActionKindAsError(t *testing.T) {
	reg := newFakeRegistry() // empty: "attack-a" is not registered
	env := &harness.Environment{Oracle: fakeOracle{}}
	policy := NewDeterministicPolicy([]ActionKind{"attack-a"})
	a := NewAgent(policy, []ActionKind{"attack-a"}, reg, env, 1)
	runner := &fakeRunner{}

	if _, _, err := a.Run(context.Background(), runner, 1); err == nil {
		t.Fatalf("expected an error when the chosen ActionKind resolves to no registered Scenario")
	}
}

func TestAgent_RunnerErrorPropagates(t *testing.T) {
	reg := newFakeRegistry("attack-a")
	env := &harness.Environment{Oracle: fakeOracle{}}
	policy := NewDeterministicPolicy([]ActionKind{"attack-a"})
	a := NewAgent(policy, []ActionKind{"attack-a"}, reg, env, 1)
	runner := &fakeRunner{err: errors.New("simulated runner failure")}

	if _, _, err := a.Run(context.Background(), runner, 1); err == nil {
		t.Fatalf("expected the runner's error to propagate")
	}
}

func TestAgentReport_RecordsAllSixMetrics(t *testing.T) {
	reg := newFakeRegistry("attack-a", "attack-b", "attack-c")
	env := &harness.Environment{Oracle: fakeOracle{}}
	policy := NewDeterministicPolicy([]ActionKind{"attack-a", "attack-b", "attack-c"})
	a := NewAgent(policy, []ActionKind{"attack-a", "attack-b", "attack-c"}, reg, env, 3)
	runner := &fakeRunner{
		resultFunc: func(s harness.Scenario, seed int64) harness.Result {
			// attack-b is the only successful compromise.
			success := s.ID == "attack-b"
			ttc := int64(42)
			var ttcPtr *int64
			if success {
				ttcPtr = &ttc
			}
			return harness.Result{AttackID: s.ID, Success: success, ExecutionTimeMS: 5, TimeToCompromiseMS: ttcPtr}
		},
	}

	results, report, err := a.Run(context.Background(), runner, 1)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if report.Attempts != 3 {
		t.Fatalf("expected Attempts=3, got %d", report.Attempts)
	}
	if report.SuccessfulCompromises != 1 {
		t.Fatalf("expected SuccessfulCompromises=1, got %d", report.SuccessfulCompromises)
	}
	if report.TimeToCompromiseMS == nil {
		t.Fatalf("expected a non-nil TimeToCompromiseMS once a compromise occurred")
	}
	if report.ObservationCount != 3 {
		t.Fatalf("expected ObservationCount=3 (budget exhausted exactly at the last action), got %d", report.ObservationCount)
	}
	if report.ActionCallCount != 3 {
		t.Fatalf("expected ActionCallCount=3, got %d", report.ActionCallCount)
	}
	if report.ComputationalCostMS < 0 {
		t.Fatalf("expected a non-negative ComputationalCostMS, got %d", report.ComputationalCostMS)
	}
}

func TestAgent_RespectsContextCancellation(t *testing.T) {
	reg := newFakeRegistry("attack-a", "attack-b")
	env := &harness.Environment{Oracle: fakeOracle{}}
	policy := NewDeterministicPolicy([]ActionKind{"attack-a", "attack-b"})
	a := NewAgent(policy, []ActionKind{"attack-a", "attack-b"}, reg, env, 2)
	runner := &fakeRunner{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := a.Run(ctx, runner, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected an already-cancelled context to be reported, got %v", err)
	}
}

// fixedPolicy always returns the same Action -- for tests that need a
// Policy deliberately misbehaving (e.g. choosing an action outside the
// Agent's own bounded ActionKinds), which DeterministicPolicy itself
// cannot be made to do.
type fixedPolicy struct {
	action ActionKind
}

func (p fixedPolicy) Decide(obs Observation) (Action, error) {
	return Action{Kind: p.action}, nil
}

// TestAgent_RejectsActionOutsideBoundedActionKinds is the regression
// test for security review finding I1: Agent.Run previously resolved
// any Action.Kind its Policy returned directly against the Registry,
// never checking it against a.ActionKinds first -- a Policy (e.g. a
// future LLMPolicy) returning a Kind that IS registered in the harness
// but is NOT in this Agent's own bounded list was executed anyway,
// defeating the one safety boundary NewAgent's own doc comment promises.
func TestAgent_RejectsActionOutsideBoundedActionKinds(t *testing.T) {
	reg := newFakeRegistry("allowed", "forbidden") // both registered in the harness
	env := &harness.Environment{Oracle: fakeOracle{}}
	policy := fixedPolicy{action: "forbidden"}
	a := NewAgent(policy, []ActionKind{"allowed"}, reg, env, 1) // but NOT in this Agent's own bounded list
	runner := &fakeRunner{}

	if _, _, err := a.Run(context.Background(), runner, 1); err == nil {
		t.Fatalf("expected an error when the Policy chooses an action outside the Agent's bounded ActionKinds")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected the out-of-bounds action to never reach the runner, got calls=%+v", runner.calls)
	}
}

// TestAgent_WrappedErrNoActionsRemainStillStopsCleanly is the regression
// test for security review finding M2: Run compared the Policy's error
// against ErrNoActionsRemain with == instead of errors.Is, so a Policy
// that wraps it (fmt.Errorf("...: %w", ErrNoActionsRemain) -- exactly
// the pattern a future LLMPolicy would use per
// docs/AGENT_LLM_INTEGRATION.md) was treated as a real failure instead
// of a clean, expected stop.
type wrappingExhaustedPolicy struct{ decided bool }

func (p *wrappingExhaustedPolicy) Decide(obs Observation) (Action, error) {
	if p.decided {
		return Action{}, fmt.Errorf("llm policy: %w", ErrNoActionsRemain)
	}
	p.decided = true
	return Action{Kind: "attack-a"}, nil
}

func TestAgent_WrappedErrNoActionsRemainStillStopsCleanly(t *testing.T) {
	reg := newFakeRegistry("attack-a")
	env := &harness.Environment{Oracle: fakeOracle{}}
	a := NewAgent(&wrappingExhaustedPolicy{}, []ActionKind{"attack-a"}, reg, env, 100)
	runner := &fakeRunner{}

	results, _, err := a.Run(context.Background(), runner, 1)
	if err != nil {
		t.Fatalf("expected a WRAPPED ErrNoActionsRemain to still be treated as a clean stop, got %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 result before the wrapped exhaustion was reported, got %d", len(results))
	}
}

// TestAgent_NilClockDoesNotPanic is the regression test for security
// review finding M3: an Agent built as a bare struct literal (every
// field is exported, so this is a legitimate construction path, not
// only via NewAgent) with no Clock set panicked with a nil pointer
// dereference the first time Run tried to call it.
func TestAgent_NilClockDoesNotPanic(t *testing.T) {
	reg := newFakeRegistry("attack-a")
	env := &harness.Environment{Oracle: fakeOracle{}}
	a := &Agent{
		Policy:      NewDeterministicPolicy([]ActionKind{"attack-a"}),
		ActionKinds: []ActionKind{"attack-a"},
		Registry:    reg,
		Env:         env,
		Budget:      1,
		// Clock deliberately left nil.
	}
	runner := &fakeRunner{}
	if _, _, err := a.Run(context.Background(), runner, 1); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestAgent_DecisionLogResetsAcrossRunCalls is the regression test for
// security review finding M5: DecisionLog previously accumulated across
// multiple Run calls on one reused Agent, inconsistent with AgentReport
// being freshly computed every call.
func TestAgent_DecisionLogResetsAcrossRunCalls(t *testing.T) {
	reg := newFakeRegistry("attack-a", "attack-b")
	env := &harness.Environment{Oracle: fakeOracle{}}
	policy := NewDeterministicPolicy([]ActionKind{"attack-a", "attack-b"})
	a := NewAgent(policy, []ActionKind{"attack-a", "attack-b"}, reg, env, 1)
	runner := &fakeRunner{}

	if _, _, err := a.Run(context.Background(), runner, 1); err != nil {
		t.Fatalf("Run #1: %v", err)
	}
	if len(a.DecisionLog) != 1 {
		t.Fatalf("expected 1 decision after the first Run, got %d", len(a.DecisionLog))
	}

	if _, _, err := a.Run(context.Background(), runner, 1); err != nil {
		t.Fatalf("Run #2: %v", err)
	}
	if len(a.DecisionLog) != 1 {
		t.Fatalf("expected DecisionLog to reflect ONLY the second Run's own decision (1), not accumulate across calls, got %d", len(a.DecisionLog))
	}
}

// TestAgent_PreservesPartialResultOnRunnerError is the regression test
// for security review finding M5's other half: on a runner.Run error,
// an earlier version discarded that step's partial Result entirely even
// though DecisionLog already recorded the Decision that led to it --
// results and DecisionLog (and Attempts/ActionCallCount) must stay in
// sync.
func TestAgent_PreservesPartialResultOnRunnerError(t *testing.T) {
	reg := newFakeRegistry("attack-a")
	env := &harness.Environment{Oracle: fakeOracle{}}
	policy := NewDeterministicPolicy([]ActionKind{"attack-a"})
	a := NewAgent(policy, []ActionKind{"attack-a"}, reg, env, 1)
	runner := &fakeRunner{
		resultFunc: func(s harness.Scenario, seed int64) harness.Result {
			return harness.Result{AttackID: s.ID, Attempts: 7}
		},
		err: errors.New("simulated runner failure"),
	}

	results, report, err := a.Run(context.Background(), runner, 1)
	if err == nil {
		t.Fatalf("expected the runner's error to propagate")
	}
	if len(a.DecisionLog) != 1 {
		t.Fatalf("expected 1 decision logged, got %d", len(a.DecisionLog))
	}
	if len(results) != 1 {
		t.Fatalf("expected the partial Result to be preserved despite the runner error, got %d results", len(results))
	}
	if report.ActionCallCount != 1 || report.Attempts != 1 {
		t.Fatalf("expected ActionCallCount=1 and Attempts=1 to stay in sync with DecisionLog, got %+v", report)
	}
}

// TestAgent_PropagatesOracleErrorInsteadOfEmptyObservation is the
// regression test for security review finding M1: an Oracle read
// failure previously made buildObservation silently return an EMPTY
// Observation (err==nil at the Run level), letting the Policy decide
// from data that looked like "nothing happened yet" rather than "the
// Oracle itself is broken."
func TestAgent_PropagatesOracleErrorInsteadOfEmptyObservation(t *testing.T) {
	reg := newFakeRegistry("attack-a")
	env := &harness.Environment{Oracle: erroringOracle{}}
	policy := NewDeterministicPolicy([]ActionKind{"attack-a"})
	a := NewAgent(policy, []ActionKind{"attack-a"}, reg, env, 1)
	runner := &fakeRunner{}

	if _, _, err := a.Run(context.Background(), runner, 1); err == nil {
		t.Fatalf("expected an Oracle failure to propagate as a Run-level error, got nil")
	}
}

// TestAgent_RecentAuditSinceRunBeginsNotEpoch is the regression test for
// security review finding I4's RecentAudit bug: buildObservation always
// called AuditEventsSince(time.Time{}) (the zero/epoch time), so every
// Observation included every audit event ever recorded in the
// Environment's lifetime, not "since the Agent's Run began" as
// documented.
func TestAgent_RecentAuditSinceRunBeginsNotEpoch(t *testing.T) {
	reg := newFakeRegistry("attack-a")
	oracle := &recordingOracle{}
	env := &harness.Environment{Oracle: oracle}
	policy := NewDeterministicPolicy([]ActionKind{"attack-a"})
	a := NewAgent(policy, []ActionKind{"attack-a"}, reg, env, 1)
	runner := &fakeRunner{}

	before := time.Now()
	if _, _, err := a.Run(context.Background(), runner, 1); err != nil {
		t.Fatalf("Run: %v", err)
	}
	after := time.Now()

	if len(oracle.sinceCalls) != 1 {
		t.Fatalf("expected exactly 1 AuditEventsSince call, got %d", len(oracle.sinceCalls))
	}
	since := oracle.sinceCalls[0]
	if since.IsZero() {
		t.Fatalf("expected AuditEventsSince to be called with Run's own start time, got the zero/epoch time")
	}
	if since.Before(before) || since.After(after) {
		t.Fatalf("expected the `since` argument to fall within this Run call's own execution window, got %v (window %v..%v)", since, before, after)
	}
}
