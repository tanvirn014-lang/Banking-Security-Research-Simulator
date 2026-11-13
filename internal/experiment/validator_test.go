package experiment

import (
	"strings"
	"sync"
	"testing"

	"banksec-lab/internal/domain"
)

func testValidator(t *testing.T, mutate func(*ExperimentSpec)) *Validator {
	t.Helper()
	s := validSpec()
	if mutate != nil {
		mutate(&s)
	}
	v, err := NewValidator(s.Effective())
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

func deposit(amount string) Action {
	return Action{
		Op:     OpDeposit,
		Actor:  domain.Principal{ID: "alice", Role: domain.RoleAccountOwner},
		Params: map[string]string{"account": "acct-1", "amount": amount},
	}
}

func TestValidator_AllowsAWellFormedPermittedAction(t *testing.T) {
	v := testValidator(t, nil)

	got := v.Validate(deposit("100"))
	if got.Decision != DecisionAllow {
		t.Fatalf("decision = %q (%s), want allow", got.Decision, got.Reason)
	}
}

func TestValidator_DistinguishesTheFiveRejectionKinds(t *testing.T) {
	tests := []struct {
		name   string
		action Action
		spec   func(*ExperimentSpec)
		want   Decision
	}{
		{
			name:   "unsupported operation",
			action: Action{Op: "drop-database", Actor: domain.Principal{ID: "alice", Role: domain.RoleAccountOwner}},
			want:   DecisionUnsupported,
		},
		{
			name:   "missing required parameter",
			action: Action{Op: OpDeposit, Actor: domain.Principal{ID: "alice", Role: domain.RoleAccountOwner}, Params: map[string]string{"account": "acct-1"}},
			want:   DecisionMalformed,
		},
		{
			name:   "unparseable amount",
			action: deposit("not-a-number"),
			want:   DecisionMalformed,
		},
		{
			name:   "empty actor id",
			action: Action{Op: OpBalance, Actor: domain.Principal{Role: domain.RoleAccountOwner}, Params: map[string]string{"account": "acct-1"}},
			want:   DecisionMalformed,
		},
		{
			name:   "unknown actor role",
			action: Action{Op: OpBalance, Actor: domain.Principal{ID: "alice", Role: "root"}, Params: map[string]string{"account": "acct-1"}},
			want:   DecisionMalformed,
		},
		{
			name:   "operation excluded by experiment policy",
			action: deposit("100"),
			spec:   func(s *ExperimentSpec) { s.Safety.AllowedOps = []string{OpBalance, OpHistory} },
			want:   DecisionDisallowedByPolicy,
		},
		{
			name:   "amount beyond the safety bound",
			action: deposit("999999999999"),
			spec:   func(s *ExperimentSpec) { s.Safety.MaxAmount = 1000 },
			want:   DecisionDisallowedByPolicy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := testValidator(t, tt.spec)
			got := v.Validate(tt.action)
			if got.Decision != tt.want {
				t.Fatalf("decision = %q (%s), want %q", got.Decision, got.Reason, tt.want)
			}
			if got.Reason == "" {
				t.Fatal("every rejection must carry a reason, for the experiment record")
			}
		})
	}
}

// This is the research-critical case. A negative amount is well-formed
// and within the safety bound, so it is exactly the kind of candidate a
// mutation generator should be allowed to submit: whether the banking
// system rejects it is the thing under test. A validator that rejected
// it here would be doing the system-under-test's input validation on its
// behalf and would hide a real weakness.
func TestValidator_AllowsNegativeAmountsSoTheSimulatorDecides(t *testing.T) {
	v := testValidator(t, nil)

	got := v.Validate(deposit("-100"))
	if got.Decision != DecisionAllow {
		t.Fatalf("a negative amount within the safety bound must reach the simulator, got %q (%s)", got.Decision, got.Reason)
	}
}

func TestValidator_SafetyBoundAppliesToMagnitudeNotSign(t *testing.T) {
	v := testValidator(t, func(s *ExperimentSpec) { s.Safety.MaxAmount = 1000 })

	got := v.Validate(deposit("-999999999"))
	if got.Decision != DecisionDisallowedByPolicy {
		t.Fatalf("a large negative amount must hit the same safety bound as a large positive one, got %q", got.Decision)
	}
}

func TestValidator_ZeroAmountReachesTheSimulator(t *testing.T) {
	v := testValidator(t, nil)

	if got := v.Validate(deposit("0")); got.Decision != DecisionAllow {
		t.Fatalf("a zero amount is well-formed and in bounds; the simulator decides, got %q", got.Decision)
	}
}

func TestValidator_ExhaustsTheActionBudgetAndThenRefusesEverything(t *testing.T) {
	v := testValidator(t, func(s *ExperimentSpec) { s.Budget.MaxActions = 3 })

	for i := 0; i < 3; i++ {
		if got := v.Validate(deposit("10")); got.Decision != DecisionAllow {
			t.Fatalf("action %d: decision = %q (%s), want allow", i, got.Decision, got.Reason)
		}
	}
	if v.Remaining() != 0 {
		t.Fatalf("remaining = %d, want 0 after spending the whole budget", v.Remaining())
	}

	got := v.Validate(deposit("10"))
	if got.Decision != DecisionBudgetExhausted {
		t.Fatalf("decision = %q, want budget_exhausted once the budget is spent", got.Decision)
	}
}

// Budget is the unit comparative metrics normalise against, so it must
// count what actually reached the simulator. An action the validator
// refused never executed and must not be charged for.
func TestValidator_OnlyAllowedActionsConsumeBudget(t *testing.T) {
	v := testValidator(t, func(s *ExperimentSpec) { s.Budget.MaxActions = 2 })

	v.Validate(Action{Op: "drop-database", Actor: domain.Principal{ID: "alice", Role: domain.RoleAccountOwner}})
	v.Validate(deposit("not-a-number"))

	if v.Remaining() != 2 {
		t.Fatalf("remaining = %d, want 2 -- refused actions never reached the simulator", v.Remaining())
	}
}

func TestValidator_ReportsSpentAndRemaining(t *testing.T) {
	v := testValidator(t, func(s *ExperimentSpec) { s.Budget.MaxActions = 5 })

	v.Validate(deposit("10"))
	v.Validate(deposit("10"))

	if v.Spent() != 2 {
		t.Fatalf("spent = %d, want 2", v.Spent())
	}
	if v.Remaining() != 3 {
		t.Fatalf("remaining = %d, want 3", v.Remaining())
	}
}

func TestValidator_RejectsASpecItCannotEnforce(t *testing.T) {
	// An unvalidated spec must not quietly become a validator that
	// permits everything.
	if _, err := NewValidator(ExperimentSpec{}); err == nil {
		t.Fatal("expected NewValidator to reject a spec that never passed Validate")
	}
}

func TestValidator_IsSafeUnderConcurrentUse(t *testing.T) {
	v := testValidator(t, func(s *ExperimentSpec) { s.Budget.MaxActions = 100 })

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v.Validate(deposit("10"))
		}()
	}
	wg.Wait()

	if v.Spent() != 50 {
		t.Fatalf("spent = %d, want exactly 50 -- the budget counter lost or double-counted actions", v.Spent())
	}
}

func TestValidator_RequiredParamsPerOperation(t *testing.T) {
	actor := domain.Principal{ID: "alice", Role: domain.RoleAccountOwner}
	tests := []struct {
		op     string
		params map[string]string
		want   Decision
	}{
		{OpCreateAccount, map[string]string{"owner": "alice"}, DecisionAllow},
		{OpCreateAccount, map[string]string{}, DecisionMalformed},
		{OpBalance, map[string]string{"account": "acct-1"}, DecisionAllow},
		{OpBalance, map[string]string{}, DecisionMalformed},
		{OpHistory, map[string]string{"account": "acct-1"}, DecisionAllow},
		{OpWithdraw, map[string]string{"account": "acct-1", "amount": "10"}, DecisionAllow},
		{OpWithdraw, map[string]string{"amount": "10"}, DecisionMalformed},
		{OpTransfer, map[string]string{"from": "acct-1", "to": "acct-2", "amount": "10"}, DecisionAllow},
		{OpTransfer, map[string]string{"from": "acct-1", "amount": "10"}, DecisionMalformed},
		{OpTransfer, map[string]string{"from": "acct-1", "to": "acct-2"}, DecisionMalformed},
	}

	for _, tt := range tests {
		t.Run(tt.op+"/"+strings.Join(keysOf(tt.params), ","), func(t *testing.T) {
			v := testValidator(t, nil)
			got := v.Validate(Action{Op: tt.op, Actor: actor, Params: tt.params})
			if got.Decision != tt.want {
				t.Fatalf("decision = %q (%s), want %q", got.Decision, got.Reason, tt.want)
			}
		})
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
