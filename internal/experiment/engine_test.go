package experiment

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"banksec-lab/internal/config"
	"banksec-lab/internal/finding"
	"banksec-lab/internal/harness"
)

func testRegistry(t *testing.T) harness.Registry {
	t.Helper()
	reg := harness.NewRegistry()
	if err := harness.RegisterAllScenarios(reg); err != nil {
		t.Fatalf("RegisterAllScenarios: %v", err)
	}
	return reg
}

func testEngine(t *testing.T, profileName string) *Engine {
	t.Helper()
	e, err := NewEngine(testRegistry(t), loadProfile(t, profileName))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func mutationSpec(profileName string) ExperimentSpec {
	return ExperimentSpec{
		ExperimentID:  "exp-mutation",
		Objective:     "probe the authorization boundary with bounded variations",
		TargetProfile: profileName,
		Generator:     GeneratorMutation,
		Budget:        Budget{MaxActions: 60, MaxTests: 6},
		Seed:          42,
		Safety:        Safety{MaxAmount: 100_000},
		SeedScenarios: []string{"workflow-funded-transfer", "workflow-funded-withdrawal"},
	}
}

func staticSpec(profileName string, only ...string) ExperimentSpec {
	return ExperimentSpec{
		ExperimentID:  "exp-static",
		Objective:     "reproduce the registered attack corpus as a baseline",
		TargetProfile: profileName,
		Generator:     GeneratorStatic,
		Budget:        Budget{MaxActions: 100, MaxTests: 3},
		Seed:          7,
		Safety:        Safety{MaxAmount: 100_000, AllowPrivileged: true},
		SeedScenarios: only,
	}
}

func TestEngine_RejectsASpecForADifferentProfile(t *testing.T) {
	e := testEngine(t, "hardened")

	_, err := e.Run(context.Background(), staticSpec("vulnerable"))
	if err == nil {
		t.Fatal("expected a spec naming a different profile to be rejected")
	}
	if !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("expected ErrInvalidSpec, got %v", err)
	}
}

func TestEngine_RejectsAnInvalidSpecBeforeRunningAnything(t *testing.T) {
	e := testEngine(t, "hardened")
	spec := staticSpec("hardened")
	spec.Budget.MaxActions = 0

	if _, err := e.Run(context.Background(), spec); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("expected ErrInvalidSpec, got %v", err)
	}
}

// End-to-end baseline run against the hardened profile. This exercises
// the whole pipeline for real: registry -> generator -> fresh
// environment -> harness.Runner -> oracle -> invariants -> findings.
func TestEngine_StaticBaselineRunsAgainstHardened(t *testing.T) {
	e := testEngine(t, "hardened")
	spec := staticSpec("hardened", harness.AuthzBypassScenarioID, harness.ReplayScenarioID)

	rec, err := e.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(rec.Attempts) != 2 {
		t.Fatalf("attempts = %d, want 2", len(rec.Attempts))
	}
	if rec.StopReason != StopReasonGeneratorExhausted {
		t.Fatalf("stop reason = %q, want generator_exhausted", rec.StopReason)
	}
	if len(rec.Errors) != 0 {
		t.Fatalf("expected no evaluation errors, got %v", rec.Errors)
	}
	for _, a := range rec.Attempts {
		if len(a.Verdicts) == 0 {
			t.Fatalf("attempt %s produced no invariant verdicts", a.TestID)
		}
	}
	if rec.Findings.RawAttempts == 0 {
		t.Fatal("expected the run to produce findings")
	}
	if rec.Reproducibility.ExactReplaySupported {
		t.Fatal("a baseline run includes Go-implemented scenarios and must not claim exact replay")
	}
}

// The differential result this project exists to demonstrate: the same
// registered attack is blocked under hardened and confirmed under
// vulnerable. Both sides are asserted from real runs.
func TestEngine_AuthzBypassIsBlockedHardenedAndConfirmedVulnerable(t *testing.T) {
	verdictFor := func(profileName string) finding.Outcome {
		e := testEngine(t, profileName)
		rec, err := e.Run(context.Background(), staticSpec(profileName, harness.AuthzBypassScenarioID))
		if err != nil {
			t.Fatalf("Run(%s): %v", profileName, err)
		}
		if len(rec.Attempts) != 1 {
			t.Fatalf("Run(%s): attempts = %d, want 1", profileName, len(rec.Attempts))
		}
		for _, f := range rec.Findings.Unique {
			if f.Invariant == "scenario."+harness.AuthzBypassScenarioID {
				return f.Outcome
			}
		}
		t.Fatalf("Run(%s): no finding for the scenario's own adjudication", profileName)
		return ""
	}

	if got := verdictFor("hardened"); got != finding.OutcomeBlocked {
		t.Fatalf("hardened: outcome = %q, want blocked", got)
	}
	if got := verdictFor("vulnerable"); got != finding.OutcomeConfirmedViolation {
		t.Fatalf("vulnerable: outcome = %q, want confirmed_violation", got)
	}
}

// A mutation run must produce genuinely derived candidates: each one
// records what it changed relative to its seed workflow, and carries a
// plan rather than a scenario.
func TestEngine_MutationProducesDerivedCandidatesWithRecordedMutations(t *testing.T) {
	e := testEngine(t, "hardened")

	rec, err := e.Run(context.Background(), mutationSpec("hardened"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(rec.Attempts) == 0 {
		t.Fatal("the mutation generator produced no candidates at all")
	}
	for _, a := range rec.Attempts {
		if len(a.Mutations) == 0 {
			t.Fatalf("attempt %s claims to be a mutation but records no change from its seed", a.TestID)
		}
		if a.Plan == nil {
			t.Fatalf("attempt %s has no recorded plan", a.TestID)
		}
		if a.SourceScenarioID == "" {
			t.Fatalf("attempt %s does not name the seed it derived from", a.TestID)
		}
		if a.ActionsExecuted() == 0 {
			t.Fatalf("attempt %s executed no actions", a.TestID)
		}
	}
	if !rec.Reproducibility.ExactReplaySupported {
		t.Fatal("a run of nothing but recorded plans should support exact replay")
	}
}

// Reproducibility: identical seeds must produce identical candidate
// sequences, or no comparison between runs means anything.
func TestEngine_MutationIsReproducibleUnderTheSameSeed(t *testing.T) {
	ids := func() []string {
		gen, err := NewMutationGenerator(testRegistry(t), mutationSpec("hardened").Effective())
		if err != nil {
			t.Fatalf("NewMutationGenerator: %v", err)
		}
		var out []string
		obs := Observation{Spec: mutationSpec("hardened").Effective(), ActionsRemaining: 100}
		for {
			c, err := gen.Next(context.Background(), obs)
			if errors.Is(err, ErrNoMoreCandidates) {
				break
			}
			if err != nil {
				t.Fatalf("Next: %v", err)
			}
			out = append(out, c.TestID+"|"+planFingerprint(*c.Plan))
		}
		return out
	}

	first, second := ids(), ids()
	if len(first) == 0 {
		t.Fatal("the generator produced nothing")
	}
	if len(first) != len(second) {
		t.Fatalf("same seed produced %d then %d candidates", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("candidate %d differs between runs at the same seed:\n%s\n%s", i, first[i], second[i])
		}
	}
}

func TestEngine_MutationStopsAtTheTestBudget(t *testing.T) {
	e := testEngine(t, "hardened")
	spec := mutationSpec("hardened")
	spec.Budget.MaxTests = 2

	rec, err := e.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(rec.Attempts) != 2 {
		t.Fatalf("attempts = %d, want exactly the 2-test budget", len(rec.Attempts))
	}
	if rec.StopReason != StopReasonTestBudget {
		t.Fatalf("stop reason = %q, want test_budget_exhausted", rec.StopReason)
	}
}

func TestEngine_MutationNeverExceedsTheActionBudget(t *testing.T) {
	e := testEngine(t, "hardened")
	spec := mutationSpec("hardened")
	spec.Budget.MaxActions = 8
	spec.Budget.MaxTests = 20

	rec, err := e.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if rec.ActionsSpent > 8 {
		t.Fatalf("actions spent = %d, which exceeds the budget of 8", rec.ActionsSpent)
	}
}

func TestEngine_StopsOnConfirmedViolationWhenAsked(t *testing.T) {
	e := testEngine(t, "vulnerable")
	spec := staticSpec("vulnerable", harness.AuthzBypassScenarioID, harness.ReplayScenarioID, harness.TamperScenarioID)
	spec.StopConditions = []StopCondition{StopOnConfirmedViolation}

	rec, err := e.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if rec.StopReason != StopReasonConfirmedViolation {
		t.Fatalf("stop reason = %q, want confirmed_violation", rec.StopReason)
	}
	if len(rec.Attempts) != 1 {
		t.Fatalf("attempts = %d, want 1 -- it should have halted on the first confirmed violation", len(rec.Attempts))
	}
}

// Independent trials must not contaminate one another: each candidate
// gets its own environment, so every run starts from an empty ledger.
func TestEngine_EachCandidateGetsAFreshIsolatedEnvironment(t *testing.T) {
	e := testEngine(t, "hardened")
	spec := mutationSpec("hardened")
	spec.Budget.MaxTests = 3

	rec, err := e.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rec.Attempts) < 2 {
		t.Skipf("need at least 2 attempts to compare isolation, got %d", len(rec.Attempts))
	}

	for _, a := range rec.Attempts {
		if a.SnapshotBefore.EntryCount != 0 {
			t.Fatalf("attempt %s started with %d ledger entries -- state leaked from a previous trial",
				a.TestID, a.SnapshotBefore.EntryCount)
		}
	}
}

// A generated action the validator refuses must never reach the
// simulator, and must still be recorded.
func TestEngine_RefusedActionsAreRecordedAndNeverExecuted(t *testing.T) {
	e := testEngine(t, "hardened")
	spec := mutationSpec("hardened")
	// Exclude transfers entirely, so plans containing one have that
	// action refused by policy while the rest still run.
	spec.Safety.AllowedOps = []string{OpCreateAccount, OpDeposit, OpWithdraw, OpBalance, OpHistory}

	rec, err := e.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	sawRefusal := false
	for _, a := range rec.Attempts {
		for _, s := range a.Steps {
			if s.Validation.Decision == DecisionAllow {
				continue
			}
			sawRefusal = true
			if s.Executed {
				t.Fatalf("attempt %s step %d was refused (%s) yet reached the simulator",
					a.TestID, s.Index, s.Validation.Decision)
			}
			if s.Validation.Reason == "" {
				t.Fatalf("attempt %s step %d was refused with no reason recorded", a.TestID, s.Index)
			}
		}
	}
	if !sawRefusal {
		t.Fatal("expected excluding transfers to produce at least one policy refusal")
	}
}

type brokenGenerator struct{ err error }

func (g brokenGenerator) ID() string { return "broken" }
func (g brokenGenerator) Next(context.Context, Observation) (Candidate, error) {
	return Candidate{}, g.err
}

// A generator that fails must never produce a security result. This is
// the "do not trust the generator" rule at the engine level.
func TestEngine_GeneratorErrorIsNotAnAttackSuccess(t *testing.T) {
	e := testEngine(t, "hardened")
	spec := staticSpec("hardened").Effective()

	validator, err := NewValidator(spec)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	_ = validator

	// Drive the loop with a deliberately broken generator by running an
	// experiment whose generator construction we substitute.
	rec := runWithGenerator(t, e, spec, brokenGenerator{err: errors.New("model unavailable")})

	if rec.Findings.ConfirmedViolations != 0 {
		t.Fatalf("a generator failure produced %d confirmed violations", rec.Findings.ConfirmedViolations)
	}
	if rec.StopReason != StopReasonError {
		t.Fatalf("stop reason = %q, want error", rec.StopReason)
	}
	if len(rec.Errors) == 0 {
		t.Fatal("the generator failure must be recorded")
	}
}

func TestEngine_MalformedCandidateNeverReachesExecution(t *testing.T) {
	e := testEngine(t, "hardened")
	spec := staticSpec("hardened").Effective()

	rec := runWithGenerator(t, e, spec, &onceGenerator{cand: Candidate{TestID: "", GeneratorID: "bad"}})

	if len(rec.Attempts) != 0 {
		t.Fatalf("attempts = %d, want 0 -- an unusable candidate must not be executed", len(rec.Attempts))
	}
	if len(rec.Errors) == 0 {
		t.Fatal("the unusable candidate must be recorded as an error")
	}
}

type onceGenerator struct {
	cand Candidate
	done bool
}

func (g *onceGenerator) ID() string { return "once" }
func (g *onceGenerator) Next(context.Context, Observation) (Candidate, error) {
	if g.done {
		return Candidate{}, ErrNoMoreCandidates
	}
	g.done = true
	return g.cand, nil
}

func TestEngine_CancelledContextStopsCleanly(t *testing.T) {
	e := testEngine(t, "hardened")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rec, err := e.Run(ctx, mutationSpec("hardened"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rec.StopReason != StopReasonCancelled {
		t.Fatalf("stop reason = %q, want cancelled", rec.StopReason)
	}
}

func TestEngine_TimeBudgetIsEnforced(t *testing.T) {
	e := testEngine(t, "hardened")
	spec := mutationSpec("hardened")
	spec.Budget.MaxDuration = time.Nanosecond

	rec, err := e.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rec.StopReason != StopReasonTimeBudget {
		t.Fatalf("stop reason = %q, want time_budget_exhausted", rec.StopReason)
	}
}

func TestEngine_RecordSerializesWithItsEvidence(t *testing.T) {
	e := testEngine(t, "hardened")
	rec, err := e.Run(context.Background(), staticSpec("hardened", harness.AuthzBypassScenarioID))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var buf strings.Builder
	if err := rec.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"experiment_id", "stop_reason", "ledger.double-entry", "reproducibility", "findings"} {
		if !strings.Contains(out, want) {
			t.Fatalf("serialized record is missing %q", want)
		}
	}
}

// Nothing in an experiment record may carry key material.
func TestEngine_RecordsCarryNoKeyMaterial(t *testing.T) {
	e := testEngine(t, "vulnerable")
	rec, err := e.Run(context.Background(), staticSpec("vulnerable", harness.KeyExposureScenarioID))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var buf strings.Builder
	if err := rec.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	lower := strings.ToLower(buf.String())

	for _, forbidden := range []string{"private_key", "key_material", "passphrase"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("experiment record contains %q", forbidden)
		}
	}
}

func TestStaticGenerator_PrivilegedScenariosAreExcludedWhenNotAllowed(t *testing.T) {
	reg := testRegistry(t)

	gen, err := NewStaticGenerator(reg, nil, false)
	if err != nil {
		t.Fatalf("NewStaticGenerator: %v", err)
	}
	for _, id := range gen.Selected() {
		if IsPrivilegedScenario(id) {
			t.Fatalf("scenario %q uses the insider bypass and must be excluded when privileged access is not allowed", id)
		}
	}

	withPriv, err := NewStaticGenerator(reg, nil, true)
	if err != nil {
		t.Fatalf("NewStaticGenerator(allowPrivileged): %v", err)
	}
	if len(withPriv.Selected()) <= len(gen.Selected()) {
		t.Fatal("allowing privileged scenarios should admit more scenarios")
	}
}

// Guards the hand-maintained privileged list against registry growth.
func TestStaticGenerator_PrivilegedListMatchesTheRegistry(t *testing.T) {
	reg := testRegistry(t)
	registered := map[string]bool{}
	for _, s := range reg.All() {
		registered[s.ID] = true
	}

	for id := range privilegedScenarios {
		if !registered[id] {
			t.Fatalf("privilegedScenarios names %q, which is not registered", id)
		}
	}
	if len(reg.All()) != 12 {
		t.Fatalf("the registry holds %d scenarios, not the 12 this list was reviewed against -- re-check which of them use env.Priv", len(reg.All()))
	}
}

func TestStaticGenerator_RejectsAnUnregisteredScenario(t *testing.T) {
	if _, err := NewStaticGenerator(testRegistry(t), []string{"no-such-attack"}, true); err == nil {
		t.Fatal("expected an unregistered scenario name to be rejected")
	}
}

func TestMutationGenerator_RejectsAnUnknownSeedWorkflow(t *testing.T) {
	spec := mutationSpec("hardened")
	spec.SeedScenarios = []string{"not-a-workflow"}

	if _, err := NewMutationGenerator(testRegistry(t), spec.Effective()); err == nil {
		t.Fatal("expected an unknown seed workflow to be rejected rather than skipped")
	}
}

// runWithGenerator drives the engine's evaluation loop with a
// substituted generator, so generator-failure paths can be tested
// without a real one that misbehaves.
func runWithGenerator(t *testing.T, e *Engine, spec ExperimentSpec, gen Generator) Record {
	t.Helper()

	validator, err := NewValidator(spec)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return e.runLoop(context.Background(), spec, gen, validator)
}

var _ = config.SecurityProfile{}

// Pins a result that is correct but easy to misread, so nobody has to
// rediscover it from a report: the ledger-tamper scenario writes
// beneath the application through the privileged insider channel, so
// the ledger genuinely ends up unbalanced under the HARDENED profile
// too. What hardening changes is that the tampering is detected -- which
// shows up as the scenario's own finding being blocked, not as the
// state invariant holding. Both findings together are the real result;
// either one alone misrepresents it.
func TestEngine_LedgerTamperUnbalancesTheLedgerEvenWhenDetected(t *testing.T) {
	e := testEngine(t, "hardened")

	rec, err := e.Run(context.Background(), staticSpec("hardened", harness.LedgerTamperScenarioID))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var stateOutcome, scenarioOutcome finding.Outcome
	for _, f := range rec.Findings.Unique {
		switch f.Invariant {
		case "ledger.double-entry":
			stateOutcome = f.Outcome
		case "scenario." + harness.LedgerTamperScenarioID:
			scenarioOutcome = f.Outcome
		}
	}

	if stateOutcome != finding.OutcomeConfirmedViolation {
		t.Fatalf("ledger.double-entry = %q, want confirmed_violation: a privileged write really does unbalance the ledger", stateOutcome)
	}
	if scenarioOutcome != finding.OutcomeBlocked {
		t.Fatalf("scenario.%s = %q, want blocked: hardening detects the tampering", harness.LedgerTamperScenarioID, scenarioOutcome)
	}
}
