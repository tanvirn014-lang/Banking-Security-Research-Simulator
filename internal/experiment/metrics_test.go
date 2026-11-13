package experiment

import (
	"context"
	"strings"
	"testing"

	"banksec-lab/internal/finding"
	"banksec-lab/internal/harness"
)

// The division-by-zero case the prompt calls out explicitly: an
// experiment that found nothing must report undefined ratios, not zeros.
func TestMetrics_NoFindingsLeavesRatiosUndefinedNotZero(t *testing.T) {
	m := MetricsOf(Record{})

	if m.FindingYieldPerAction != nil {
		t.Fatalf("finding yield = %v, want undefined with no actions spent", *m.FindingYieldPerAction)
	}
	if m.CostPerConfirmedFindingMS != nil {
		t.Fatalf("cost per finding = %v, want undefined with no findings", *m.CostPerConfirmedFindingMS)
	}
	if m.VerificationRate != nil {
		t.Fatalf("verification rate = %v, want undefined with nothing evaluated", *m.VerificationRate)
	}
	if m.InvariantCoverage != nil {
		t.Fatalf("invariant coverage = %v, want undefined with no invariant evaluated", *m.InvariantCoverage)
	}
	if m.BenignTaskSuccessRate != nil {
		t.Fatalf("benign task rate = %v, want undefined with no benign operation submitted", *m.BenignTaskSuccessRate)
	}
}

func TestMetrics_RatiosUseTheDocumentedDefinitions(t *testing.T) {
	rec := Record{
		Spec:          ExperimentSpec{ExperimentID: "exp", TargetProfile: "hardened", Budget: Budget{MaxActions: 20}},
		GeneratorID:   "mutation",
		TestsProduced: 4,
		ActionsSpent:  10,
		DurationMS:    500,
		Findings: finding.Set{
			RawAttempts:         8,
			ConfirmedViolations: 3,
			Blocked:             3,
			Inconclusive:        2,
			Unique: []finding.Finding{
				{ID: "a", Outcome: finding.OutcomeConfirmedViolation},
				{ID: "b", Outcome: finding.OutcomeConfirmedViolation},
				{ID: "c", Outcome: finding.OutcomeBlocked},
			},
		},
	}

	m := MetricsOf(rec)

	if m.UniqueConfirmedFindings != 2 {
		t.Fatalf("unique confirmed = %d, want 2 (only confirmed violations among unique findings)", m.UniqueConfirmedFindings)
	}
	if got := *m.FindingYieldPerAction; got != 0.2 {
		t.Fatalf("finding yield = %v, want 2/10", got)
	}
	if got := *m.VerificationRate; got != 0.75 {
		t.Fatalf("verification rate = %v, want (3+3)/8", got)
	}
	if got := *m.CostPerConfirmedFindingMS; got != 250 {
		t.Fatalf("cost per finding = %v, want 500/2", got)
	}
	// Raw attempts and unique findings must stay separate.
	if m.ConfirmedViolations == m.UniqueConfirmedFindings {
		t.Fatal("raw confirmed violations and unique confirmed findings must be reported as different figures")
	}
}

func TestMetrics_InvariantCoverageCountsOnlyConclusiveVerdicts(t *testing.T) {
	rec := Record{
		Attempts: []Attempt{{
			Verdicts: []VerdictRecord{
				{Invariant: "a", Outcome: finding.OutcomeBlocked},
				{Invariant: "b", Outcome: finding.OutcomeInconclusive},
				{Invariant: "c", Outcome: finding.OutcomeConfirmedViolation},
				{Invariant: "d", Outcome: finding.OutcomeError},
			},
		}},
	}

	got := *MetricsOf(rec).InvariantCoverage
	if got != 0.5 {
		t.Fatalf("invariant coverage = %v, want 2/4 -- only blocked and confirmed are conclusive", got)
	}
}

func TestMetrics_BenignTaskRateCountsOwnersActingOnTheirOwnAccounts(t *testing.T) {
	steps := []Step{
		step(0, Action{Op: OpCreateAccount, Actor: owner("alice"), Params: map[string]string{"owner": "alice"}}, true, map[string]string{"account": "acct-1"}),
		// benign and accepted
		step(1, Action{Op: OpDeposit, Actor: owner("alice"), Params: map[string]string{"account": "acct-1", "amount": "100"}}, true, nil),
		// benign and refused
		step(2, Action{Op: OpWithdraw, Actor: owner("alice"), Params: map[string]string{"account": "acct-1", "amount": "999999"}}, false, nil),
		// not benign: a different actor, so excluded from the rate
		step(3, Action{Op: OpWithdraw, Actor: owner("mallory"), Params: map[string]string{"account": "acct-1", "amount": "10"}}, false, nil),
	}

	got := *MetricsOf(Record{Attempts: []Attempt{{Steps: steps}}}).BenignTaskSuccessRate
	// create-account + accepted deposit = 2 of 3 benign operations.
	if got < 0.66 || got > 0.67 {
		t.Fatalf("benign task success rate = %v, want 2/3", got)
	}
}

func TestCompare_FlagsDifferentBudgetsAsIncomparable(t *testing.T) {
	a := Record{Spec: ExperimentSpec{ExperimentID: "a", TargetProfile: "hardened", Budget: Budget{MaxActions: 20}}, GeneratorID: "static"}
	b := Record{Spec: ExperimentSpec{ExperimentID: "b", TargetProfile: "hardened", Budget: Budget{MaxActions: 100}}, GeneratorID: "mutation"}

	c := Compare(a, b)

	if c.Comparable {
		t.Fatal("two runs at different action budgets must not be reported as comparable")
	}
	if !strings.Contains(strings.Join(c.Caveats, " "), "action budget") {
		t.Fatalf("expected the caveat to name the budget mismatch, got %v", c.Caveats)
	}
}

func TestCompare_FlagsDifferentConfigurationsAsIncomparable(t *testing.T) {
	a := Record{Spec: ExperimentSpec{ExperimentID: "a", TargetProfile: "hardened", Budget: Budget{MaxActions: 20}}}
	b := Record{Spec: ExperimentSpec{ExperimentID: "b", TargetProfile: "vulnerable", Budget: Budget{MaxActions: 20}}}

	if Compare(a, b).Comparable {
		t.Fatal("runs against different security configurations must not be reported as comparable")
	}
}

func TestCompare_EquivalentRunsAreComparable(t *testing.T) {
	a := Record{Spec: ExperimentSpec{ExperimentID: "a", TargetProfile: "hardened", Budget: Budget{MaxActions: 20}}, GeneratorID: "static", StopReason: StopReasonGeneratorExhausted}
	b := Record{Spec: ExperimentSpec{ExperimentID: "b", TargetProfile: "hardened", Budget: Budget{MaxActions: 20}}, GeneratorID: "mutation", StopReason: StopReasonTestBudget}

	c := Compare(a, b)
	if !c.Comparable {
		t.Fatalf("expected equivalent runs to be comparable, caveats: %v", c.Caveats)
	}
}

func TestCompare_ASingleConditionIsNotAComparison(t *testing.T) {
	if Compare(Record{}).Comparable {
		t.Fatal("one condition is not a comparison")
	}
}

func TestCompare_NotesAnEarlyStop(t *testing.T) {
	a := Record{Spec: ExperimentSpec{ExperimentID: "a", TargetProfile: "hardened", Budget: Budget{MaxActions: 20}}, StopReason: StopReasonGeneratorExhausted}
	b := Record{Spec: ExperimentSpec{ExperimentID: "b", TargetProfile: "hardened", Budget: Budget{MaxActions: 20}}, StopReason: StopReasonError}

	c := Compare(a, b)
	if !strings.Contains(strings.Join(c.Caveats, " "), "stopped early") {
		t.Fatalf("expected a caveat about the early stop, got %v", c.Caveats)
	}
}

// Replay must distinguish exact replay from re-execution rather than
// claiming a reproducibility figure it cannot support.
func TestReplay_BaselineRecordsAreNotClaimedAsReplayable(t *testing.T) {
	e := testEngine(t, "vulnerable")
	rec, err := e.Run(context.Background(), staticSpec("vulnerable", harness.AuthzBypassScenarioID))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	m, err := e.Replay(context.Background(), rec)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if m.ReproducibilityRate != nil {
		t.Fatalf("reproducibility rate = %v, want undefined for a record of Go-implemented scenarios", *m.ReproducibilityRate)
	}
	if !strings.Contains(m.ReproducibilityNote, "baseline") {
		t.Fatalf("the note should explain why nothing was replayed, got %q", m.ReproducibilityNote)
	}
}

func TestReplay_RejectsARecordFromAnotherProfile(t *testing.T) {
	e := testEngine(t, "hardened")
	rec := Record{Spec: ExperimentSpec{
		ExperimentID: "x", Objective: "y", TargetProfile: "vulnerable",
		Generator: GeneratorStatic, Budget: Budget{MaxActions: 1, MaxTests: 1},
	}}

	if _, err := e.Replay(context.Background(), rec); err == nil {
		t.Fatal("expected replaying another profile's record to be rejected")
	}
}

// End-to-end: a mutation run's confirmed findings replay from the
// record alone.
func TestReplay_MutationFindingsReproduceFromTheRecord(t *testing.T) {
	e := testEngine(t, "vulnerable")
	spec := mutationSpec("vulnerable")

	rec, err := e.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	m, err := e.Replay(context.Background(), rec)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if m.ReplayedFindings == 0 {
		t.Skipf("this run confirmed nothing to replay (stop reason %s); nothing to assert", rec.StopReason)
	}
	if m.ReproducibilityRate == nil {
		t.Fatal("a run with replayable findings must report a reproducibility rate")
	}
	if *m.ReproducibilityRate != 1.0 {
		t.Fatalf("reproducibility rate = %v, want 1.0 -- a deterministic plan replayed on a fresh environment should reproduce",
			*m.ReproducibilityRate)
	}
}
