package agent

import (
	"context"
	"testing"

	"banksec-lab/internal/config"
	"banksec-lab/internal/harness"
)

// TestControlledExperiment_BaselineAgentAgainstRealScenarios is this
// package's "evaluate the baseline agent using controlled experiments"
// deliverable: the SAME DeterministicPolicy-driven Agent, with the same
// two real, registered Milestone 8 scenarios available
// (ledger-tamper, audit-tamper), run once against a hardened
// Environment and once against a vulnerable one -- a genuine controlled
// experiment (one variable changed: the profile), not a mechanical
// smoke test. Both scenarios' own Verify defines Success as "the tamper
// went UNDETECTED" (the attacker's perspective), so the hardened run
// must report zero successful compromises (the Detection Engine catches
// both) while the vulnerable run reports both as successful (nothing
// is watching) -- a real, falsifiable, scientifically meaningful
// prediction this test actually checks, not just "it ran without
// crashing."
func TestControlledExperiment_BaselineAgentAgainstRealScenarios(t *testing.T) {
	kinds := []ActionKind{
		ActionKind(harness.LedgerTamperScenarioID),
		ActionKind(harness.AuditTamperScenarioID),
	}

	runExperiment := func(t *testing.T, configPath string) AgentReport {
		t.Helper()
		profile, err := config.Load(configPath)
		if err != nil {
			t.Fatalf("config.Load(%s): %v", configPath, err)
		}
		env, err := harness.NewLocalEnvironment(profile)
		if err != nil {
			t.Fatalf("NewLocalEnvironment: %v", err)
		}
		defer env.Close()

		reg := harness.NewRegistry()
		if err := harness.RegisterAllScenarios(reg); err != nil {
			t.Fatalf("RegisterAllScenarios: %v", err)
		}

		policy := NewDeterministicPolicy(kinds)
		a := NewAgent(policy, kinds, reg, env, 2)
		runner := harness.NewRunner()

		results, report, err := a.Run(context.Background(), runner, 1)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("expected exactly 2 results (one per scenario), got %d", len(results))
		}
		return report
	}

	t.Run("hardened", func(t *testing.T) {
		report := runExperiment(t, "../../configs/hardened.json")
		if report.Attempts != 2 {
			t.Fatalf("expected Attempts=2, got %d", report.Attempts)
		}
		if report.SuccessfulCompromises != 0 {
			t.Fatalf("expected 0 successful compromises under hardened (both tampers should be detected), got %d", report.SuccessfulCompromises)
		}
		if report.TimeToCompromiseMS != nil {
			t.Fatalf("expected TimeToCompromiseMS to be nil when nothing was compromised, got %v", *report.TimeToCompromiseMS)
		}
		if report.ObservationCount != 2 || report.ActionCallCount != 2 {
			t.Fatalf("expected ObservationCount=2 and ActionCallCount=2, got %+v", report)
		}
		if report.ComputationalCostMS < 0 {
			t.Fatalf("expected a non-negative ComputationalCostMS, got %d", report.ComputationalCostMS)
		}
	})

	t.Run("vulnerable", func(t *testing.T) {
		report := runExperiment(t, "../../configs/vulnerable.json")
		if report.SuccessfulCompromises != 2 {
			t.Fatalf("expected 2 successful compromises under vulnerable (nothing is watching), got %d", report.SuccessfulCompromises)
		}
		if report.TimeToCompromiseMS == nil {
			t.Fatalf("expected a non-nil TimeToCompromiseMS once a compromise occurred")
		}
	})
}
