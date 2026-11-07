package agent

import (
	"testing"

	"banksec-lab/internal/domain"
)

// TestObservation_OnlyExposesDeclaredVisibility confirms Observation's
// zero value starts with nothing visible: an agent only ever sees what
// buildObservation (agent.go) explicitly populates from the Oracle, not
// some ambient default.
func TestObservation_OnlyExposesDeclaredVisibility(t *testing.T) {
	var obs Observation
	if len(obs.VisibleAccounts) != 0 {
		t.Fatalf("expected a zero-value Observation to have no visible accounts, got %v", obs.VisibleAccounts)
	}
	if len(obs.VisibleBalances) != 0 {
		t.Fatalf("expected a zero-value Observation to have no visible balances, got %v", obs.VisibleBalances)
	}
	if len(obs.RecentAudit) != 0 {
		t.Fatalf("expected a zero-value Observation to have no recent audit events, got %v", obs.RecentAudit)
	}
}

func TestAction_CarriesKindAndTarget(t *testing.T) {
	a := Action{Kind: ActionKind("ledger-tamper"), Target: domain.AccountID("acct-1")}
	if a.Kind != "ledger-tamper" {
		t.Fatalf("expected Kind to round-trip, got %q", a.Kind)
	}
	if a.Target != "acct-1" {
		t.Fatalf("expected Target to round-trip, got %q", a.Target)
	}
}
