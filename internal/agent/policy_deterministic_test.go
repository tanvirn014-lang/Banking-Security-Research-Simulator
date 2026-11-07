package agent

import (
	"errors"
	"testing"

	"banksec-lab/internal/domain"
)

func TestDeterministicPolicy_SameObservation_SameAction(t *testing.T) {
	kinds := []ActionKind{"attack-a", "attack-b", "attack-c"}
	obs := Observation{VisibleAccounts: []domain.AccountID{"acct-1"}}

	p1 := NewDeterministicPolicy(kinds)
	a1, err := p1.Decide(obs)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}

	p2 := NewDeterministicPolicy(kinds)
	a2, err := p2.Decide(obs)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}

	if a1 != a2 {
		t.Fatalf("expected two freshly-constructed policies given the same Observation to decide the same Action, got %+v then %+v", a1, a2)
	}
	if a1.Kind != "attack-a" || a1.Target != "acct-1" {
		t.Fatalf("expected the first fixed-order action against the first visible account, got %+v", a1)
	}
}

func TestDeterministicPolicy_ExhaustsActionsInFixedOrder(t *testing.T) {
	kinds := []ActionKind{"attack-a", "attack-b"}
	obs := Observation{VisibleAccounts: []domain.AccountID{"acct-1"}}
	p := NewDeterministicPolicy(kinds)

	a1, err := p.Decide(obs)
	if err != nil {
		t.Fatalf("Decide #1: %v", err)
	}
	a2, err := p.Decide(obs)
	if err != nil {
		t.Fatalf("Decide #2: %v", err)
	}
	if a1.Kind != "attack-a" || a2.Kind != "attack-b" {
		t.Fatalf("expected actions in fixed order attack-a then attack-b, got %q then %q", a1.Kind, a2.Kind)
	}

	if _, err := p.Decide(obs); !errors.Is(err, ErrNoActionsRemain) {
		t.Fatalf("expected ErrNoActionsRemain once every (target,kind) pair has been tried, got %v", err)
	}
}

func TestDeterministicPolicy_ExhaustionIsPerKindNotPerTarget(t *testing.T) {
	// A second Decide call, even against a newly-appeared, different
	// first-visible-account, must NOT re-offer an already-tried
	// ActionKind -- exhaustion tracks the ActionKind alone. (A per
	// -target scheme was tried during development and reverted: see
	// DeterministicPolicy's own doc comment for the real Detection
	// -Engine-dedup interaction it caused.)
	kinds := []ActionKind{"attack-a"}
	p := NewDeterministicPolicy(kinds)

	obs1 := Observation{VisibleAccounts: []domain.AccountID{"acct-1"}}
	a1, err := p.Decide(obs1)
	if err != nil {
		t.Fatalf("Decide against acct-1: %v", err)
	}
	if a1.Target != "acct-1" || a1.Kind != "attack-a" {
		t.Fatalf("expected attack-a against acct-1, got %+v", a1)
	}

	obs2 := Observation{VisibleAccounts: []domain.AccountID{"acct-2"}}
	if _, err := p.Decide(obs2); !errors.Is(err, ErrNoActionsRemain) {
		t.Fatalf("expected ErrNoActionsRemain: attack-a was already tried, regardless of the new target acct-2, got %v", err)
	}
}

func TestDeterministicPolicy_TargetTracksCurrentFirstVisibleAccount(t *testing.T) {
	// Each Decide call's Action.Target reflects whatever is CURRENTLY
	// obs.VisibleAccounts[0] -- the Policy is reactive to its argument
	// every call, even though exhaustion itself is tracked per-kind.
	kinds := []ActionKind{"attack-a", "attack-b"}
	p := NewDeterministicPolicy(kinds)

	a1, err := p.Decide(Observation{VisibleAccounts: []domain.AccountID{"acct-1"}})
	if err != nil {
		t.Fatalf("Decide #1: %v", err)
	}
	a2, err := p.Decide(Observation{VisibleAccounts: []domain.AccountID{"acct-2"}})
	if err != nil {
		t.Fatalf("Decide #2: %v", err)
	}
	if a1.Target != "acct-1" || a2.Target != "acct-2" {
		t.Fatalf("expected each decision's Target to track the CURRENT first visible account, got %+v then %+v", a1, a2)
	}
}

func TestDeterministicPolicy_NoVisibleAccountsStillPicksAnAction(t *testing.T) {
	// Before any scenario has created an account yet, VisibleAccounts is
	// empty -- the policy must still make progress (every Milestone 8
	// scenario creates its own account fixture internally), targeting
	// the zero-value AccountID.
	kinds := []ActionKind{"attack-a"}
	p := NewDeterministicPolicy(kinds)
	a, err := p.Decide(Observation{})
	if err != nil {
		t.Fatalf("Decide with no visible accounts: %v", err)
	}
	if a.Kind != "attack-a" || a.Target != "" {
		t.Fatalf("expected attack-a with a zero-value target, got %+v", a)
	}
}
