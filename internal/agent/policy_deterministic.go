package agent

import "banksec-lab/internal/domain"

// DeterministicPolicy is this package's required baseline Policy: a
// rule-based (NOT learning -- see docs/IMPLEMENTATION_PLAN.md's
// infeasibility note on Milestone 10's "adaptive execution") agent that
// reacts to its current Observation by picking the next unexplored
// ActionKind, in a fixed order, targeted at whichever account is
// obs.VisibleAccounts[0] AT THE TIME of that decision (or the zero-value
// domain.AccountID when no account is visible yet -- expected before the
// first scenario has created one). "Reactive" means Decide branches on
// its Observation argument every call (the Target it attaches can
// change from one Decide call to the next as new accounts appear);
// "adaptive" does NOT mean it learns or improves across runs -- a fresh
// NewDeterministicPolicy call starts with entirely fresh exhausted-kind
// tracking every time, by design.
//
// Exhaustion is tracked per ActionKind only, NOT per (target, kind) --
// each registered attack is attempted exactly once per Policy instance,
// deliberately. A per-target tracking scheme was tried during
// development and discarded: every Milestone 8 scenario is
// self-contained (it creates its own account fixture internally,
// ignoring Action.Target -- see Action's own doc comment) and several
// use a FIXED, non-unique offending-entity ID (e.g.
// NewLedgerTamperScenario's hardcoded ledger TxID); re-running the SAME
// scenario a second time against the SAME shared Environment collides
// with the Detection Engine's own per-entity dedup latch and reports a
// false "undetected" the second time -- not a bug in the scenario or
// the Detection Engine (each was only ever tested in isolation, one
// fresh Environment per scenario, in Milestone 8), but a real
// interaction this Policy's simpler, literal "next unexplored
// ActionKind" semantics (as specified) avoids entirely by construction,
// since it never runs the same ActionKind twice.
//
// Per the user's explicit "do not present a deterministic baseline as
// an advanced AI agent" requirement: this is exactly what its name says
// it is, nothing more. See docs/AGENT_LLM_INTEGRATION.md for what a
// genuinely adaptive, LLM-backed Policy would need instead.
type DeterministicPolicy struct {
	actionKinds []ActionKind
	tried       map[ActionKind]bool
}

// NewDeterministicPolicy constructs a DeterministicPolicy that tries
// each of actionKinds exactly once, in the given order.
func NewDeterministicPolicy(actionKinds []ActionKind) *DeterministicPolicy {
	kinds := append([]ActionKind(nil), actionKinds...)
	return &DeterministicPolicy{actionKinds: kinds, tried: make(map[ActionKind]bool)}
}

func (p *DeterministicPolicy) Decide(obs Observation) (Action, error) {
	target := targetAccount(obs)
	for _, kind := range p.actionKinds {
		if !p.tried[kind] {
			p.tried[kind] = true
			return Action{Kind: kind, Target: target}, nil
		}
	}
	return Action{}, ErrNoActionsRemain
}

// targetAccount returns obs's first visible account, or the zero-value
// domain.AccountID when none is visible yet.
func targetAccount(obs Observation) domain.AccountID {
	if len(obs.VisibleAccounts) == 0 {
		return ""
	}
	return obs.VisibleAccounts[0]
}
