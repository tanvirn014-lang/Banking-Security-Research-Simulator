package experiment

import (
	"testing"

	"banksec-lab/internal/config"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/finding"
)

func loadProfile(t *testing.T, name string) config.SecurityProfile {
	t.Helper()
	p, err := config.Load("../../configs/" + name + ".json")
	if err != nil {
		t.Fatalf("config.Load(%s): %v", name, err)
	}
	return p
}

func owner(id string) domain.Principal {
	return domain.Principal{ID: domain.PrincipalID(id), Role: domain.RoleAccountOwner}
}

// step builds an executed, allowed step with the given response verdict.
func step(i int, a Action, ok bool, data map[string]string) Step {
	return Step{
		Index:        i,
		Action:       a,
		Validation:   ValidationResult{Decision: DecisionAllow},
		Executed:     true,
		ResponseOK:   ok,
		ResponseData: data,
	}
}

func invariantByID(t *testing.T, id string) Invariant {
	t.Helper()
	for _, inv := range CoreInvariants() {
		if inv.ID == id {
			return inv
		}
	}
	t.Fatalf("no core invariant with id %q", id)
	return Invariant{}
}

func TestInvariants_EveryCoreInvariantIsFullyDescribed(t *testing.T) {
	invs := CoreInvariants()
	if len(invs) == 0 {
		t.Fatal("expected at least one core invariant")
	}
	seen := map[string]bool{}
	for _, inv := range invs {
		if inv.ID == "" || inv.Description == "" || inv.Component == "" {
			t.Fatalf("invariant %+v must name itself, describe itself, and name its component", inv)
		}
		if inv.Severity == "" {
			t.Fatalf("invariant %q must declare the severity a violation of it carries", inv.ID)
		}
		if inv.Check == nil {
			t.Fatalf("invariant %q has no check", inv.ID)
		}
		if seen[inv.ID] {
			t.Fatalf("duplicate invariant id %q", inv.ID)
		}
		seen[inv.ID] = true
	}
}

// Known-negative fixture: the double-entry invariant held, and actions
// did exercise it. That must read as blocked, never as a violation.
func TestInvariant_DoubleEntry_KnownNegative(t *testing.T) {
	inv := invariantByID(t, "ledger.double-entry")

	got := inv.Check(InvariantInput{
		Profile: loadProfile(t, "hardened"),
		Before:  Snapshot{EntryCount: 0, InvariantOK: true},
		After:   Snapshot{EntryCount: 2, InvariantOK: true},
		Steps: []Step{
			step(0, Action{Op: OpDeposit, Actor: owner("alice"), Params: map[string]string{"account": "acct-1", "amount": "100"}}, true, nil),
		},
	})

	if got.Outcome != finding.OutcomeBlocked {
		t.Fatalf("outcome = %q (%s), want blocked -- the invariant held", got.Outcome, got.Detail)
	}
}

// Known-positive fixture: the oracle itself reports the ledger
// unbalanced. That is a confirmed violation.
func TestInvariant_DoubleEntry_KnownPositive(t *testing.T) {
	inv := invariantByID(t, "ledger.double-entry")

	got := inv.Check(InvariantInput{
		Profile: loadProfile(t, "vulnerable"),
		Before:  Snapshot{EntryCount: 2, InvariantOK: true},
		After:   Snapshot{EntryCount: 3, InvariantOK: false},
		Steps: []Step{
			step(0, Action{Op: OpDeposit, Actor: owner("alice"), Params: map[string]string{"account": "acct-1", "amount": "100"}}, true, nil),
		},
	})

	if got.Outcome != finding.OutcomeConfirmedViolation {
		t.Fatalf("outcome = %q (%s), want confirmed_violation", got.Outcome, got.Detail)
	}
	if got.Evidence == nil {
		t.Fatal("a confirmed violation must carry the evidence it was concluded from")
	}
}

// Nothing exercised the invariant, so there is nothing to conclude.
// Reporting "blocked" here would claim a control worked when it was
// never tested.
func TestInvariant_DoubleEntry_NoMutationIsInconclusive(t *testing.T) {
	inv := invariantByID(t, "ledger.double-entry")

	got := inv.Check(InvariantInput{
		Profile: loadProfile(t, "hardened"),
		Before:  Snapshot{InvariantOK: true},
		After:   Snapshot{InvariantOK: true},
		Steps: []Step{
			step(0, Action{Op: OpBalance, Actor: owner("alice"), Params: map[string]string{"account": "acct-1"}}, true, nil),
		},
	})

	if got.Outcome != finding.OutcomeInconclusive {
		t.Fatalf("outcome = %q (%s), want inconclusive -- no state-changing action ran", got.Outcome, got.Detail)
	}
}

// The headline authorization property. A withdrawal by someone who does
// not own the account, which the simulator accepted, is a confirmed
// violation.
func TestInvariant_ValueExtraction_KnownPositive(t *testing.T) {
	inv := invariantByID(t, "authz.no-unauthorized-value-extraction")

	got := inv.Check(InvariantInput{
		Profile: loadProfile(t, "vulnerable"),
		Before:  Snapshot{EntryCount: 2, InvariantOK: true},
		After:   Snapshot{EntryCount: 4, InvariantOK: true},
		Steps: []Step{
			step(0, Action{Op: OpCreateAccount, Actor: owner("alice"), Params: map[string]string{"owner": "alice"}}, true, map[string]string{"account": "acct-1"}),
			step(1, Action{Op: OpWithdraw, Actor: owner("mallory"), Params: map[string]string{"account": "acct-1", "amount": "100"}}, true, nil),
		},
	})

	if got.Outcome != finding.OutcomeConfirmedViolation {
		t.Fatalf("outcome = %q (%s), want confirmed_violation", got.Outcome, got.Detail)
	}
}

// The same attempt, refused by the simulator. This is the case that
// must never be counted as a vulnerability.
func TestInvariant_ValueExtraction_RefusedAttemptIsBlocked(t *testing.T) {
	inv := invariantByID(t, "authz.no-unauthorized-value-extraction")

	got := inv.Check(InvariantInput{
		Profile: loadProfile(t, "hardened"),
		Before:  Snapshot{EntryCount: 2, InvariantOK: true},
		After:   Snapshot{EntryCount: 2, InvariantOK: true},
		Steps: []Step{
			step(0, Action{Op: OpCreateAccount, Actor: owner("alice"), Params: map[string]string{"owner": "alice"}}, true, map[string]string{"account": "acct-1"}),
			step(1, Action{Op: OpWithdraw, Actor: owner("mallory"), Params: map[string]string{"account": "acct-1", "amount": "100"}}, false, nil),
		},
	})

	if got.Outcome != finding.OutcomeBlocked {
		t.Fatalf("outcome = %q (%s), want blocked -- the system refused the unauthorized withdrawal", got.Outcome, got.Detail)
	}
}

// An owner withdrawing from their own account is not an attack at all.
func TestInvariant_ValueExtraction_OwnerActingOnOwnAccountIsInconclusive(t *testing.T) {
	inv := invariantByID(t, "authz.no-unauthorized-value-extraction")

	got := inv.Check(InvariantInput{
		Profile: loadProfile(t, "hardened"),
		Before:  Snapshot{InvariantOK: true},
		After:   Snapshot{InvariantOK: true},
		Steps: []Step{
			step(0, Action{Op: OpCreateAccount, Actor: owner("alice"), Params: map[string]string{"owner": "alice"}}, true, map[string]string{"account": "acct-1"}),
			step(1, Action{Op: OpWithdraw, Actor: owner("alice"), Params: map[string]string{"account": "acct-1", "amount": "100"}}, true, nil),
		},
	})

	if got.Outcome != finding.OutcomeInconclusive {
		t.Fatalf("outcome = %q (%s), want inconclusive -- no cross-actor extraction was attempted", got.Outcome, got.Detail)
	}
}

// Ownership is only known for accounts this trace created. Acting on an
// account of unknown provenance cannot be adjudicated either way.
func TestInvariant_ValueExtraction_UnknownOwnershipIsInconclusive(t *testing.T) {
	inv := invariantByID(t, "authz.no-unauthorized-value-extraction")

	got := inv.Check(InvariantInput{
		Profile: loadProfile(t, "vulnerable"),
		Before:  Snapshot{InvariantOK: true},
		After:   Snapshot{InvariantOK: true},
		Steps: []Step{
			step(0, Action{Op: OpWithdraw, Actor: owner("mallory"), Params: map[string]string{"account": "acct-unknown", "amount": "100"}}, true, nil),
		},
	})

	if got.Outcome != finding.OutcomeInconclusive {
		t.Fatalf("outcome = %q (%s), want inconclusive -- this trace never established who owns acct-unknown", got.Outcome, got.Detail)
	}
}

func TestInvariant_ValueExtraction_TransferIsJudgedOnTheDebitedAccount(t *testing.T) {
	inv := invariantByID(t, "authz.no-unauthorized-value-extraction")

	got := inv.Check(InvariantInput{
		Profile: loadProfile(t, "vulnerable"),
		Before:  Snapshot{EntryCount: 2, InvariantOK: true},
		After:   Snapshot{EntryCount: 4, InvariantOK: true},
		Steps: []Step{
			step(0, Action{Op: OpCreateAccount, Actor: owner("alice"), Params: map[string]string{"owner": "alice"}}, true, map[string]string{"account": "acct-1"}),
			step(1, Action{Op: OpCreateAccount, Actor: owner("mallory"), Params: map[string]string{"owner": "mallory"}}, true, map[string]string{"account": "acct-2"}),
			step(2, Action{Op: OpTransfer, Actor: owner("mallory"), Params: map[string]string{"from": "acct-1", "to": "acct-2", "amount": "100"}}, true, nil),
		},
	})

	if got.Outcome != finding.OutcomeConfirmedViolation {
		t.Fatalf("outcome = %q (%s), want confirmed_violation -- mallory debited alice's account", got.Outcome, got.Detail)
	}
}

// A deposit into an account you do not own moves value in, not out. It
// is not value extraction and must not be reported as one.
func TestInvariant_ValueExtraction_DepositIntoAnotherAccountIsNotExtraction(t *testing.T) {
	inv := invariantByID(t, "authz.no-unauthorized-value-extraction")

	got := inv.Check(InvariantInput{
		Profile: loadProfile(t, "vulnerable"),
		Before:  Snapshot{InvariantOK: true},
		After:   Snapshot{EntryCount: 2, InvariantOK: true},
		Steps: []Step{
			step(0, Action{Op: OpCreateAccount, Actor: owner("alice"), Params: map[string]string{"owner": "alice"}}, true, map[string]string{"account": "acct-1"}),
			step(1, Action{Op: OpDeposit, Actor: owner("mallory"), Params: map[string]string{"account": "acct-1", "amount": "100"}}, true, nil),
		},
	})

	if got.Outcome == finding.OutcomeConfirmedViolation {
		t.Fatalf("a deposit into another account is not value extraction, got %q (%s)", got.Outcome, got.Detail)
	}
}

func TestInvariant_RejectedOperationHasNoEffect_KnownPositive(t *testing.T) {
	inv := invariantByID(t, "ledger.rejected-operation-no-effect")

	got := inv.Check(InvariantInput{
		Profile: loadProfile(t, "vulnerable"),
		Before:  Snapshot{EntryCount: 2, InvariantOK: true},
		After:   Snapshot{EntryCount: 4, InvariantOK: true},
		Steps: []Step{
			step(0, Action{Op: OpWithdraw, Actor: owner("mallory"), Params: map[string]string{"account": "acct-1", "amount": "100"}}, false, nil),
		},
	})

	if got.Outcome != finding.OutcomeConfirmedViolation {
		t.Fatalf("outcome = %q (%s), want confirmed_violation -- every mutation was refused yet the ledger grew", got.Outcome, got.Detail)
	}
}

func TestInvariant_RejectedOperationHasNoEffect_KnownNegative(t *testing.T) {
	inv := invariantByID(t, "ledger.rejected-operation-no-effect")

	got := inv.Check(InvariantInput{
		Profile: loadProfile(t, "hardened"),
		Before:  Snapshot{EntryCount: 2, InvariantOK: true},
		After:   Snapshot{EntryCount: 2, InvariantOK: true},
		Steps: []Step{
			step(0, Action{Op: OpWithdraw, Actor: owner("mallory"), Params: map[string]string{"account": "acct-1", "amount": "100"}}, false, nil),
		},
	})

	if got.Outcome != finding.OutcomeBlocked {
		t.Fatalf("outcome = %q (%s), want blocked", got.Outcome, got.Detail)
	}
}

// With a mix of accepted and refused mutations, a ledger change cannot
// be attributed to the refused one. Saying so is the honest answer.
func TestInvariant_RejectedOperationHasNoEffect_MixedIsInconclusive(t *testing.T) {
	inv := invariantByID(t, "ledger.rejected-operation-no-effect")

	got := inv.Check(InvariantInput{
		Profile: loadProfile(t, "hardened"),
		Before:  Snapshot{EntryCount: 0, InvariantOK: true},
		After:   Snapshot{EntryCount: 2, InvariantOK: true},
		Steps: []Step{
			step(0, Action{Op: OpDeposit, Actor: owner("alice"), Params: map[string]string{"account": "acct-1", "amount": "100"}}, true, nil),
			step(1, Action{Op: OpWithdraw, Actor: owner("mallory"), Params: map[string]string{"account": "acct-1", "amount": "100"}}, false, nil),
		},
	})

	if got.Outcome != finding.OutcomeInconclusive {
		t.Fatalf("outcome = %q (%s), want inconclusive -- the ledger change cannot be attributed to the refused operation", got.Outcome, got.Detail)
	}
}

// An action the validation boundary refused never reached the
// simulator, so it can neither confirm nor exercise any invariant.
func TestInvariants_UnexecutedStepsExerciseNothing(t *testing.T) {
	refused := Step{
		Index:      0,
		Action:     Action{Op: OpWithdraw, Actor: owner("mallory"), Params: map[string]string{"account": "acct-1", "amount": "100"}},
		Validation: ValidationResult{Decision: DecisionDisallowedByPolicy, Reason: "excluded"},
		Executed:   false,
	}

	for _, inv := range CoreInvariants() {
		t.Run(inv.ID, func(t *testing.T) {
			got := inv.Check(InvariantInput{
				Profile: loadProfile(t, "hardened"),
				Before:  Snapshot{InvariantOK: true},
				After:   Snapshot{InvariantOK: true},
				Steps:   []Step{refused},
			})
			if got.Outcome == finding.OutcomeConfirmedViolation {
				t.Fatalf("invariant %q confirmed a violation from an action that never ran", inv.ID)
			}
		})
	}
}

func TestInvariants_AppliesToDefaultsToEveryProfile(t *testing.T) {
	hardened := loadProfile(t, "hardened")
	vulnerable := loadProfile(t, "vulnerable")

	for _, inv := range CoreInvariants() {
		if inv.AppliesTo == nil {
			continue
		}
		// An invariant that applies to neither profile can never be
		// evaluated and is dead weight in the registry.
		if !inv.AppliesTo(hardened) && !inv.AppliesTo(vulnerable) {
			t.Fatalf("invariant %q applies to no configured profile", inv.ID)
		}
	}
}

func TestInvariant_Applicable(t *testing.T) {
	always := Invariant{ID: "x", AppliesTo: nil}
	if !always.Applicable(loadProfile(t, "hardened")) {
		t.Fatal("an invariant with no AppliesTo applies everywhere")
	}

	never := Invariant{ID: "y", AppliesTo: func(config.SecurityProfile) bool { return false }}
	if never.Applicable(loadProfile(t, "hardened")) {
		t.Fatal("AppliesTo must be honoured")
	}
}
