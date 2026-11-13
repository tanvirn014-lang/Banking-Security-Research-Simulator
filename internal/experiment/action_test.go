package experiment

import (
	"encoding/json"
	"strings"
	"testing"

	"banksec-lab/internal/domain"
)

func TestAction_SupportedOpsMatchesTheProtocolDispatch(t *testing.T) {
	// These are exactly the operations protocol/server.go switches over.
	// If the simulator gains or loses an operation, this test is the
	// place that notices.
	want := []string{"balance", "create-account", "deposit", "history", "transfer", "withdraw"}
	got := SupportedOps()

	if len(got) != len(want) {
		t.Fatalf("supported ops = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("supported ops = %v, want %v", got, want)
		}
	}
	if IsSupportedOp("drop-database") {
		t.Fatal("an operation the simulator cannot dispatch must not be reported as supported")
	}
}

func TestAction_SupportedOpsCannotBeMutatedByACaller(t *testing.T) {
	first := SupportedOps()
	first[0] = "tampered"

	second := SupportedOps()
	if second[0] == "tampered" {
		t.Fatal("SupportedOps handed out its backing store -- a caller corrupted the canonical op set")
	}
}

func TestAction_MutatingOpsAreTheStateChangingOnes(t *testing.T) {
	for _, op := range []string{OpCreateAccount, OpDeposit, OpWithdraw, OpTransfer} {
		if !IsMutatingOp(op) {
			t.Fatalf("%s changes ledger state and must be reported as mutating", op)
		}
	}
	for _, op := range []string{OpBalance, OpHistory} {
		if IsMutatingOp(op) {
			t.Fatalf("%s is read-only and must not be reported as mutating", op)
		}
	}
}

func TestAction_RequestDoesNotAliasActionParams(t *testing.T) {
	a := Action{
		Op:     OpDeposit,
		Actor:  domain.Principal{ID: "alice", Role: domain.RoleAccountOwner},
		Params: map[string]string{"account": "acct-1", "amount": "100"},
	}

	req := a.Request()
	req.Params["amount"] = "999999"

	if a.Params["amount"] != "100" {
		t.Fatal("Request aliased the Action's Params map -- changing a request in flight changed the recorded action")
	}
}

func TestAction_RequestCarriesOpAndActorThrough(t *testing.T) {
	a := Action{
		Op:     OpTransfer,
		Actor:  domain.Principal{ID: "bob", Role: domain.RoleAccountOwner},
		Params: map[string]string{"from": "acct-1", "to": "acct-2", "amount": "50"},
	}

	req := a.Request()
	if req.Op != OpTransfer {
		t.Fatalf("Op = %q, want %q", req.Op, OpTransfer)
	}
	if req.Actor.ID != "bob" || req.Actor.Role != domain.RoleAccountOwner {
		t.Fatalf("Actor = %+v, want bob/account-owner", req.Actor)
	}
	if req.Params["from"] != "acct-1" || req.Params["to"] != "acct-2" || req.Params["amount"] != "50" {
		t.Fatalf("Params = %v, want the action's own params", req.Params)
	}
}

func TestAction_RequestOfNilParamsStaysNil(t *testing.T) {
	a := Action{Op: OpBalance, Actor: domain.Principal{ID: "alice", Role: domain.RoleAccountOwner}}

	if req := a.Request(); req.Params != nil {
		t.Fatalf("a nil Params must not become an empty map, got %v", req.Params)
	}
}

func TestAction_CloneDoesNotAliasParams(t *testing.T) {
	a := Action{Op: OpDeposit, Params: map[string]string{"amount": "100"}}

	clone := a.Clone()
	clone.Params["amount"] = "200"

	if a.Params["amount"] != "100" {
		t.Fatal("Clone aliased Params -- a mutated action corrupted the action it was derived from")
	}
}

func TestAction_StringIsStableAcrossParamOrdering(t *testing.T) {
	a := Action{
		Op:     OpTransfer,
		Actor:  domain.Principal{ID: "alice", Role: domain.RoleAccountOwner},
		Params: map[string]string{"to": "acct-2", "amount": "50", "from": "acct-1"},
	}

	first := a.String()
	for i := 0; i < 20; i++ {
		if got := a.String(); got != first {
			t.Fatalf("Action.String is not stable: %q then %q", first, got)
		}
	}
	if !strings.Contains(first, "transfer") || !strings.Contains(first, "alice") {
		t.Fatalf("Action.String should name the op and actor, got %q", first)
	}
}

func TestAction_RoundTripsThroughJSONForReproduction(t *testing.T) {
	a := Action{
		Op:     OpWithdraw,
		Actor:  domain.Principal{ID: "mallory", Role: domain.RoleAccountOwner},
		Params: map[string]string{"account": "acct-1", "amount": "-100"},
		Label:  "mutated:amount-negate",
	}

	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Action
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if back.String() != a.String() {
		t.Fatalf("an action must survive a JSON round trip to be reproducible: %q != %q", back.String(), a.String())
	}
	if back.Label != a.Label {
		t.Fatalf("Label = %q, want %q", back.Label, a.Label)
	}
}
