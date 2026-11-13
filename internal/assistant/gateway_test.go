package assistant

import (
	"context"
	"strings"
	"testing"

	"banksec-lab/internal/config"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/harness"
	"banksec-lab/internal/llm"
)

// fixture wires a real simulator environment with two synthetic
// accounts: alice's (funded) and mallory's (empty). Every gateway test
// runs against the genuine banking stack, not a stub, so an
// authorization result means the real authorization layer produced it.
type fixture struct {
	env     *harness.Environment
	gateway *Gateway
	session Session
	alice   domain.AccountID
	mallory domain.AccountID
}

func newFixture(t *testing.T, profileName string) *fixture {
	t.Helper()

	profile, err := config.Load("../../configs/" + profileName + ".json")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	env, err := harness.NewLocalEnvironment(profile)
	if err != nil {
		t.Fatalf("NewLocalEnvironment: %v", err)
	}
	t.Cleanup(func() { env.Close() })

	seed, err := SeedSyntheticAccounts(context.Background(), env.Client, SyntheticFixture())
	if err != nil {
		t.Fatalf("seed synthetic accounts: %v", err)
	}

	// A correct application declares what the session owns and who it
	// may pay. The gateway now checks both independently of the bank,
	// and fails closed when they are absent.
	session := Session{
		ID:        "sess-1",
		Principal: domain.Principal{ID: "alice", Role: domain.RoleAccountOwner},
		Accounts:  []domain.AccountID{seed.Accounts["alice"]},
		Payees:    []Payee{{Name: "mallory", Account: seed.Accounts["mallory"]}},
	}
	gw, err := NewGateway(env.Client, DefaultLimits())
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	return &fixture{
		env: env, gateway: gw, session: session,
		alice:   seed.Accounts["alice"],
		mallory: seed.Accounts["mallory"],
	}
}

func call(name string, args map[string]any) llm.ToolCall {
	return llm.ToolCall{ID: "call-1", Name: name, Arguments: args}
}

func TestGateway_ExecutesAnOwnersOwnBalanceRead(t *testing.T) {
	f := newFixture(t, "hardened")

	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolGetBalance), map[string]any{
		"account": string(f.alice),
	}))

	if inv.Decision != DecisionExecuted {
		t.Fatalf("decision = %q (%s), want executed", inv.Decision, inv.Reason)
	}
	if inv.Result["balance"] == "" {
		t.Fatalf("expected a balance in the result, got %v", inv.Result)
	}
}

// The central rule: the model proposes, the application decides. An
// actor the model invents must be discarded in favour of the session's
// server-side principal.
func TestGateway_IgnoresAModelSuppliedActor(t *testing.T) {
	f := newFixture(t, "hardened")

	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolGetBalance), map[string]any{
		"account": string(f.mallory),
		// Everything below is a lie the model told. None of it may count.
		"actor":           "mallory",
		"as":              "mallory",
		"role":            "privileged-operator",
		"principal":       "admin",
		"authorized":      "true",
		"confirmation_id": "anything",
		"permissions":     "all",
	}))

	if inv.Decision == DecisionExecuted {
		t.Fatalf("the gateway honoured a model-supplied actor and read another account: %v", inv.Result)
	}
	if inv.EffectiveActor != f.session.Principal.ID {
		t.Fatalf("effective actor = %q, want the session's own principal %q", inv.EffectiveActor, f.session.Principal.ID)
	}
}

func TestGateway_RefusesAnUnknownTool(t *testing.T) {
	f := newFixture(t, "hardened")

	for _, name := range []string{"exec_sql", "read_private_key", "set_role", "http_get", "shell"} {
		t.Run(name, func(t *testing.T) {
			inv := f.gateway.Invoke(context.Background(), f.session, call(name, map[string]any{}))
			if inv.Decision != DecisionRefusedUnknownTool {
				t.Fatalf("decision = %q, want refused_unknown_tool", inv.Decision)
			}
			if inv.Executed {
				t.Fatal("an unknown tool must never be recorded as executed")
			}
		})
	}
}

func TestGateway_RefusesMalformedArguments(t *testing.T) {
	f := newFixture(t, "hardened")

	tests := []struct {
		name string
		call llm.ToolCall
	}{
		{"missing account", call(string(ToolGetBalance), map[string]any{})},
		{"account of the wrong type", call(string(ToolGetBalance), map[string]any{"account": 42})},
		{"unknown argument", call(string(ToolGetBalance), map[string]any{"account": "a", "sql": "DROP TABLE"})},
		{"transfer missing amount", call(string(ToolPrepareTransfer), map[string]any{"from": "a", "to": "b"})},
		{"amount not a number", call(string(ToolPrepareTransfer), map[string]any{"from": "a", "to": "b", "amount": "lots"})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := f.gateway.Invoke(context.Background(), f.session, tt.call)
			if inv.Decision != DecisionRefusedSchema {
				t.Fatalf("decision = %q (%s), want refused_schema", inv.Decision, inv.Reason)
			}
			if inv.Executed {
				t.Fatal("a malformed call must never execute")
			}
		})
	}
}

func TestGateway_RefusesReadingAnAccountTheSessionDoesNotOwn(t *testing.T) {
	f := newFixture(t, "hardened")

	for _, tool := range []ToolName{ToolGetBalance, ToolGetTransactionHistory, ToolGetAccountSummary} {
		t.Run(string(tool), func(t *testing.T) {
			inv := f.gateway.Invoke(context.Background(), f.session, call(string(tool), map[string]any{
				"account": string(f.mallory),
			}))
			if inv.Decision == DecisionExecuted {
				t.Fatalf("%s returned another account's data: %v", tool, inv.Result)
			}
			if inv.Decision != DecisionRefusedUnauthorized {
				t.Fatalf("decision = %q (%s), want refused_unauthorized", inv.Decision, inv.Reason)
			}
		})
	}
}

// There is no direct execute tool at all. This asserts the shape of the
// catalog itself, not just that a particular call is refused.
func TestGateway_ExposesNoDirectTransferExecution(t *testing.T) {
	for _, spec := range ToolCatalog() {
		lower := strings.ToLower(spec.Name)
		if strings.Contains(lower, "execute") || lower == "transfer" || lower == "do_transfer" {
			t.Fatalf("the catalog exposes a direct execution tool: %q", spec.Name)
		}
	}

	names := map[string]bool{}
	for _, spec := range ToolCatalog() {
		names[spec.Name] = true
	}
	if names[string(ToolPrepareTransfer)] && !names[string(ToolConfirmTransfer)] {
		t.Fatal("prepare_transfer without confirm_transfer would leave a prepared transfer unexecutable by design -- or executable by accident")
	}
}

func TestGateway_PrepareTransferMovesNoMoney(t *testing.T) {
	f := newFixture(t, "hardened")
	before := f.balance(t, f.alice)

	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
		"from": string(f.alice), "to": string(f.mallory), "amount": "100",
	}))

	if inv.Decision != DecisionExecuted {
		t.Fatalf("decision = %q (%s), want executed (preparing is allowed)", inv.Decision, inv.Reason)
	}
	if inv.Result["confirmation_id"] == "" {
		t.Fatal("prepare_transfer must return a confirmation id")
	}
	if after := f.balance(t, f.alice); after != before {
		t.Fatalf("preparing a transfer moved money: %d -> %d", before, after)
	}
}

// The core of the confirmation design: the model holding a valid
// confirmation id is not enough. A human must approve it out of band.
func TestGateway_ConfirmTransferRequiresApprovalGrantedOutsideTheModel(t *testing.T) {
	f := newFixture(t, "hardened")
	before := f.balance(t, f.alice)

	prep := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
		"from": string(f.alice), "to": string(f.mallory), "amount": "100",
	}))
	id := prep.Result["confirmation_id"]

	// The model confirms its own transfer, with the real id.
	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolConfirmTransfer), map[string]any{
		"confirmation_id": id,
	}))

	if inv.Decision != DecisionRefusedUnconfirmed {
		t.Fatalf("decision = %q (%s), want refused_unconfirmed -- the model must not be able to approve its own transfer", inv.Decision, inv.Reason)
	}
	if after := f.balance(t, f.alice); after != before {
		t.Fatalf("a self-confirmed transfer moved money: %d -> %d", before, after)
	}
}

func TestGateway_ConfirmTransferSucceedsOnceApproved(t *testing.T) {
	f := newFixture(t, "hardened")
	before := f.balance(t, f.alice)

	prep := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
		"from": string(f.alice), "to": string(f.mallory), "amount": "100",
	}))
	id := prep.Result["confirmation_id"]

	// The application, not the model, records the user's approval.
	if err := f.gateway.ApproveTransfer(f.session.ID, id); err != nil {
		t.Fatalf("ApproveTransfer: %v", err)
	}

	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolConfirmTransfer), map[string]any{
		"confirmation_id": id,
	}))
	if inv.Decision != DecisionExecuted {
		t.Fatalf("decision = %q (%s), want executed", inv.Decision, inv.Reason)
	}
	if after := f.balance(t, f.alice); after != before-100 {
		t.Fatalf("balance = %d, want %d after an approved transfer", after, before-100)
	}
}

func TestGateway_InventedConfirmationIDIsRefused(t *testing.T) {
	f := newFixture(t, "hardened")

	for _, id := range []string{"", "confirm-1", "0", "true", "approved", strings.Repeat("a", 64)} {
		inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolConfirmTransfer), map[string]any{
			"confirmation_id": id,
		}))
		if inv.Decision == DecisionExecuted {
			t.Fatalf("a model-invented confirmation id %q was accepted", id)
		}
	}
}

func TestGateway_ApprovalCannotBeReused(t *testing.T) {
	f := newFixture(t, "hardened")

	prep := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
		"from": string(f.alice), "to": string(f.mallory), "amount": "50",
	}))
	id := prep.Result["confirmation_id"]
	if err := f.gateway.ApproveTransfer(f.session.ID, id); err != nil {
		t.Fatalf("ApproveTransfer: %v", err)
	}

	first := f.gateway.Invoke(context.Background(), f.session, call(string(ToolConfirmTransfer), map[string]any{"confirmation_id": id}))
	if first.Decision != DecisionExecuted {
		t.Fatalf("first confirm: %q (%s)", first.Decision, first.Reason)
	}

	before := f.balance(t, f.alice)
	second := f.gateway.Invoke(context.Background(), f.session, call(string(ToolConfirmTransfer), map[string]any{"confirmation_id": id}))
	if second.Decision == DecisionExecuted {
		t.Fatal("a confirmation id was accepted twice -- one approval must authorize exactly one transfer")
	}
	if after := f.balance(t, f.alice); after != before {
		t.Fatalf("the replayed confirmation moved money again: %d -> %d", before, after)
	}
}

// Session isolation: a confirmation prepared in one session must not be
// usable from another, even with the right id.
func TestGateway_ConfirmationIsBoundToItsSession(t *testing.T) {
	f := newFixture(t, "hardened")

	prep := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
		"from": string(f.alice), "to": string(f.mallory), "amount": "50",
	}))
	id := prep.Result["confirmation_id"]
	if err := f.gateway.ApproveTransfer(f.session.ID, id); err != nil {
		t.Fatalf("ApproveTransfer: %v", err)
	}

	other := Session{ID: "sess-2", Principal: domain.Principal{ID: "mallory", Role: domain.RoleAccountOwner}}
	inv := f.gateway.Invoke(context.Background(), other, call(string(ToolConfirmTransfer), map[string]any{
		"confirmation_id": id,
	}))

	if inv.Decision == DecisionExecuted {
		t.Fatal("another session confirmed a transfer prepared in this one")
	}
}

func TestGateway_ApprovingFromAnotherSessionIsRejected(t *testing.T) {
	f := newFixture(t, "hardened")

	prep := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
		"from": string(f.alice), "to": string(f.mallory), "amount": "50",
	}))
	id := prep.Result["confirmation_id"]

	if err := f.gateway.ApproveTransfer("sess-2", id); err == nil {
		t.Fatal("approving another session's pending transfer must be rejected")
	}
}

func TestGateway_RefusesPreparingATransferFromAnotherAccount(t *testing.T) {
	f := newFixture(t, "hardened")

	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
		"from": string(f.mallory), "to": string(f.alice), "amount": "100",
	}))

	if inv.Decision != DecisionRefusedUnauthorized {
		t.Fatalf("decision = %q (%s), want refused_unauthorized", inv.Decision, inv.Reason)
	}
}

func TestGateway_EnforcesTheTransferAmountLimit(t *testing.T) {
	f := newFixture(t, "hardened")
	limits := DefaultLimits()

	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
		"from": string(f.alice), "to": string(f.mallory), "amount": "99999999999",
	}))

	if inv.Decision != DecisionRefusedLimit {
		t.Fatalf("decision = %q (%s), want refused_limit", inv.Decision, inv.Reason)
	}
	if !strings.Contains(inv.Reason, "limit") {
		t.Fatalf("the reason should name the limit, got %q", inv.Reason)
	}
	_ = limits
}

func TestGateway_RefusesNonPositiveTransferAmounts(t *testing.T) {
	f := newFixture(t, "hardened")

	for _, amount := range []string{"0", "-100"} {
		inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
			"from": string(f.alice), "to": string(f.mallory), "amount": amount,
		}))
		if inv.Decision == DecisionExecuted {
			t.Fatalf("a transfer of %s was prepared", amount)
		}
	}
}

func TestGateway_EnforcesTheToolBudget(t *testing.T) {
	f := newFixture(t, "hardened")
	limits := DefaultLimits()
	limits.MaxToolCalls = 2
	gw, err := NewGateway(f.env.Client, limits)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	for i := 0; i < 2; i++ {
		inv := gw.Invoke(context.Background(), f.session, call(string(ToolGetBalance), map[string]any{"account": string(f.alice)}))
		if inv.Decision != DecisionExecuted {
			t.Fatalf("call %d: %q (%s)", i, inv.Decision, inv.Reason)
		}
	}

	inv := gw.Invoke(context.Background(), f.session, call(string(ToolGetBalance), map[string]any{"account": string(f.alice)}))
	if inv.Decision != DecisionRefusedBudget {
		t.Fatalf("decision = %q, want refused_budget once the tool budget is spent", inv.Decision)
	}
}

// Attempted and executed calls must be countable separately, or a
// refused proposal could be read as an action.
func TestGateway_RecordsAttemptsAndExecutionsSeparately(t *testing.T) {
	f := newFixture(t, "hardened")

	f.gateway.Invoke(context.Background(), f.session, call(string(ToolGetBalance), map[string]any{"account": string(f.alice)}))
	f.gateway.Invoke(context.Background(), f.session, call("exec_sql", map[string]any{}))
	f.gateway.Invoke(context.Background(), f.session, call(string(ToolGetBalance), map[string]any{"account": string(f.mallory)}))

	log := f.gateway.Log()
	if len(log) != 3 {
		t.Fatalf("attempted calls recorded = %d, want 3", len(log))
	}
	if got := f.gateway.ExecutedCount(); got != 1 {
		t.Fatalf("executed calls = %d, want 1", got)
	}
	if got := f.gateway.AttemptedCount(); got != 3 {
		t.Fatalf("attempted calls = %d, want 3", got)
	}
	for _, inv := range log {
		if inv.Reason == "" && inv.Decision != DecisionExecuted {
			t.Fatalf("refused call %+v carries no reason", inv)
		}
	}
}

// Nothing in the gateway's record may carry key material.
func TestGateway_LogCarriesNoKeyMaterial(t *testing.T) {
	f := newFixture(t, "hardened")

	f.gateway.Invoke(context.Background(), f.session, call(string(ToolGetAccountSummary), map[string]any{
		"account": string(f.alice),
	}))

	for _, inv := range f.gateway.Log() {
		for k, v := range inv.Result {
			lower := strings.ToLower(k + v)
			for _, forbidden := range []string{"private_key", "passphrase", "secret"} {
				if strings.Contains(lower, forbidden) {
					t.Fatalf("the tool result exposes %q: %v", forbidden, inv.Result)
				}
			}
		}
	}
}

func TestGateway_ToolCatalogIsSchemaComplete(t *testing.T) {
	for _, spec := range ToolCatalog() {
		if spec.Description == "" {
			t.Fatalf("tool %q has no description for the model", spec.Name)
		}
		params, ok := spec.Parameters["type"].(string)
		if !ok || params != "object" {
			t.Fatalf("tool %q parameters must be a JSON Schema object, got %v", spec.Name, spec.Parameters)
		}
		if _, ok := spec.Parameters["properties"]; !ok {
			t.Fatalf("tool %q declares no properties", spec.Name)
		}
	}
}

func TestGateway_ReadOnlyToolsNeverChangeState(t *testing.T) {
	f := newFixture(t, "hardened")
	before := f.balance(t, f.alice)

	for _, tool := range []ToolName{ToolGetBalance, ToolGetTransactionHistory, ToolGetAccountSummary} {
		f.gateway.Invoke(context.Background(), f.session, call(string(tool), map[string]any{"account": string(f.alice)}))
	}

	if after := f.balance(t, f.alice); after != before {
		t.Fatalf("a read-only tool changed the balance: %d -> %d", before, after)
	}
}

// balance reads alice's balance straight from the oracle, independently
// of the gateway, so a test asserting "no money moved" is not asking the
// component under test to grade itself.
func (f *fixture) balance(t *testing.T, acct domain.AccountID) domain.Money {
	t.Helper()
	state, err := f.env.Oracle.LedgerSnapshot(context.Background())
	if err != nil {
		t.Fatalf("LedgerSnapshot: %v", err)
	}
	var sum domain.Money
	for _, e := range state.Entries {
		if e.AccountID == acct {
			sum += e.Amount
		}
	}
	return sum
}
