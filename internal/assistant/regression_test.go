package assistant

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"banksec-lab/internal/domain"
	"banksec-lab/internal/protocol"
)

// These tests are the permanent regressions for the findings in
// docs/LLM_SECURITY_ASSESSMENT.md. Each one fails if its finding comes
// back. They are written against the behaviour the fix established, not
// against the code that implements it, so a reimplementation that
// reintroduces the weakness still trips them.

// seedDeposits adds n legitimate deposits to the session owner's own
// account, to build a long transaction history.
func seedDeposits(t *testing.T, f *fixture, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		resp, err := f.env.Client.Send(context.Background(), protocol.Request{
			Op:    "deposit",
			Actor: domain.Principal{ID: "alice", Role: domain.RoleAccountOwner},
			Params: map[string]string{
				"account": string(f.alice),
				"amount":  strconv.Itoa(100 + i),
			},
		})
		if err != nil || !resp.OK {
			t.Fatalf("seed deposit %d: err=%v resp=%+v", i, err, resp)
		}
	}
}

// F-01: the history cap must apply to the key the banking server
// actually returns. It previously capped a key named "entries", which
// the server never sends, so the cap did nothing.
func TestRegression_F01_HistoryIsCappedOnTheKeyTheServerReturns(t *testing.T) {
	f := newFixture(t, "hardened")
	limits := DefaultLimits()
	seedDeposits(t, f, limits.MaxHistoryEntries+40)

	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolGetTransactionHistory), map[string]any{
		"account": string(f.alice),
	}))
	if inv.Decision != DecisionExecuted {
		t.Fatalf("history read: %q (%s)", inv.Decision, inv.Reason)
	}

	var entries []json.RawMessage
	if err := json.Unmarshal([]byte(inv.Result[historyResultKey]), &entries); err != nil {
		t.Fatalf("the capped history must still be valid JSON: %v", err)
	}
	if len(entries) != limits.MaxHistoryEntries {
		t.Fatalf("returned %d entries, want the cap of %d", len(entries), limits.MaxHistoryEntries)
	}
	if inv.Result["history_entries_withheld"] == "" {
		t.Fatal("the model must be told that entries were withheld, not left to assume the view is complete")
	}
}

func TestRegression_F01_ShortHistoryIsNotAnnotated(t *testing.T) {
	f := newFixture(t, "hardened")
	seedDeposits(t, f, 2)

	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolGetTransactionHistory), map[string]any{
		"account": string(f.alice),
	}))

	if inv.Result["history_entries_withheld"] != "" {
		t.Fatal("a history inside the cap must not claim anything was withheld")
	}
}

// F-02: the gateway must refuse an account the session does not declare,
// independently of the bank. Asserted under the vulnerable profile,
// where the bank's own authorization is off -- that is the whole point:
// the gateway has to contribute a check of its own.
func TestRegression_F02_GatewayRefusesUnownedAccountsWithoutTheBank(t *testing.T) {
	for _, profileName := range []string{"hardened", "vulnerable"} {
		t.Run(profileName, func(t *testing.T) {
			f := newFixture(t, profileName)
			// Declare only alice's account, and no payees at all.
			f.session.Accounts = []domain.AccountID{f.alice}
			f.session.Payees = nil

			for _, tool := range []ToolName{ToolGetBalance, ToolGetTransactionHistory, ToolGetAccountSummary} {
				inv := f.gateway.Invoke(context.Background(), f.session, call(string(tool), map[string]any{
					"account": string(f.mallory),
				}))
				if inv.Decision != DecisionRefusedUnauthorized {
					t.Fatalf("%s: decision = %q (%s), want refused_unauthorized", tool, inv.Decision, inv.Reason)
				}
				if inv.Executed {
					t.Fatalf("%s executed against an account the session does not own", tool)
				}
			}

			draft := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
				"from": string(f.mallory), "to": string(f.alice), "amount": "1000",
			}))
			if draft.Decision != DecisionRefusedUnauthorized {
				t.Fatalf("prepare_transfer: decision = %q (%s), want refused_unauthorized", draft.Decision, draft.Reason)
			}
			if draft.Result["confirmation_id"] != "" {
				t.Fatal("a confirmation was minted for a debit from an unowned account")
			}
		})
	}
}

// F-02: a session that declares no accounts must own nothing, rather
// than skipping the check. A caller that forgets to populate the field
// gets refusals, not an unchecked gateway.
func TestRegression_F02_EmptyAccountListFailsClosed(t *testing.T) {
	f := newFixture(t, "vulnerable")
	f.session.Accounts = nil

	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolGetBalance), map[string]any{
		"account": string(f.alice),
	}))

	if inv.Decision != DecisionRefusedUnauthorized {
		t.Fatalf("decision = %q, want refused_unauthorized when the session declares no accounts", inv.Decision)
	}
	if !strings.Contains(inv.Reason, "no accounts") {
		t.Fatalf("the reason should say the session declares no accounts, got %q", inv.Reason)
	}
}

// F-03: the budget bounds proposals, not executions, and the counters
// are reported separately so the two cannot be confused.
func TestRegression_F03_BudgetBoundsProposalsAndCountersAreSeparate(t *testing.T) {
	f := newFixture(t, "hardened")
	limits := DefaultLimits()
	limits.MaxToolCalls = 3
	gw, err := NewGateway(f.env.Client, limits)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	for i := 0; i < 2; i++ {
		gw.Invoke(context.Background(), f.session, call("exec_sql", map[string]any{}))
	}
	gw.Invoke(context.Background(), f.session, call(string(ToolGetBalance), map[string]any{
		"account": string(f.alice),
	}))

	if gw.AttemptedCount() != 3 {
		t.Fatalf("attempted = %d, want 3", gw.AttemptedCount())
	}
	if gw.ExecutedCount() != 1 {
		t.Fatalf("executed = %d, want 1", gw.ExecutedCount())
	}
	if gw.RefusedCount() != 2 {
		t.Fatalf("refused = %d, want 2", gw.RefusedCount())
	}
	if gw.Remaining() != 0 {
		t.Fatalf("remaining = %d, want 0 -- refused proposals are charged deliberately", gw.Remaining())
	}
}

// F-04: an unreachable destination must be refused at draft time, so no
// confirmation is minted and no customer approval can be consumed by a
// transfer that could never execute.
func TestRegression_F04_UnreachableDestinationIsRefusedAtDraftTime(t *testing.T) {
	f := newFixture(t, "hardened")

	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
		"from": string(f.alice), "to": "acct-does-not-exist", "amount": "100",
	}))

	if inv.Decision == DecisionExecuted {
		t.Fatalf("a transfer to an unknown destination was drafted: %v", inv.Result)
	}
	if inv.Result["confirmation_id"] != "" {
		t.Fatal("no confirmation may be minted for an unreachable destination")
	}
}

// F-04: an account number the model invented by altering the customer's
// own -- observed in live testing -- must be refused.
func TestRegression_F04_InventedNeighbouringAccountIsRefused(t *testing.T) {
	f := newFixture(t, "hardened")
	invented := string(f.alice[:len(f.alice)-1]) + "0"
	if invented == string(f.alice) {
		invented = string(f.alice[:len(f.alice)-1]) + "1"
	}

	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
		"from": string(f.alice), "to": invented, "amount": "100",
	}))

	if inv.Decision == DecisionExecuted {
		t.Fatalf("a drafted transfer to an invented neighbouring account was allowed: %v", inv.Result)
	}
}

// F-04: a saved payee remains a valid destination, so the fix does not
// block legitimate work.
func TestRegression_F04_SavedPayeeIsStillAValidDestination(t *testing.T) {
	f := newFixture(t, "hardened")

	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
		"from": string(f.alice), "to": string(f.mallory), "amount": "100",
	}))

	if inv.Decision != DecisionExecuted {
		t.Fatalf("decision = %q (%s), want executed for a saved payee", inv.Decision, inv.Reason)
	}
}

// F-05: the gateway must not synthesise an owner field. It previously
// reported the caller as the owner of whatever account was read, which
// is a fabrication that masks a cross-account read.
func TestRegression_F05_SummaryDoesNotFabricateAnOwner(t *testing.T) {
	f := newFixture(t, "hardened")

	inv := f.gateway.Invoke(context.Background(), f.session, call(string(ToolGetAccountSummary), map[string]any{
		"account": string(f.alice),
	}))
	if inv.Decision != DecisionExecuted {
		t.Fatalf("decision = %q (%s)", inv.Decision, inv.Reason)
	}

	if _, present := inv.Result["owner"]; present {
		t.Fatal("the gateway must not assert an owner the bank never returned")
	}
	if inv.Result["balance"] == "" {
		t.Fatal("the summary should still return the balance the bank did provide")
	}
}

// Benign regression: the legitimate path must still work end to end
// after every fix above. A security change that quietly breaks ordinary
// banking would make every refusal meaningless.
func TestRegression_BenignTransferStillCompletes(t *testing.T) {
	f := newFixture(t, "hardened")
	before := f.balance(t, f.alice)

	prep := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
		"from": string(f.alice), "to": string(f.mallory), "amount": "100",
	}))
	if prep.Decision != DecisionExecuted {
		t.Fatalf("prepare: %q (%s)", prep.Decision, prep.Reason)
	}
	id := prep.Result["confirmation_id"]

	if err := f.gateway.ApproveTransfer(f.session.ID, id); err != nil {
		t.Fatalf("ApproveTransfer: %v", err)
	}
	confirm := f.gateway.Invoke(context.Background(), f.session, call(string(ToolConfirmTransfer), map[string]any{
		"confirmation_id": id,
	}))
	if confirm.Decision != DecisionExecuted {
		t.Fatalf("confirm: %q (%s)", confirm.Decision, confirm.Reason)
	}

	if after := f.balance(t, f.alice); after != before-100 {
		t.Fatalf("balance = %d, want %d", after, before-100)
	}
}

func TestRegression_BenignReadsStillWork(t *testing.T) {
	f := newFixture(t, "hardened")
	seedDeposits(t, f, 3)

	for _, tool := range []ToolName{ToolGetBalance, ToolGetTransactionHistory, ToolGetAccountSummary} {
		inv := f.gateway.Invoke(context.Background(), f.session, call(string(tool), map[string]any{
			"account": string(f.alice),
		}))
		if inv.Decision != DecisionExecuted {
			t.Fatalf("%s on the customer's own account: %q (%s)", tool, inv.Decision, inv.Reason)
		}
	}
}

// PendingTransfer must report the real figures, since an application
// shows them to a human before approving (see finding F-06).
func TestRegression_F06_PendingTransferReportsTheRealFigures(t *testing.T) {
	f := newFixture(t, "hardened")

	prep := f.gateway.Invoke(context.Background(), f.session, call(string(ToolPrepareTransfer), map[string]any{
		"from": string(f.alice), "to": string(f.mallory), "amount": "4242",
	}))
	id := prep.Result["confirmation_id"]

	from, to, amount, ok := f.gateway.PendingTransfer(id)
	if !ok {
		t.Fatal("the pending transfer must be inspectable before approval")
	}
	if from != string(f.alice) || to != string(f.mallory) || amount != 4242 {
		t.Fatalf("PendingTransfer = %s -> %s, %d; want the drafted figures", from, to, amount)
	}
}
