package backend

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/config"
	"banksec-lab/internal/crypto"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/keystore"
	"banksec-lab/internal/ledger"
	"banksec-lab/internal/testsupport"
)

// hardenedTestProfile and vulnerableTestProfile are minimal literal
// SecurityProfiles for backend tests -- only the fields backend actually
// reads matter here; the full profile set lives in configs/*.json.
func hardenedTestProfile() config.SecurityProfile {
	return config.SecurityProfile{Name: "hardened", AuthzEnforced: true, AtomicityEnforced: true}
}

func vulnerableTestProfile() config.SecurityProfile {
	return config.SecurityProfile{Name: "vulnerable", AuthzEnforced: false, AtomicityEnforced: false}
}

func newTestStores(t *testing.T) (ledger.Store, keystore.Store, audit.Stream) {
	t.Helper()

	l, err := ledger.NewSQLiteStore(testsupport.TempSQLitePath(t))
	if err != nil {
		t.Fatalf("ledger.NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	a, err := audit.NewSQLiteStream(testsupport.TempSQLitePath(t), false)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStream: %v", err)
	}
	t.Cleanup(func() { a.Close() })

	k, err := keystore.NewSQLiteStore(testsupport.TempSQLitePath(t), crypto.NewEngine(), false, a)
	if err != nil {
		t.Fatalf("keystore.NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { k.Close() })

	return l, k, a
}

func newTestService(t *testing.T) (Service, audit.Stream) {
	t.Helper()
	return newTestServiceWithProfile(t, hardenedTestProfile())
}

func newTestServiceWithProfile(t *testing.T, p config.SecurityProfile) (Service, audit.Stream) {
	t.Helper()
	l, k, a := newTestStores(t)
	return NewService(l, k, a, p), a
}

func owner(id domain.PrincipalID) domain.Principal {
	return domain.Principal{ID: id, Role: domain.RoleAccountOwner}
}

func TestDepositBalance_RoundTrip(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)

	acct, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if err := svc.Deposit(ctx, owner("owner-1"), acct, 1000); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	bal, err := svc.Balance(ctx, owner("owner-1"), acct)
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if bal != 1000 {
		t.Fatalf("got balance %d, want 1000", bal)
	}
}

func TestWithdraw_InsufficientFunds(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)

	acct, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	err = svc.Withdraw(ctx, owner("owner-1"), acct, 500)
	if !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("expected ErrInsufficientFunds, got %v", err)
	}
}

func TestTransfer_UnauthorizedOwnerRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)

	acctA, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount A: %v", err)
	}
	acctB, err := svc.CreateAccount(ctx, "owner-2")
	if err != nil {
		t.Fatalf("CreateAccount B: %v", err)
	}
	if err := svc.Deposit(ctx, owner("owner-1"), acctA, 1000); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	intruder := owner("owner-2")
	err = svc.Transfer(ctx, intruder, acctA, acctB, 100)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestTransfer_UnauthorizedRejectedWhenAuthzEnforced(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestServiceWithProfile(t, hardenedTestProfile())

	acctA, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount A: %v", err)
	}
	acctB, err := svc.CreateAccount(ctx, "owner-2")
	if err != nil {
		t.Fatalf("CreateAccount B: %v", err)
	}
	if err := svc.Deposit(ctx, owner("owner-1"), acctA, 1000); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	intruder := owner("owner-2")
	err = svc.Transfer(ctx, intruder, acctA, acctB, 100)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized under the hardened profile, got %v", err)
	}
}

func TestTransfer_UnauthorizedAllowedWhenAuthzNotEnforced(t *testing.T) {
	// This is the deliberately exploitable surface the vulnerable
	// profile exists to demonstrate (Task I1): the same cross-account
	// action that TestTransfer_UnauthorizedRejectedWhenAuthzEnforced
	// shows is rejected under the hardened profile.
	ctx := context.Background()
	svc, _ := newTestServiceWithProfile(t, vulnerableTestProfile())

	acctA, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount A: %v", err)
	}
	acctB, err := svc.CreateAccount(ctx, "owner-2")
	if err != nil {
		t.Fatalf("CreateAccount B: %v", err)
	}
	if err := svc.Deposit(ctx, owner("owner-1"), acctA, 1000); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	intruder := owner("owner-2")
	if err := svc.Transfer(ctx, intruder, acctA, acctB, 100); err != nil {
		t.Fatalf("expected the cross-account transfer to succeed under the vulnerable profile, got %v", err)
	}

	balB, err := svc.Balance(ctx, owner("owner-2"), acctB)
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if balB != 100 {
		t.Fatalf("expected the intruder's transfer to have moved funds, got balance %d", balB)
	}
}

func TestTransfer_NonexistentDestinationRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)

	acct, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if err := svc.Deposit(ctx, owner("owner-1"), acct, 1000); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	err = svc.Transfer(ctx, owner("owner-1"), acct, "no-such-account", 100)
	if err == nil {
		t.Fatal("expected transfer to a nonexistent account to be rejected")
	}

	bal, err := svc.Balance(ctx, owner("owner-1"), acct)
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if bal != 1000 {
		t.Fatalf("expected balance to be unchanged at 1000, got %d (funds were lost)", bal)
	}
}

func TestTransfer_ToExternalAccountRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)

	acct, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if err := svc.Deposit(ctx, owner("owner-1"), acct, 1000); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	err = svc.Transfer(ctx, owner("owner-1"), acct, externalSourceAccount, 100)
	if err == nil {
		t.Fatal("expected transfer to the synthetic external account to be rejected")
	}
}

func TestTransfer_SameAccountRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)

	acct, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if err := svc.Deposit(ctx, owner("owner-1"), acct, 1000); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	err = svc.Transfer(ctx, owner("owner-1"), acct, acct, 100)
	if err == nil {
		t.Fatal("expected a transfer to the same account to be rejected")
	}
}

func TestConcurrentWithdrawals_NoOverdraftAndInvariantHolds(t *testing.T) {
	ctx := context.Background()
	l, k, a := newTestStores(t)
	svc := NewService(l, k, a, hardenedTestProfile())

	acct, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if err := svc.Deposit(ctx, owner("owner-1"), acct, 1000); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.Withdraw(ctx, owner("owner-1"), acct, 100) // ignore individual errors; some must fail once funds are exhausted
		}()
	}
	wg.Wait()

	bal, err := svc.Balance(ctx, owner("owner-1"), acct)
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if bal < 0 {
		t.Fatalf("overdrawn: balance=%d", bal)
	}

	ok, bad, err := l.CheckInvariant(ctx)
	if err != nil {
		t.Fatalf("CheckInvariant: %v", err)
	}
	if !ok {
		t.Fatalf("ledger invariant violated under concurrent withdrawals: %v", bad)
	}
}

func TestDeposit_WouldOverflowBalanceRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)

	acct, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if err := svc.Deposit(ctx, owner("owner-1"), acct, maxAccountBalance); err != nil {
		t.Fatalf("Deposit up to the cap: %v", err)
	}

	// One more unit would push the balance past the safe cap -- this is
	// what, left unguarded, eventually makes SQLite's own SUM() throw a
	// runtime integer-overflow error on every later read of the account.
	err = svc.Deposit(ctx, owner("owner-1"), acct, 1)
	if err == nil {
		t.Fatal("expected a deposit that would overflow the account's safe balance cap to be rejected")
	}

	bal, err := svc.Balance(ctx, owner("owner-1"), acct)
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if bal != maxAccountBalance {
		t.Fatalf("expected balance to remain at the cap %d, got %d", maxAccountBalance, bal)
	}
}

func TestDeposit_NegativeAmountRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)

	acct, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	err = svc.Deposit(ctx, owner("owner-1"), acct, -100)
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation, got %v", err)
	}
}

func TestEveryOperation_EmitsAuditEvent(t *testing.T) {
	ctx := context.Background()
	svc, stream := newTestService(t)
	since := time.Now().Add(-time.Minute)

	acct, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	acct2, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount 2: %v", err)
	}
	if err := svc.Deposit(ctx, owner("owner-1"), acct, 1000); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	if err := svc.Withdraw(ctx, owner("owner-1"), acct, 100); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if err := svc.Transfer(ctx, owner("owner-1"), acct, acct2, 100); err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if _, err := svc.Balance(ctx, owner("owner-1"), acct); err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if _, err := svc.History(ctx, owner("owner-1"), acct); err != nil {
		t.Fatalf("History: %v", err)
	}
	// Rejected operations must be audited too.
	_ = svc.Withdraw(ctx, owner("owner-2"), acct, 10) // unauthorized

	events, err := stream.Since(ctx, since)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	// 2x CreateAccount, Deposit, Withdraw, Transfer, Balance, History,
	// and the rejected Withdraw = 8 operations, each must audit.
	const wantEvents = 8
	if len(events) != wantEvents {
		t.Fatalf("expected %d audit events, got %d: %+v", wantEvents, len(events), events)
	}
}

func TestOperations_ProduceDistinctEventAndTransactionIDs(t *testing.T) {
	// Regression test for a bug where per-process ID counters restarted
	// at tx-1/evt-1 whenever a fresh Service was built against the same
	// persistent stores (exactly what happens across separate CLI
	// invocations), silently colliding and dropping audit events.
	ctx := context.Background()

	l, k, a := newTestStores(t)
	svc1 := NewService(l, k, a, hardenedTestProfile())
	acct, err := svc1.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if err := svc1.Deposit(ctx, owner("owner-1"), acct, 500); err != nil {
		t.Fatalf("Deposit (svc1): %v", err)
	}

	// A fresh Service instance against the SAME stores, simulating a
	// separate CLI invocation.
	svc2 := NewService(l, k, a, hardenedTestProfile())
	if err := svc2.Deposit(ctx, owner("owner-1"), acct, 500); err != nil {
		t.Fatalf("Deposit (svc2): %v", err)
	}

	events, err := a.Since(ctx, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(events) != 3 { // CreateAccount + 2 Deposits
		t.Fatalf("expected 3 audit events across both service instances, got %d (IDs likely collided)", len(events))
	}

	hist, err := l.History(ctx, acct)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 2 { // History(acct) returns only acct's own leg of each deposit
		t.Fatalf("expected 2 ledger entries for acct, got %d", len(hist))
	}
	if hist[0].TxID == hist[1].TxID {
		t.Fatalf("expected the two deposits to have distinct transaction IDs, both were %q", hist[0].TxID)
	}
}
