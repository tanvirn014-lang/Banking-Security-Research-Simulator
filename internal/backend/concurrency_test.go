package backend

import (
	"context"
	"sync"
	"testing"

	"banksec-lab/internal/domain"
)

// setupTwoAccountTransferScenario creates two accounts owned by owner-1
// and deposits startBalance into the first.
func setupTwoAccountTransferScenario(t *testing.T, svc Service, startBalance domain.Money) (acctA, acctB domain.AccountID) {
	t.Helper()
	ctx := context.Background()

	a, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount A: %v", err)
	}
	b, err := svc.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount B: %v", err)
	}
	if err := svc.Deposit(ctx, owner("owner-1"), a, startBalance); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	return a, b
}

func TestConcurrentTransfers_HardenedPreservesInvariant(t *testing.T) {
	ctx := context.Background()
	l, k, a := newTestStores(t)
	svc := NewService(l, k, a, hardenedTestProfile())

	acctA, acctB := setupTwoAccountTransferScenario(t, svc, 1000)

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.Transfer(ctx, owner("owner-1"), acctA, acctB, 100) // ignore individual errors; some must fail once funds are exhausted
		}()
	}
	wg.Wait()

	balA, err := svc.Balance(ctx, owner("owner-1"), acctA)
	if err != nil {
		t.Fatalf("Balance A: %v", err)
	}
	if balA < 0 {
		t.Fatalf("overdrawn under the hardened (atomicity-enforced) profile: balance=%d", balA)
	}

	balB, err := svc.Balance(ctx, owner("owner-1"), acctB)
	if err != nil {
		t.Fatalf("Balance B: %v", err)
	}
	if balA+balB != 1000 {
		t.Fatalf("expected total funds to be conserved (balA+balB=1000), got %d+%d=%d", balA, balB, balA+balB)
	}

	ok, bad, err := l.CheckInvariant(ctx)
	if err != nil {
		t.Fatalf("CheckInvariant: %v", err)
	}
	if !ok {
		t.Fatalf("ledger invariant violated under hardened concurrent transfers: %v", bad)
	}
}

func TestConcurrentTransfers_VulnerableAllowsOverdraftButNoDataRace(t *testing.T) {
	ctx := context.Background()
	l, k, a := newTestStores(t)
	svc := NewService(l, k, a, vulnerableTestProfile())

	acctA, acctB := setupTwoAccountTransferScenario(t, svc, 1000)

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.Transfer(ctx, owner("owner-1"), acctA, acctB, 100)
		}()
	}
	wg.Wait()

	balA, err := svc.Balance(ctx, owner("owner-1"), acctA)
	if err != nil {
		t.Fatalf("Balance A: %v", err)
	}
	// This is the documented vulnerability, not a hidden side effect: the
	// injected race window (see service.go) makes every concurrent
	// Transfer read the same stale balance before any of them write,
	// so all 20 can pass the insufficient-funds check deterministically.
	if balA >= 0 {
		t.Fatalf("expected the vulnerable (non-atomic) profile to demonstrably allow an overdraft, got balance=%d (race window did not manifest)", balA)
	}

	// Each individual Transfer still writes a balanced double-entry pair
	// -- the race breaks the *business* balance invariant (an account
	// going negative), not the ledger's own structural invariant (every
	// transaction's entries sum to zero). Asserting this distinction
	// explicitly: claiming ledger.CheckInvariant would also fail here
	// would be a false, overclaimed finding.
	ok, bad, err := l.CheckInvariant(ctx)
	if err != nil {
		t.Fatalf("CheckInvariant: %v", err)
	}
	if !ok {
		t.Fatalf("ledger structural invariant unexpectedly violated (expected only the business balance to be affected): %v", bad)
	}
}
