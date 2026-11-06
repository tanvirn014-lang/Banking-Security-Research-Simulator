package ledger

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"banksec-lab/internal/testsupport"
)

func newTestStore(t *testing.T) Store {
	t.Helper()
	s, err := NewSQLiteStore(testsupport.TempSQLitePath(t))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func TestCreateAccount_AccountOwnerRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	acct, err := s.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if acct == "" {
		t.Fatal("expected a non-empty account ID")
	}

	owner, ok, err := s.AccountOwner(ctx, acct)
	if err != nil {
		t.Fatalf("AccountOwner: %v", err)
	}
	if !ok || owner != "owner-1" {
		t.Fatalf("expected owner=owner-1 ok=true, got owner=%q ok=%v", owner, ok)
	}
}

func TestCreateAccount_PersistsAcrossStoreInstances(t *testing.T) {
	ctx := context.Background()
	path := testsupport.TempSQLitePath(t)

	s1, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore (1st): %v", err)
	}
	acct, err := s1.CreateAccount(ctx, "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close (1st): %v", err)
	}

	s2, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore (2nd): %v", err)
	}
	t.Cleanup(func() { s2.Close() })

	owner, ok, err := s2.AccountOwner(ctx, acct)
	if err != nil {
		t.Fatalf("AccountOwner: %v", err)
	}
	if !ok || owner != "owner-1" {
		t.Fatalf("expected ownership to persist across store instances, got owner=%q ok=%v", owner, ok)
	}
}

func TestAccountOwner_UnknownAccount(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	_, ok, err := s.AccountOwner(ctx, "no-such-account")
	if err != nil {
		t.Fatalf("AccountOwner: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for an unknown account")
	}
}

func TestAppendTransaction_BalancedSucceeds(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	err := s.AppendTransaction(ctx, []Entry{
		{TxID: "tx1", AccountID: "a1", Amount: -500, Timestamp: time.Now()},
		{TxID: "tx1", AccountID: "a2", Amount: 500, Timestamp: time.Now()},
	})
	if err != nil {
		t.Fatalf("AppendTransaction: %v", err)
	}

	bal, err := s.Balance(ctx, "a2")
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if bal != 500 {
		t.Fatalf("got balance %d, want 500", bal)
	}
}

func TestAppendTransaction_UnbalancedRejected(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	err := s.AppendTransaction(ctx, []Entry{
		{TxID: "tx2", AccountID: "a1", Amount: -500, Timestamp: time.Now()},
		{TxID: "tx2", AccountID: "a2", Amount: 400, Timestamp: time.Now()},
	})
	if !errors.Is(err, ErrUnbalancedEntries) {
		t.Fatalf("expected ErrUnbalancedEntries, got %v", err)
	}

	hist, err := s.History(ctx, "a1")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 0 {
		t.Fatalf("expected no entries written for rejected transaction, got %d", len(hist))
	}
}

func TestAppendTransaction_OverflowingSumRejected(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// math.MaxInt64 + math.MaxInt64 + 2 wraps around to 0 in int64
	// arithmetic, which would otherwise slip an unbalanced batch past a
	// naive sum check.
	err := s.AppendTransaction(ctx, []Entry{
		{TxID: "tx-overflow", AccountID: "a1", Amount: math.MaxInt64, Timestamp: time.Now()},
		{TxID: "tx-overflow", AccountID: "a2", Amount: math.MaxInt64, Timestamp: time.Now()},
		{TxID: "tx-overflow", AccountID: "a3", Amount: 2, Timestamp: time.Now()},
	})
	if !errors.Is(err, ErrAmountOverflow) {
		t.Fatalf("expected ErrAmountOverflow, got %v", err)
	}

	hist, err := s.History(ctx, "a1")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 0 {
		t.Fatalf("expected no entries written for the overflowing transaction, got %d", len(hist))
	}
}

func TestHistory_OrderedByTime(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	t1 := time.Now()
	t2 := t1.Add(time.Minute)

	if err := s.AppendTransaction(ctx, []Entry{
		{TxID: "tx1", AccountID: "a1", Amount: -100, Timestamp: t1},
		{TxID: "tx1", AccountID: "a2", Amount: 100, Timestamp: t1},
	}); err != nil {
		t.Fatalf("AppendTransaction 1: %v", err)
	}
	if err := s.AppendTransaction(ctx, []Entry{
		{TxID: "tx2", AccountID: "a1", Amount: -50, Timestamp: t2},
		{TxID: "tx2", AccountID: "a2", Amount: 50, Timestamp: t2},
	}); err != nil {
		t.Fatalf("AppendTransaction 2: %v", err)
	}

	hist, err := s.History(ctx, "a1")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(hist))
	}
	if hist[0].TxID != "tx1" || hist[1].TxID != "tx2" {
		t.Fatalf("expected tx1 before tx2, got %v then %v", hist[0].TxID, hist[1].TxID)
	}
}

func TestCheckInvariant_OKAfterBalancedWrites(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.AppendTransaction(ctx, []Entry{
		{TxID: "tx1", AccountID: "a1", Amount: -100, Timestamp: time.Now()},
		{TxID: "tx1", AccountID: "a2", Amount: 100, Timestamp: time.Now()},
	}); err != nil {
		t.Fatalf("AppendTransaction: %v", err)
	}

	ok, bad, err := s.CheckInvariant(ctx)
	if err != nil {
		t.Fatalf("CheckInvariant: %v", err)
	}
	if !ok || len(bad) != 0 {
		t.Fatalf("expected ok=true, no violations, got ok=%v bad=%v", ok, bad)
	}
}
