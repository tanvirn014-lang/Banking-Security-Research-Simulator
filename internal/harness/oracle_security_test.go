package harness

import (
	"context"
	"sync"
	"testing"
	"time"

	"banksec-lab/internal/domain"
	"banksec-lab/internal/ledger"
)

// TestKeySnapshot_NeverRecordsAuditEvent is the regression test for
// Milestone 7 security review finding I4: Oracle.KeySnapshot used to
// call keystore.Store.Get, which records a key_access audit event for
// every call -- so a Scenario's Verify merely *checking* a key's
// metadata polluted the audit trail as if it were a real material
// access, indistinguishable from an attacker's own key access.
func TestKeySnapshot_NeverRecordsAuditEvent(t *testing.T) {
	ctx := context.Background()
	_, k, a, o := newTestOracleStores(t)

	meta, err := k.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	start := time.Now().Add(-time.Minute)
	for i := 0; i < 4; i++ {
		if _, err := o.KeySnapshot(ctx, meta.ID); err != nil {
			t.Fatalf("KeySnapshot: %v", err)
		}
	}

	events, err := a.Since(ctx, start)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	for _, e := range events {
		// Generate's own audit event is expected and correct; only a
		// read (Get/Meta) triggered by KeySnapshot must not appear.
		if e.Component == "keystore" && e.Operation != "Generate" {
			t.Fatalf("expected KeySnapshot to record no keystore audit event, found %+v", e)
		}
	}
}

// TestKeySnapshot_RevokedKeyReturnsNoError is the other half of finding
// I4: Get returns ErrKeyRevoked for a revoked key, which would make a
// Verify step that merely wants to *check* revocation status abort with
// an error instead of getting a clean answer.
func TestKeySnapshot_RevokedKeyReturnsNoError(t *testing.T) {
	ctx := context.Background()
	_, k, _, o := newTestOracleStores(t)

	meta, err := k.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := k.Revoke(ctx, meta.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := o.KeySnapshot(ctx, meta.ID)
	if err != nil {
		t.Fatalf("KeySnapshot on a revoked key: expected no error, got %v", err)
	}
	if got.RevokedAt == nil {
		t.Fatalf("expected RevokedAt to be set, got %+v", got)
	}
}

// TestLedgerSnapshot_InvariantMatchesEntries is the regression test for
// finding I5: LedgerSnapshot used two separate queries (AllEntries, then
// CheckInvariant), so a writer between them could produce a
// self-contradictory State -- entries implying a different set of
// violating transactions than ViolatingTxIDs actually names. Computing
// the invariant from the already-fetched Entries in Go (one query only)
// makes that structurally impossible.
func TestLedgerSnapshot_InvariantMatchesEntries(t *testing.T) {
	ctx := context.Background()
	l, _, _, o := newTestOracleStores(t)

	if err := l.AppendTransaction(ctx, []ledger.Entry{
		{TxID: "tx1", AccountID: "a1", Amount: -100, Timestamp: time.Now()},
		{TxID: "tx1", AccountID: "a2", Amount: 100, Timestamp: time.Now()},
	}); err != nil {
		t.Fatalf("AppendTransaction: %v", err)
	}

	state, err := o.LedgerSnapshot(ctx)
	if err != nil {
		t.Fatalf("LedgerSnapshot: %v", err)
	}

	sums := make(map[domain.TransactionID]domain.Money)
	for _, e := range state.Entries {
		sums[e.TxID] += e.Amount
	}
	wantBad := 0
	for _, sum := range sums {
		if sum != 0 {
			wantBad++
		}
	}
	if len(state.ViolatingTxIDs) != wantBad {
		t.Fatalf("State's Entries imply %d violating tx(s), but ViolatingTxIDs has %d: %+v", wantBad, len(state.ViolatingTxIDs), state)
	}
}

// TestLedgerSnapshot_ConsistentUnderConcurrentWriter is a bounded
// concurrency probe for finding I5: with a writer continuously
// appending unbalanced raw entries, every snapshot taken concurrently
// must still be internally self-consistent (ViolatingTxIDs always
// matches what Entries themselves imply) -- never "torn" between two
// separate reads of a changing table.
func TestLedgerSnapshot_ConsistentUnderConcurrentWriter(t *testing.T) {
	ctx := context.Background()
	l, _, _, o := newTestOracleStores(t)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			n++
			_ = l.AppendTransaction(ctx, []ledger.Entry{
				{TxID: domain.TransactionID("bg-tx"), AccountID: "bg-acct", Amount: domain.Money(n), Timestamp: time.Now()},
			})
		}
	}()

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		state, err := o.LedgerSnapshot(ctx)
		if err != nil {
			t.Fatalf("LedgerSnapshot: %v", err)
		}
		sums := make(map[domain.TransactionID]domain.Money)
		for _, e := range state.Entries {
			sums[e.TxID] += e.Amount
		}
		wantBad := 0
		for _, sum := range sums {
			if sum != 0 {
				wantBad++
			}
		}
		if len(state.ViolatingTxIDs) != wantBad {
			close(stop)
			wg.Wait()
			t.Fatalf("torn snapshot under concurrent writes: Entries imply %d violating tx(s), ViolatingTxIDs has %d", wantBad, len(state.ViolatingTxIDs))
		}
	}
	close(stop)
	wg.Wait()
}
