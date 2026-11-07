package harness

import (
	"context"
	"testing"
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/crypto"
	"banksec-lab/internal/keystore"
	"banksec-lab/internal/ledger"
	"banksec-lab/internal/testsupport"
)

// newTestOracleStores wires a fresh ledger/keystore/audit trio for
// harness tests, returning them alongside an Oracle over them.
func newTestOracleStores(t *testing.T) (ledger.Store, keystore.Store, audit.Stream, Oracle) {
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

	return l, k, a, NewOracle(l, k, a)
}

func TestOracle_LedgerSnapshot_ReflectsRealState(t *testing.T) {
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
	if len(state.Entries) != 2 {
		t.Fatalf("expected 2 entries in the snapshot, got %d", len(state.Entries))
	}
	if !state.InvariantOK || len(state.ViolatingTxIDs) != 0 {
		t.Fatalf("expected a balanced ledger to report InvariantOK=true, got %+v", state)
	}
}

func TestScenario_PrereqsGateExecution(t *testing.T) {
	ctx := context.Background()
	_, _, _, o := newTestOracleStores(t)

	s := Scenario{
		ID: "test-prereqs-gate",
		Prereqs: func(ctx context.Context, o Oracle) (bool, error) {
			return false, nil
		},
	}

	ok, err := s.Prereqs(ctx, o)
	if err != nil {
		t.Fatalf("Prereqs: %v", err)
	}
	if ok {
		t.Fatalf("expected Prereqs to report false")
	}
	// Full "Prereqs gates execution" behavior (Exec never called when
	// Prereqs is false) is the Runner's job and is covered by
	// TestRunner_* in runner_test.go (Task 32); this test only confirms
	// Scenario.Prereqs itself is callable and reports the expected
	// answer given a real Oracle.
}
