package detection

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/ledger"
	"banksec-lab/internal/testsupport"
)

// breakInvariant inserts a single, unmatched entry directly into the
// ledger's storage, bypassing AppendTransaction's own balance check --
// simulating a bug or an attacker writing straight to the database file.
func breakInvariant(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw ledger db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(
		`INSERT INTO entries (tx_id, account_id, amount, timestamp) VALUES (?, ?, ?, ?)`,
		"unbalanced-tx", "acct-1", 1, time.Now().UnixNano(),
	); err != nil {
		t.Fatalf("insert unbalanced entry: %v", err)
	}
}

func waitForDetectionEvent(t *testing.T, ctx context.Context, stream audit.Stream, since time.Time) audit.Event {
	t.Helper()
	events, err := stream.Since(ctx, since)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	for _, e := range events {
		if e.Type == "detection" {
			return e
		}
	}
	t.Fatalf("expected a detection event, found none among %d events: %+v", len(events), events)
	return audit.Event{}
}

// TestEngine_RegisterRunConcurrentWithRecord is the regression test for
// security review finding I12: Register appended to e.rules without
// taking e.mu, while handle (run synchronously from Record) read e.rules
// under e.mu -- a data race if Register is ever called after Run, even
// though the normal wiring pattern (cli.go) always calls it before.
func TestEngine_RegisterRunConcurrentWithRecord(t *testing.T) {
	ctx := context.Background()
	stream, err := audit.NewSQLiteStream(testsupport.TempSQLitePath(t), false)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStream: %v", err)
	}
	defer stream.Close()

	e := NewEngine()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := e.Run(runCtx, stream); err != nil {
		t.Fatalf("Run: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			e.Register(NewBalanceInvariantRule(&stubLedger{invariantOK: true}))
		}
	}()

	for i := 0; i < 50; i++ {
		if err := stream.Record(ctx, backendEvent(fmt.Sprintf("race-%d", i))); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	<-done
}

func TestDetectionEngine_RuleTriggersOnViolation(t *testing.T) {
	ctx := context.Background()

	ledgerPath := testsupport.TempSQLitePath(t)
	l, err := ledger.NewSQLiteStore(ledgerPath)
	if err != nil {
		t.Fatalf("ledger.NewSQLiteStore: %v", err)
	}
	defer l.Close()

	stream, err := audit.NewSQLiteStream(testsupport.TempSQLitePath(t), false)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStream: %v", err)
	}
	defer stream.Close()

	e := NewEngine()
	e.Register(NewBalanceInvariantRule(l))

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := e.Run(runCtx, stream); err != nil {
		t.Fatalf("Run: %v", err)
	}

	start := time.Now().Add(-time.Minute)

	breakInvariant(t, ledgerPath)

	// Simulate a normal backend operation's own audit event -- this is
	// what the rule evaluates against (see rules.go's documented choice
	// to trigger on every "backend"-component event rather than a timer).
	if err := stream.Record(ctx, audit.Event{ID: "trigger-1", Timestamp: time.Now(), Type: "deposit", Component: "backend", Operation: "Deposit", Outcome: "ok"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	detected := waitForDetectionEvent(t, ctx, stream, start)
	if detected.Component != "detection" {
		t.Fatalf("expected Component=detection, got %+v", detected)
	}
	if detected.Outcome != "triggered" {
		t.Fatalf("expected Outcome=triggered, got %+v", detected)
	}
}
