package detection

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/ledger"
	"banksec-lab/internal/testsupport"
)

func TestRegisterConfigured_OnlyRegistersListedRules(t *testing.T) {
	rule := NewBalanceInvariantRule(&stubLedger{invariantOK: true})

	e1 := NewEngine().(*engine)
	RegisterConfigured(e1, rule, []domain.DetectionRuleID{"some-other-rule"})
	if len(e1.rules) != 0 {
		t.Fatalf("expected the rule not to be registered when its ID is absent from configured, got %d rules", len(e1.rules))
	}

	e2 := NewEngine().(*engine)
	RegisterConfigured(e2, rule, []domain.DetectionRuleID{BalanceInvariantRuleID})
	if len(e2.rules) != 1 {
		t.Fatalf("expected the rule to be registered when its ID is present in configured, got %d rules", len(e2.rules))
	}
}

// TestValidateDetectionRules_RejectsUnknownID is the regression test for
// security review finding I6: a typo'd or unknown rule ID in a
// profile's detection_rules used to silently result in zero rules
// registered (RegisterConfigured just finds no match), with nothing to
// tell an operator their "hardened" profile is actually running no
// detection at all.
func TestValidateDetectionRules_RejectsUnknownID(t *testing.T) {
	known := []domain.DetectionRuleID{BalanceInvariantRuleID}

	if err := ValidateDetectionRules([]domain.DetectionRuleID{BalanceInvariantRuleID}, known); err != nil {
		t.Fatalf("expected a known rule ID to validate cleanly, got %v", err)
	}
	if err := ValidateDetectionRules(nil, known); err != nil {
		t.Fatalf("expected an empty configured list to validate cleanly, got %v", err)
	}
	if err := ValidateDetectionRules([]domain.DetectionRuleID{"balance-invariant-violaton"}, known); err == nil {
		t.Fatalf("expected a typo'd rule ID to be rejected, got no error")
	}
}

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
