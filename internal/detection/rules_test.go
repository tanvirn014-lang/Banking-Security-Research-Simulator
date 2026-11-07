package detection

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/ledger"
	"banksec-lab/internal/testsupport"
)

// stubLedger is a minimal ledger.Store whose CheckInvariant result is
// configurable, for testing balanceInvariantRule without a real SQLite
// file in a corrupted/locked state.
type stubLedger struct {
	mu                  sync.Mutex
	invariantOK         bool
	invariantViolations []domain.TransactionID
	invariantErr        error
}

func (s *stubLedger) CreateAccount(ctx context.Context, owner domain.PrincipalID) (domain.AccountID, error) {
	return "", nil
}
func (s *stubLedger) AccountOwner(ctx context.Context, acct domain.AccountID) (domain.PrincipalID, bool, error) {
	return "", false, nil
}
func (s *stubLedger) AppendTransaction(ctx context.Context, entries []ledger.Entry) error { return nil }
func (s *stubLedger) Balance(ctx context.Context, acct domain.AccountID) (domain.Money, error) {
	return 0, nil
}
func (s *stubLedger) History(ctx context.Context, acct domain.AccountID) ([]ledger.Entry, error) {
	return nil, nil
}
func (s *stubLedger) AllEntries(ctx context.Context) ([]ledger.Entry, error) { return nil, nil }
func (s *stubLedger) CheckInvariant(ctx context.Context) (bool, []domain.TransactionID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.invariantOK, s.invariantViolations, s.invariantErr
}
func (s *stubLedger) Close() error { return nil }

func backendEvent(id string) audit.Event {
	return audit.Event{ID: id, Timestamp: time.Now(), Type: "op", Component: "backend", Operation: "op", Outcome: "ok"}
}

// TestBalanceInvariantRule_CheckInvariantErrorSurfaces is the regression
// test for security review finding I9: Evaluate treated a CheckInvariant
// error identically to "no violation", silently hiding it -- e.g. an
// attacker holding a lock on ledger.db past its busy_timeout could make
// the invariant query fail and never be flagged.
func TestBalanceInvariantRule_CheckInvariantErrorSurfaces(t *testing.T) {
	stub := &stubLedger{invariantErr: errors.New("db locked")}
	rule := NewBalanceInvariantRule(stub)

	triggered, detail := rule.Evaluate([]audit.Event{backendEvent("e1")})
	if !triggered {
		t.Fatalf("expected a CheckInvariant error to trigger the rule, got triggered=false")
	}
	if !strings.Contains(detail, "db locked") {
		t.Fatalf("expected detail to mention the underlying error, got %q", detail)
	}
}

// TestBalanceInvariantRule_DedupesRepeatedTrigger is the regression test
// for finding I10: a single violation re-triggered a fresh detection
// event on every subsequent "backend" event, growing the audit log
// without bound and burying any new detection in a flood of repeats.
func TestBalanceInvariantRule_DedupesRepeatedTrigger(t *testing.T) {
	stub := &stubLedger{invariantOK: false, invariantViolations: []domain.TransactionID{"bad-tx"}}
	rule := NewBalanceInvariantRule(stub)

	triggerCount := 0
	for i := 0; i < 10; i++ {
		triggered, _ := rule.Evaluate([]audit.Event{backendEvent("e1")})
		if triggered {
			triggerCount++
		}
	}
	if triggerCount != 1 {
		t.Fatalf("expected the same offending transaction to trigger exactly once across 10 evaluations, got %d", triggerCount)
	}

	// A genuinely new violation must still be reported.
	stub.mu.Lock()
	stub.invariantViolations = []domain.TransactionID{"bad-tx", "another-bad-tx"}
	stub.mu.Unlock()
	triggered, detail := rule.Evaluate([]audit.Event{backendEvent("e2")})
	if !triggered {
		t.Fatalf("expected a newly-seen offending transaction to trigger, got triggered=false")
	}
	if !strings.Contains(detail, "another-bad-tx") {
		t.Fatalf("expected detail to name the new transaction, got %q", detail)
	}
}

// TestAuditChainRule_DetectsBrokenChain is the direct unit test for the
// audit-chain-violation rule (Milestone 8 Task 36, ATTACK_SURFACES.md
// §3's audit-tampering variant): a raw-SQL tamper against a
// hash-chained stream must trigger the rule.
func TestAuditChainRule_DetectsBrokenChain(t *testing.T) {
	ctx := context.Background()
	path := testsupport.TempSQLitePath(t)
	a, err := audit.NewSQLiteStream(path, true)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStream: %v", err)
	}
	defer a.Close()

	if err := a.Record(ctx, audit.Event{ID: "e1", Timestamp: time.Now(), Type: "op"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE events SET outcome = 'tampered' WHERE id = 'e1'`); err != nil {
		t.Fatalf("tamper row: %v", err)
	}

	rule := NewAuditChainRule(a)
	triggered, detail := rule.Evaluate([]audit.Event{backendEvent("e2")})
	if !triggered {
		t.Fatalf("expected a broken hash chain to trigger the rule, got triggered=false")
	}
	if detail == "" {
		t.Fatalf("expected a non-empty detail describing the break")
	}
}

// TestAuditChainRule_NotEnabledNeverTriggers mirrors
// TestAuditChainRule_DetectsBrokenChain under hashChained=false
// (vulnerable mode): VerifyChain returns ErrChainNotEnabled, which must
// be treated as "nothing to check", never as a trigger.
func TestAuditChainRule_NotEnabledNeverTriggers(t *testing.T) {
	ctx := context.Background()
	a, err := audit.NewSQLiteStream(testsupport.TempSQLitePath(t), false)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStream: %v", err)
	}
	defer a.Close()
	if err := a.Record(ctx, audit.Event{ID: "e1", Timestamp: time.Now(), Type: "op"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	rule := NewAuditChainRule(a)
	triggered, _ := rule.Evaluate([]audit.Event{backendEvent("e2")})
	if triggered {
		t.Fatalf("expected hashChained=false to never trigger the rule, got triggered=true")
	}
}

// TestAuditChainRule_DedupesRepeatedTrigger mirrors
// TestBalanceInvariantRule_DedupesRepeatedTrigger: once a broken chain
// has been reported, it must not re-trigger on every subsequent event.
func TestAuditChainRule_DedupesRepeatedTrigger(t *testing.T) {
	ctx := context.Background()
	path := testsupport.TempSQLitePath(t)
	a, err := audit.NewSQLiteStream(path, true)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStream: %v", err)
	}
	defer a.Close()
	if err := a.Record(ctx, audit.Event{ID: "e1", Timestamp: time.Now(), Type: "op"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE events SET outcome = 'tampered' WHERE id = 'e1'`); err != nil {
		t.Fatalf("tamper row: %v", err)
	}

	rule := NewAuditChainRule(a)
	triggerCount := 0
	for i := 0; i < 5; i++ {
		triggered, _ := rule.Evaluate([]audit.Event{backendEvent("e2")})
		if triggered {
			triggerCount++
		}
	}
	if triggerCount != 1 {
		t.Fatalf("expected exactly one trigger across 5 evaluations of the same break, got %d", triggerCount)
	}
}

// TestAuditChainRule_NewBreakLocationReTriggers is the regression test
// for security review finding I1's defense-in-depth fix: the dedup
// latch is keyed by the broken event's own ID (or a fixed marker for
// truncation), not a single permanent bool -- a second, distinct break
// must still be reported even after an earlier, different break was
// already reported once.
func TestAuditChainRule_NewBreakLocationReTriggers(t *testing.T) {
	ctx := context.Background()
	path := testsupport.TempSQLitePath(t)
	a, err := audit.NewSQLiteStream(path, true)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStream: %v", err)
	}
	defer a.Close()
	for _, id := range []string{"e1", "e2"} {
		if err := a.Record(ctx, audit.Event{ID: id, Timestamp: time.Now(), Type: "op"}); err != nil {
			t.Fatalf("Record %s: %v", id, err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer db.Close()

	rule := NewAuditChainRule(a)

	if _, err := db.Exec(`UPDATE events SET outcome = 'tampered-1' WHERE id = 'e1'`); err != nil {
		t.Fatalf("first tamper: %v", err)
	}
	triggered1, detail1 := rule.Evaluate([]audit.Event{backendEvent("e3")})
	if !triggered1 {
		t.Fatalf("expected the first break (at e1) to trigger")
	}

	// Same break, re-evaluated: must not re-trigger (existing dedup
	// behavior, unchanged).
	if triggered, _ := rule.Evaluate([]audit.Event{backendEvent("e4")}); triggered {
		t.Fatalf("expected the same break (still at e1) not to re-trigger")
	}

	// A genuinely different kind of break: restore e1 (undo the first
	// tamper) and delete e2 -- VerifyChain now reports a truncation
	// (brokenAt=nil), a different key than "e1". Must trigger again.
	if _, err := db.Exec(`UPDATE events SET outcome = '' WHERE id = 'e1'`); err != nil {
		t.Fatalf("restore e1: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM events WHERE id = 'e2'`); err != nil {
		t.Fatalf("delete e2: %v", err)
	}
	triggered2, detail2 := rule.Evaluate([]audit.Event{backendEvent("e5")})
	if !triggered2 {
		t.Fatalf("expected a new, distinct break (truncation) to trigger again after an earlier different break was already reported")
	}
	if detail1 == detail2 {
		t.Fatalf("expected the two triggers to name different break locations, both said %q", detail1)
	}
}
