package detection

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/ledger"
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
