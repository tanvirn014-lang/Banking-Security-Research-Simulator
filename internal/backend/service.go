// Package backend implements the banking business logic: account
// management and the deposit/withdraw/transfer operations, built on top
// of the ledger, keystore, and audit packages.
//
// This baseline always enforces account ownership and always validates
// amounts — there is no vulnerable/hardened fork yet (Milestone 3 adds
// config.SecurityProfile.AuthzEnforced as a toggle on top of this). The
// whole service is guarded by a single mutex: every operation's
// balance-check-then-append sequence is atomic and safe under concurrent
// calls, which is this task's "hardened" starting point.
package backend

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"banksec-lab/internal/apperr"
	"banksec-lab/internal/audit"
	"banksec-lab/internal/config"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/keystore"
	"banksec-lab/internal/ledger"
)

// externalSourceAccount is a reserved synthetic account used as the
// balancing counter-entry for Deposit and Withdraw, which are single-sided
// from the caller's point of view but must still produce a balanced
// double-entry transaction (ledger.Store requires entries to sum to zero).
// It represents money entering or leaving the simulated system, never a
// real account, and is never exposed through Service's public API.
const externalSourceAccount domain.AccountID = "external"

// maxAccountBalance bounds how high any single account's balance may go.
// Without this, a deposit near math.MaxInt64 can leave an account whose
// balance SQLite's own SUM(amount) aggregation later overflows at the
// SQL layer (a runtime error on every subsequent read of that account,
// confirmed by probe during review) -- this cap keeps every legitimate
// balance far below that boundary.
const maxAccountBalance domain.Money = math.MaxInt64 / 2

// raceWindowForVulnerableMode is injected between reading a balance and
// appending the resulting transaction when SecurityProfile.AtomicityEnforced
// is false, so the TOCTOU window this models is reliably, deterministically
// reproducible in tests -- per Task 15's requirement that each vulnerability
// have a deterministic demonstration, not one dependent on incidental
// goroutine-scheduling luck.
const raceWindowForVulnerableMode = 5 * time.Millisecond

// Service is the banking backend's interface.
type Service interface {
	CreateAccount(ctx context.Context, owner domain.PrincipalID) (domain.AccountID, error)
	Deposit(ctx context.Context, actor domain.Principal, acct domain.AccountID, amount domain.Money) error
	Withdraw(ctx context.Context, actor domain.Principal, acct domain.AccountID, amount domain.Money) error
	Transfer(ctx context.Context, actor domain.Principal, from, to domain.AccountID, amount domain.Money) error
	Balance(ctx context.Context, actor domain.Principal, acct domain.AccountID) (domain.Money, error)
	History(ctx context.Context, actor domain.Principal, acct domain.AccountID) ([]ledger.Entry, error)
}

var ErrInsufficientFunds = apperr.New(apperr.CodeConflict, "insufficient funds")
var ErrUnauthorized = apperr.New(apperr.CodeUnauthorized, "unauthorized")
var ErrValidation = apperr.New(apperr.CodeValidation, "validation failed")
var ErrAccountNotFound = apperr.New(apperr.CodeNotFound, "account not found")

type service struct {
	ledger ledger.Store
	// keystore is accepted and wired for later milestones' use; this
	// task's business logic does not call it yet.
	keystore keystore.Store
	audit    audit.Stream
	profile  config.SecurityProfile

	mu sync.Mutex
}

// newTxID and newEventID generate random, collision-resistant IDs rather
// than per-process counters: a fresh Service is constructed for every CLI
// invocation against the same persistent stores, so counters restarting at
// 1 would collide with IDs already written by earlier invocations (audit's
// ID is a primary key, so a collision silently drops the event).

func (s *service) newTxID() domain.TransactionID {
	return domain.TransactionID("tx-" + randomHex(16))
}

func (s *service) newEventID() string {
	return "evt-" + randomHex(16)
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is not something a caller can sensibly
		// recover from; it would mean the OS CSPRNG is unavailable.
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(buf)
}

// NewService constructs a banking Service. Authorization enforcement is
// gated by p.AuthzEnforced; input validation (amounts, account existence)
// is always on regardless of profile (ARCHITECTURE.md §6).
func NewService(l ledger.Store, k keystore.Store, a audit.Stream, p config.SecurityProfile) Service {
	return &service{
		ledger:   l,
		keystore: k,
		audit:    a,
		profile:  p,
	}
}

func (s *service) record(ctx context.Context, op string, actor domain.PrincipalID, outcome string, txID *domain.TransactionID) {
	if err := s.audit.Record(ctx, audit.Event{
		ID:        s.newEventID(),
		Timestamp: time.Now(),
		Type:      op,
		Component: "backend",
		Actor:     actor,
		Operation: op,
		Outcome:   outcome,
		TxID:      txID,
	}); err != nil {
		slog.Default().Error("failed to record audit event", "operation", op, "actor", actor, "error", err)
	}
}

func (s *service) CreateAccount(ctx context.Context, owner domain.PrincipalID) (domain.AccountID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	acct, err := s.ledger.CreateAccount(ctx, owner)
	if err != nil {
		s.record(ctx, "CreateAccount", owner, "rejected: "+err.Error(), nil)
		return "", err
	}

	s.record(ctx, "CreateAccount", owner, "ok", nil)
	return acct, nil
}

// checkOwnership enforces two distinct things: that acct exists (always,
// in both modes -- this is input validation, not a security control) and
// that actor owns it (only when s.profile.AuthzEnforced -- the
// deliberately exploitable surface in vulnerable mode).
func (s *service) checkOwnership(ctx context.Context, actor domain.Principal, acct domain.AccountID) error {
	owner, ok, err := s.ledger.AccountOwner(ctx, acct)
	if err != nil {
		return err
	}
	if !ok {
		return ErrAccountNotFound
	}
	if s.profile.AuthzEnforced && owner != actor.ID {
		return ErrUnauthorized
	}
	return nil
}

func (s *service) Deposit(ctx context.Context, actor domain.Principal, acct domain.AccountID, amount domain.Money) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if amount <= 0 {
		s.record(ctx, "Deposit", actor.ID, "rejected: validation", nil)
		return ErrValidation
	}
	if err := s.checkOwnership(ctx, actor, acct); err != nil {
		s.record(ctx, "Deposit", actor.ID, "rejected: "+err.Error(), nil)
		return err
	}

	bal, err := s.ledger.Balance(ctx, acct)
	if err != nil {
		s.record(ctx, "Deposit", actor.ID, "rejected: "+err.Error(), nil)
		return err
	}
	if bal > maxAccountBalance-amount {
		s.record(ctx, "Deposit", actor.ID, "rejected: would overflow balance cap", nil)
		return ErrValidation
	}

	txID := s.newTxID()
	err = s.ledger.AppendTransaction(ctx, []ledger.Entry{
		{TxID: txID, AccountID: acct, Amount: amount, Timestamp: time.Now()},
		{TxID: txID, AccountID: externalSourceAccount, Amount: -amount, Timestamp: time.Now()},
	})
	if err != nil {
		s.record(ctx, "Deposit", actor.ID, "rejected: "+err.Error(), &txID)
		return err
	}
	s.record(ctx, "Deposit", actor.ID, "ok", &txID)
	return nil
}

func (s *service) Withdraw(ctx context.Context, actor domain.Principal, acct domain.AccountID, amount domain.Money) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if amount <= 0 {
		s.record(ctx, "Withdraw", actor.ID, "rejected: validation", nil)
		return ErrValidation
	}
	if err := s.checkOwnership(ctx, actor, acct); err != nil {
		s.record(ctx, "Withdraw", actor.ID, "rejected: "+err.Error(), nil)
		return err
	}

	bal, err := s.ledger.Balance(ctx, acct)
	if err != nil {
		s.record(ctx, "Withdraw", actor.ID, "rejected: "+err.Error(), nil)
		return err
	}
	if bal < amount {
		s.record(ctx, "Withdraw", actor.ID, "rejected: insufficient funds", nil)
		return ErrInsufficientFunds
	}

	txID := s.newTxID()
	err = s.ledger.AppendTransaction(ctx, []ledger.Entry{
		{TxID: txID, AccountID: acct, Amount: -amount, Timestamp: time.Now()},
		{TxID: txID, AccountID: externalSourceAccount, Amount: amount, Timestamp: time.Now()},
	})
	if err != nil {
		s.record(ctx, "Withdraw", actor.ID, "rejected: "+err.Error(), &txID)
		return err
	}
	s.record(ctx, "Withdraw", actor.ID, "ok", &txID)
	return nil
}

func (s *service) Transfer(ctx context.Context, actor domain.Principal, from, to domain.AccountID, amount domain.Money) error {
	if amount <= 0 {
		s.record(ctx, "Transfer", actor.ID, "rejected: validation", nil)
		return ErrValidation
	}
	if from == to {
		s.record(ctx, "Transfer", actor.ID, "rejected: validation", nil)
		return ErrValidation
	}
	if err := s.checkOwnership(ctx, actor, from); err != nil {
		s.record(ctx, "Transfer", actor.ID, "rejected: "+err.Error(), nil)
		return err
	}
	if _, ok, err := s.ledger.AccountOwner(ctx, to); err != nil {
		s.record(ctx, "Transfer", actor.ID, "rejected: "+err.Error(), nil)
		return err
	} else if !ok {
		s.record(ctx, "Transfer", actor.ID, "rejected: destination account not found", nil)
		return ErrAccountNotFound
	}

	// The balance-check-then-append sequence below is the ledger
	// integrity-critical section. Hardened mode serializes it with the
	// service-wide mutex, making concurrent Transfers atomic. Vulnerable
	// mode deliberately does not -- see raceWindowForVulnerableMode below.
	if s.profile.AtomicityEnforced {
		s.mu.Lock()
		defer s.mu.Unlock()
	}

	bal, err := s.ledger.Balance(ctx, from)
	if err != nil {
		s.record(ctx, "Transfer", actor.ID, "rejected: "+err.Error(), nil)
		return err
	}
	if bal < amount {
		s.record(ctx, "Transfer", actor.ID, "rejected: insufficient funds", nil)
		return ErrInsufficientFunds
	}

	toBal, err := s.ledger.Balance(ctx, to)
	if err != nil {
		s.record(ctx, "Transfer", actor.ID, "rejected: "+err.Error(), nil)
		return err
	}
	if toBal > maxAccountBalance-amount {
		s.record(ctx, "Transfer", actor.ID, "rejected: would overflow destination balance cap", nil)
		return ErrValidation
	}

	if !s.profile.AtomicityEnforced {
		// Deliberate, deterministic TOCTOU window: every concurrent
		// Transfer that reaches this point has already read a balance
		// snapshot above; sleeping here (instead of serializing) lets
		// them all proceed to append below from that same stale read --
		// the vulnerability this profile demonstrates.
		time.Sleep(raceWindowForVulnerableMode)
	}

	txID := s.newTxID()
	err = s.ledger.AppendTransaction(ctx, []ledger.Entry{
		{TxID: txID, AccountID: from, Amount: -amount, Timestamp: time.Now()},
		{TxID: txID, AccountID: to, Amount: amount, Timestamp: time.Now()},
	})
	if err != nil {
		s.record(ctx, "Transfer", actor.ID, "rejected: "+err.Error(), &txID)
		return err
	}
	s.record(ctx, "Transfer", actor.ID, "ok", &txID)
	return nil
}

func (s *service) Balance(ctx context.Context, actor domain.Principal, acct domain.AccountID) (domain.Money, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkOwnership(ctx, actor, acct); err != nil {
		s.record(ctx, "Balance", actor.ID, "rejected: "+err.Error(), nil)
		return 0, err
	}
	bal, err := s.ledger.Balance(ctx, acct)
	if err != nil {
		s.record(ctx, "Balance", actor.ID, "rejected: "+err.Error(), nil)
		return 0, err
	}
	s.record(ctx, "Balance", actor.ID, "ok", nil)
	return bal, nil
}

func (s *service) History(ctx context.Context, actor domain.Principal, acct domain.AccountID) ([]ledger.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkOwnership(ctx, actor, acct); err != nil {
		s.record(ctx, "History", actor.ID, "rejected: "+err.Error(), nil)
		return nil, err
	}
	hist, err := s.ledger.History(ctx, acct)
	if err != nil {
		s.record(ctx, "History", actor.ID, "rejected: "+err.Error(), nil)
		return nil, err
	}
	s.record(ctx, "History", actor.ID, "ok", nil)
	return hist, nil
}
