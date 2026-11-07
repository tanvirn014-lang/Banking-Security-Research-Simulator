// Package ledger implements the double-entry ledger store: every
// transaction is a balanced set of entries, and an account's balance is
// derived from them, never a directly mutable field.
package ledger

import (
	"context"
	"time"

	"banksec-lab/internal/apperr"
	"banksec-lab/internal/domain"
)

// Entry is one balance-affecting row belonging to a transaction.
type Entry struct {
	TxID      domain.TransactionID
	AccountID domain.AccountID
	Amount    domain.Money
	Timestamp time.Time
}

// State is a full snapshot of the ledger: every entry plus the
// invariant check's own result, taken together. Not returned by Store
// itself -- see internal/harness/oracle.go, which builds one from a
// single AllEntries call and computes ViolatingTxIDs in Go from the
// returned Entries (not a second CheckInvariant query), so Entries and
// ViolatingTxIDs can never disagree with each other, even under a
// concurrent writer.
type State struct {
	Entries        []Entry
	InvariantOK    bool
	ViolatingTxIDs []domain.TransactionID
}

// Store is the double-entry ledger's storage interface.
type Store interface {
	// CreateAccount persists a new account with the given owner and
	// returns its generated ID. Account ownership is persistent state
	// (it must survive across separate process/CLI invocations), which
	// is why it lives here rather than in backend's in-memory state.
	CreateAccount(ctx context.Context, owner domain.PrincipalID) (domain.AccountID, error)
	// AccountOwner returns acct's owner, or ok=false if the account
	// does not exist.
	AccountOwner(ctx context.Context, acct domain.AccountID) (owner domain.PrincipalID, ok bool, err error)
	AppendTransaction(ctx context.Context, entries []Entry) error
	Balance(ctx context.Context, acct domain.AccountID) (domain.Money, error)
	History(ctx context.Context, acct domain.AccountID) ([]Entry, error)
	// AllEntries returns every entry across every account, in insertion
	// order. Used by internal/harness's Oracle to build a full ledger
	// snapshot for attack-scenario verification.
	AllEntries(ctx context.Context) ([]Entry, error)
	CheckInvariant(ctx context.Context) (ok bool, violatingTxIDs []domain.TransactionID, err error)
	// Close releases the store's underlying resources (e.g. its database
	// handle). Required for file-backed stores to be removable afterward.
	Close() error
}

// ErrUnbalancedEntries is returned when a transaction's entries do not sum
// to zero; AppendTransaction rejects the whole batch before writing anything.
var ErrUnbalancedEntries = apperr.New(apperr.CodeValidation, "entries do not sum to zero")

// ErrAmountOverflow is returned when summing a transaction's entries would
// overflow int64 — silently wrapping could otherwise let an unbalanced
// batch slip past the zero-sum check.
var ErrAmountOverflow = apperr.New(apperr.CodeValidation, "transaction amount overflow")
