// Package audit implements the append-only event stream, with an
// optional hash chain (Milestone 6) for tamper detection.
package audit

import (
	"context"
	"time"

	"banksec-lab/internal/apperr"
	"banksec-lab/internal/domain"
)

// ErrChainNotEnabled is returned by VerifyChain when the stream was
// constructed with hashChained=false (vulnerable mode never computes or
// stores hashes, so there is nothing to verify).
var ErrChainNotEnabled = apperr.New(apperr.CodeValidation, "audit hash chain not enabled for this stream")

// Event is one recorded security-relevant occurrence.
type Event struct {
	ID        string
	Timestamp time.Time
	Type      string
	Component string
	Actor     domain.PrincipalID
	Operation string
	Outcome   string
	TxID      *domain.TransactionID
	AttackID  *string
}

// Filter narrows a Filter query. A zero-value field means "no
// constraint on this field" -- e.g. an empty Component matches every
// component, a zero Since/Until leaves that end of the time range open.
type Filter struct {
	Component string
	AttackID  *string
	Since     time.Time
	Until     time.Time
}

// Stream is the audit event stream's interface.
type Stream interface {
	Record(ctx context.Context, e Event) error
	Since(ctx context.Context, t time.Time) ([]Event, error)
	// Filter returns every recorded event matching f, in the same order
	// Since returns them (ascending timestamp).
	Filter(ctx context.Context, f Filter) ([]Event, error)
	// Subscribe registers fn to be called synchronously, from Record,
	// for every event recorded after this call. It returns a function
	// that removes the subscription.
	Subscribe(fn func(Event)) (unsubscribe func())
	// VerifyChain recomputes the hash chain over every recorded event, in
	// insertion order, and compares it against what was stored at Record
	// time. ok is true iff every event's hash matches; otherwise brokenAt
	// names the ID of the first event whose stored hash no longer
	// matches the recomputed chain. Returns ErrChainNotEnabled if this
	// stream was constructed with hashChained=false.
	VerifyChain(ctx context.Context) (ok bool, brokenAt *string, err error)
	// Close releases the stream's underlying resources.
	Close() error
}
