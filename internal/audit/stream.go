// Package audit implements the append-only event stream. This task's
// stream is the basic baseline (no integrity protection); hash-chaining
// and tamper detection arrive in Milestone 6.
package audit

import (
	"context"
	"time"

	"banksec-lab/internal/domain"
)

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

// Stream is the audit event stream's interface.
type Stream interface {
	Record(ctx context.Context, e Event) error
	Since(ctx context.Context, t time.Time) ([]Event, error)
	// Subscribe registers fn to be called synchronously, from Record,
	// for every event recorded after this call. It returns a function
	// that removes the subscription.
	Subscribe(fn func(Event)) (unsubscribe func())
	// Close releases the stream's underlying resources.
	Close() error
}
