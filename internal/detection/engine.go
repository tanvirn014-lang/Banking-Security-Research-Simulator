// Package detection implements a rule-based Detection Engine: it
// subscribes to the audit event stream, evaluates every new event
// against a set of registered Rules, and records any trigger back into
// the same stream as a new Event (Type: "detection").
package detection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/domain"
)

// windowSize bounds how many recent events a Rule's Evaluate call sees.
// None of this package's current rules need more than the latest event,
// but a bounded window (rather than just the single newest event) lets a
// future multi-event pattern rule (e.g. "N failed auths in a row") work
// without changing the Engine/Rule contract.
const windowSize = 100

// Rule evaluates a window of recent audit events (oldest first, newest
// last) and reports whether it has triggered, plus a human-readable
// detail string describing why.
type Rule interface {
	ID() domain.DetectionRuleID
	Evaluate(window []audit.Event) (triggered bool, detail string)
}

// DetectionEvent is what a triggered Rule reports: which rule, when, and
// the audit event that triggered the evaluation. The Engine renders this
// into an audit.Event (Type: "detection") when recording it back into
// the stream -- see recordTrigger.
type DetectionEvent struct {
	RuleID       domain.DetectionRuleID
	Timestamp    time.Time
	RelatedEvent audit.Event
}

// Engine runs a set of registered Rules against a live audit.Stream.
type Engine interface {
	// Register adds r to the set of rules evaluated against every new
	// event. Safe to call concurrently with Run and with event handling.
	Register(r Rule)
	// Run subscribes to stream (synchronously -- every event recorded
	// after Run returns will be evaluated) and evaluates every new event
	// against every registered rule until ctx is canceled, at which
	// point it unsubscribes in the background. Run itself returns
	// immediately after subscribing; the engine then keeps running in
	// the background for the rest of ctx's lifetime, alongside the rest
	// of a wired stack's background work (e.g. the protocol server's
	// Serve loop).
	Run(ctx context.Context, stream audit.Stream) error
}

type engine struct {
	mu     sync.Mutex
	rules  []Rule
	window []audit.Event
}

// NewEngine constructs an Engine with no rules registered.
func NewEngine() Engine {
	return &engine{}
}

func (e *engine) Register(r Rule) {
	e.mu.Lock()
	e.rules = append(e.rules, r)
	e.mu.Unlock()
}

func (e *engine) Run(ctx context.Context, stream audit.Stream) error {
	unsubscribe := stream.Subscribe(func(ev audit.Event) {
		e.handle(ctx, stream, ev)
	})
	go func() {
		<-ctx.Done()
		unsubscribe()
	}()
	return nil
}

// handle evaluates one newly-recorded event against every registered
// rule, recording a "detection" event for each trigger. Runs
// synchronously from Stream.Record's own call to Subscribe's callbacks
// (see audit.Stream's doc comment) -- so a trigger is recorded before
// the operation that caused it has even returned to its own caller.
func (e *engine) handle(ctx context.Context, stream audit.Stream, ev audit.Event) {
	if ev.Component == "detection" {
		// Never let a detection event itself re-trigger a rule --
		// otherwise a rule that keeps matching would spam the stream
		// with detections-of-detections forever. Checked on Component,
		// which this package itself sets and no other producer does,
		// rather than Type, which is a free-form string other producers
		// could in principle set to "detection" too (security review
		// finding I13).
		return
	}

	e.mu.Lock()
	e.window = append(e.window, ev)
	if len(e.window) > windowSize {
		e.window = e.window[len(e.window)-windowSize:]
	}
	window := append([]audit.Event(nil), e.window...)
	rules := append([]Rule(nil), e.rules...)
	e.mu.Unlock()

	for _, r := range rules {
		triggered, detail := r.Evaluate(window)
		if !triggered {
			continue
		}
		e.recordTrigger(ctx, stream, DetectionEvent{RuleID: r.ID(), Timestamp: time.Now(), RelatedEvent: ev}, detail)
	}
}

func (e *engine) recordTrigger(ctx context.Context, stream audit.Stream, de DetectionEvent, detail string) {
	id, err := newEventID()
	if err != nil {
		slog.Default().Error("detection engine: failed to generate trigger event id", "rule", de.RuleID, "error", err)
		return
	}
	if err := stream.Record(ctx, audit.Event{
		ID:        id,
		Timestamp: de.Timestamp,
		Type:      "detection",
		Component: "detection",
		Actor:     de.RelatedEvent.Actor,
		Operation: fmt.Sprintf("%s: %s", de.RuleID, detail),
		Outcome:   "triggered",
		TxID:      de.RelatedEvent.TxID,
	}); err != nil {
		// Dropping this silently would mean a detection that fails to
		// write simply disappears without trace (security review
		// finding I9).
		slog.Default().Error("detection engine: failed to record trigger", "rule", de.RuleID, "error", err)
	}
}

func newEventID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate detection event id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
