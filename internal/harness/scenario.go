package harness

import (
	"context"
	"math/rand"
	"time"
)

// Evidence is whatever concrete facts a Scenario's Verify step gathered
// while deciding success/failure -- arbitrary key/value pairs (e.g. a
// ledger snapshot, a detection-event timestamp) a Runner can read back
// out to populate Result, and a StopCond can inspect to decide whether
// to halt further attempts.
type Evidence map[string]any

// Scenario is a single attack's complete, self-describing definition --
// every attribute the harness needs to register, discover, gate, run,
// and adjudicate it, with nothing supplied out-of-band at run time.
type Scenario struct {
	// ID is this attack's unique identifier (e.g.
	// "application-authz-bypass"). Registry rejects a duplicate.
	ID string
	// Category names the attack class (e.g. "application", "protocol",
	// "ledger", "key-management", "cryptographic").
	Category string
	// TargetComponent names the simulator component this attack targets
	// (e.g. "backend", "protocol", "keystore", "audit").
	TargetComponent string
	// RequiredConfig declaratively describes the profile settings this
	// scenario needs (e.g. {"crypto_profile": "weak-educational"}), for
	// discovery/filtering without having to run Prereqs. Zero-value
	// (nil/empty) means no declared requirement.
	RequiredConfig map[string]string
	// Prereqs reports whether this scenario can even be attempted
	// against the current environment (e.g. checking RequiredConfig's
	// claims hold for real via the Oracle). Exec/Verify are never
	// called when Prereqs returns false.
	Prereqs func(ctx context.Context, o Oracle) (ok bool, err error)
	// Exec is this attack's execution method: it drives the simulator
	// exactly as a real attacker would, through env.Client (the one real
	// external entrypoint -- type-assert to protocol.AttackClient for
	// raw frame access, or call env.NewClientConnection for a genuinely
	// separate concurrent connection) and/or env.Priv (an insider-style
	// bypass -- see privileged.go). Taking the whole Environment, rather
	// than just its Client/Priv fields, is what lets a scenario like the
	// concurrent-overdraft race (Milestone 8) open additional
	// connections against the same backend -- a single Client
	// serializes its own Send calls, so real concurrency needs more than
	// one. rnd is a Runner-provided, seed-derived random source, for
	// reproducible attacks that need randomness (e.g. race timing).
	Exec func(ctx context.Context, env *Environment, rnd *rand.Rand) error
	// Verify is this attack's success criteria, impact measurement, and
	// detection-result check, all in one: it inspects the Oracle (never
	// Exec's own return value) and reports whether the attack actually
	// succeeded, plus whatever Evidence it gathered along the way.
	Verify func(ctx context.Context, o Oracle) (success bool, evidence Evidence, err error)
	// StopCond, given the Evidence from one attempt, reports whether a
	// Runner driving repeated attempts (e.g. a brute-force) should stop.
	// May be nil, meaning "always stop after one attempt".
	StopCond func(e Evidence) bool
	// Timeout bounds one Exec+Verify attempt. Zero means "use the
	// caller's ctx deadline as-is, with no additional bound".
	Timeout time.Duration
}
