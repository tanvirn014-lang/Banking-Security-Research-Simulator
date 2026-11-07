// Package agent is an offline-first, deterministic attack-selection
// framework that drives internal/harness's Scenario registry through
// its own approved, already-reviewed interfaces (Registry, Runner,
// Environment, Oracle) -- never anything new or privileged. It has no
// mandatory external dependency (no LLM API call anywhere in this
// package), never reaches outside the simulator (the same isolation
// guarantee internal/harness itself already provides to every Milestone
// 8 scenario), and every run is bounded by a caller-configured step
// Budget -- there is no unbounded or background execution path.
//
// See docs/AGENT_LLM_INTEGRATION.md for how a future LLM-driven Policy
// could be added later without weakening any of this.
package agent

import (
	"errors"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/domain"
)

// ErrNoActionsRemain is returned by Policy.Decide when it has exhausted
// every action it intends to try. Agent.Run treats this as a clean,
// expected stop (per the user's "stop ... when no actions remain"
// requirement), never as a failure.
var ErrNoActionsRemain = errors.New("agent: no actions remain to try")

// ActionKind identifies a registered harness.Scenario by its own ID.
// The agent framework never invents an ActionKind of its own -- every
// value comes from a harness Scenario the caller has already decided to
// make available (see Agent's own doc comment), so the agent can never
// select an action the harness hasn't registered.
type ActionKind string

// Action is one decision an Agent's Policy makes: which registered
// attack to attempt (Kind), and which account to attempt it against
// (Target) -- the framework's "parameter submission" capability. Target
// is recorded in every Decision, reflecting whatever account the Policy
// could currently see, but the underlying harness.Scenario.Exec (every
// Milestone 8 scenario is fully self-contained, creating its own account
// fixtures) does not itself consume Target -- see agent.go's doc comment
// and task-42-45-brief.md's disclosed "parameter submission" deviation
// for why reopening that already-reviewed interface was out of scope
// here. DeterministicPolicy deliberately does NOT key its own
// already-tried tracking by Target (see its doc comment for the real
// Detection-Engine-dedup interaction a per-target scheme caused) --
// Target is informational/decision-shaping only, never a dimension of
// "exhaustion" in this package's required baseline Policy.
type Action struct {
	Kind   ActionKind
	Target domain.AccountID
}

// Observation is everything a Policy sees before deciding its next
// Action -- an agent only ever sees what Agent.buildObservation
// explicitly populates from the harness Oracle's read-only view, never
// an ambient or privileged channel.
type Observation struct {
	// VisibleAccounts are every account ID buildObservation has found
	// from the ledger so far (derived from harness.Oracle.LedgerSnapshot's
	// entries). Empty before any scenario has created an account yet --
	// this is expected, not an error: every Milestone 8 scenario creates
	// its own account as part of its own Exec.
	VisibleAccounts []domain.AccountID
	// VisibleBalances is each VisibleAccounts entry's current ledger
	// balance (the sum of its entries' Amounts).
	VisibleBalances map[domain.AccountID]domain.Money
	// RecentAudit is every audit event recorded since the Agent's Run
	// began -- how a Policy observes the DETECTABLE consequences
	// (Milestone 6's audit stream, Milestone 8's Detection Engine rules)
	// of its own prior actions, i.e. "result interpretation": each
	// step's Observation reflects everything every earlier step's
	// scenario execution actually did.
	RecentAudit []audit.Event
	// StepsRemaining is the Agent's remaining step Budget at the time
	// this Observation was built, letting a Policy react to how much
	// budget it has left (e.g. to prioritize differently near the end).
	StepsRemaining int
}

// Policy decides an Agent's next Action from its current Observation.
// DeterministicPolicy (policy_deterministic.go) is this package's one
// required baseline implementation; docs/AGENT_LLM_INTEGRATION.md
// documents how a future LLM-backed Policy could implement this same
// interface without the Agent/Environment plumbing around it changing
// at all.
type Policy interface {
	// Decide returns ErrNoActionsRemain (and a zero Action) when it has
	// nothing left to try -- Agent.Run treats that as a clean stop, not
	// a failure.
	Decide(obs Observation) (Action, error)
}
