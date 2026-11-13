// Package experiment implements BankSec Lab's research experiment
// pipeline: a typed, validated experiment specification; a generator
// contract that the existing static attack corpus and new dynamic
// generators both satisfy; a canonical action contract with a
// validation boundary in front of the simulator; and structured,
// reproducible experiment records.
//
// The pipeline is deliberately additive. It does not replace
// internal/harness -- every candidate it produces, static or generated,
// is executed by the existing harness.Runner and adjudicated by the
// existing read-only harness.Oracle. What this package adds is the
// specification, generation, validation, and reporting layers around
// that unchanged core.
package experiment

import (
	"fmt"
	"sort"

	"banksec-lab/internal/domain"
	"banksec-lab/internal/protocol"
)

// Supported operation names. These are exactly the operations
// internal/protocol's server dispatches (see protocol/server.go's switch
// over Request.Op); an Action naming anything else is unsupported by
// construction, not merely disallowed by policy.
const (
	OpCreateAccount = "create-account"
	OpDeposit       = "deposit"
	OpWithdraw      = "withdraw"
	OpTransfer      = "transfer"
	OpBalance       = "balance"
	OpHistory       = "history"
)

// supportedOps is the closed set of operations the simulator can
// execute. Kept as a set rather than a slice so IsSupportedOp is a
// lookup, and exposed only through SupportedOps so no caller can
// mutate it.
var supportedOps = map[string]struct{}{
	OpCreateAccount: {},
	OpDeposit:       {},
	OpWithdraw:      {},
	OpTransfer:      {},
	OpBalance:       {},
	OpHistory:       {},
}

// SupportedOps returns the sorted set of operations the simulator can
// execute, as a fresh slice the caller may keep or modify.
func SupportedOps() []string {
	out := make([]string, 0, len(supportedOps))
	for op := range supportedOps {
		out = append(out, op)
	}
	sort.Strings(out)
	return out
}

// IsSupportedOp reports whether op is an operation the simulator can
// execute at all.
func IsSupportedOp(op string) bool {
	_, ok := supportedOps[op]
	return ok
}

// mutatingOps are the operations that can change ledger state. Read-only
// operations can still be unauthorized, but they can never violate a
// ledger-integrity invariant, so the validator and the mutation
// generator both need to tell the two apart.
var mutatingOps = map[string]struct{}{
	OpCreateAccount: {},
	OpDeposit:       {},
	OpWithdraw:      {},
	OpTransfer:      {},
}

// IsMutatingOp reports whether op can change ledger state.
func IsMutatingOp(op string) bool {
	_, ok := mutatingOps[op]
	return ok
}

// Action is the canonical, machine-readable representation of one
// operation a generator proposes against the simulated banking system.
//
// It carries exactly the fields protocol.Request carries -- an operation,
// an actor with a role, and string parameters -- plus provenance
// (Label), and nothing else. In particular it exposes no key material,
// no database handle, and no filesystem or network capability: an
// Action is a request to the banking application's own front door, so
// the strongest thing a generator can propose is something a hostile
// client could already have sent. Privileged insider bypasses
// (harness.PrivilegedAccess) are deliberately not representable here;
// only the reviewed static scenarios have that capability.
//
// JSON tags are present because an ActionPlan is part of an experiment
// record, and a recorded plan is what makes a finding reproducible.
type Action struct {
	Op     string            `json:"op"`
	Actor  domain.Principal  `json:"actor"`
	Params map[string]string `json:"params,omitempty"`
	// Label records where this action came from -- "seed" for an action
	// copied unchanged from a baseline scenario, or a mutation
	// descriptor such as "mutated:actor-swap". It is metadata for the
	// experiment record and never affects execution.
	Label string `json:"label,omitempty"`
}

// Request converts a validated Action into the protocol request the
// simulator's client accepts. The Params map is copied so a caller
// holding the Action cannot change a request already in flight.
func (a Action) Request() protocol.Request {
	var params map[string]string
	if a.Params != nil {
		params = make(map[string]string, len(a.Params))
		for k, v := range a.Params {
			params[k] = v
		}
	}
	return protocol.Request{Op: a.Op, Actor: a.Actor, Params: params}
}

// Clone returns a deep copy of a, so a generator can derive a mutated
// action without aliasing the Params map of the action it mutated.
func (a Action) Clone() Action {
	clone := a
	if a.Params != nil {
		clone.Params = make(map[string]string, len(a.Params))
		for k, v := range a.Params {
			clone.Params[k] = v
		}
	}
	return clone
}

// String renders an action compactly for a log line or a finding's
// reproduction notes. Parameter keys are sorted so the same action
// always renders identically -- a reproduction note that reordered
// itself between runs would not be a reproduction note.
func (a Action) String() string {
	keys := make([]string, 0, len(a.Params))
	for k := range a.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	s := fmt.Sprintf("%s actor=%s/%s", a.Op, a.Actor.ID, a.Actor.Role)
	for _, k := range keys {
		s += fmt.Sprintf(" %s=%s", k, a.Params[k])
	}
	return s
}
