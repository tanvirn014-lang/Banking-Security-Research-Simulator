package experiment

import (
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/ledger"
)

// Step is one action's complete record: what was proposed, what the
// validation boundary decided, whether it therefore reached the
// simulator, and what the simulator answered. Every field is recorded
// whether or not the action executed, because "the generator proposed
// something the boundary refused" is itself a result worth keeping.
type Step struct {
	Index      int              `json:"index"`
	Action     Action           `json:"action"`
	Validation ValidationResult `json:"validation"`
	// Executed is true only when Validation.Decision was DecisionAllow
	// and the request was actually sent.
	Executed bool `json:"executed"`
	// ResponseOK is the simulator's own verdict. A false here means the
	// banking system refused the operation -- a legitimate result, never
	// by itself a security finding.
	ResponseOK    bool              `json:"response_ok"`
	ResponseError string            `json:"response_error,omitempty"`
	ResponseData  map[string]string `json:"response_data,omitempty"`
	// TransportError records a failure to even exchange the request
	// (a closed pipe, a deadline), as distinct from a request the
	// simulator received and refused.
	TransportError string `json:"transport_error,omitempty"`
	DurationMS     int64  `json:"duration_ms"`
}

// IsSuccessfulMutation reports whether this step actually changed, or
// was accepted as changing, ledger state. Invariant checks use it to
// tell "nothing exercised this property" from "something did".
func (s Step) IsSuccessfulMutation() bool {
	return s.Executed && s.ResponseOK && IsMutatingOp(s.Action.Op)
}

// IsRefusedMutation reports whether this step was a state-changing
// operation that reached the simulator and was refused by it.
func (s Step) IsRefusedMutation() bool {
	return s.Executed && !s.ResponseOK && s.TransportError == "" && IsMutatingOp(s.Action.Op)
}

// Snapshot is the simulator state the Oracle exposed at one instant. It
// is the only evidence an invariant check is allowed to reason from:
// never a step's own claim, and never anything the attack code reported
// about itself.
type Snapshot struct {
	At          time.Time     `json:"at"`
	Ledger      ledger.State  `json:"-"`
	AuditEvents []audit.Event `json:"-"`
	// EntryCount and InvariantOK mirror the parts of Ledger a report
	// needs, since ledger.State itself is not serialized into records.
	EntryCount  int  `json:"entry_count"`
	InvariantOK bool `json:"invariant_ok"`
	AuditCount  int  `json:"audit_count"`
}
