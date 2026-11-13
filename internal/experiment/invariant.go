package experiment

import (
	"context"
	"fmt"
	"time"

	"banksec-lab/internal/config"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/finding"
	"banksec-lab/internal/harness"
)

// Invariant is one named, independently checkable security property.
//
// Invariants are the separation between generation and verification that
// this project's research design rests on. A generator proposes actions;
// an Invariant decides, from Oracle-observed state alone, whether a
// security property actually broke. No Check may read a generator's
// opinion of its own success, and none may treat the simulator's
// refusal of an operation as evidence of a violation.
type Invariant struct {
	// ID is a stable identifier, e.g. "ledger.double-entry". It is what
	// findings are deduplicated on, so it must not change casually.
	ID string
	// Description states the property in one sentence, for the report.
	Description string
	// Severity is the band a confirmed violation of this property
	// carries. It is a property of the invariant, not of the attack that
	// tripped it.
	Severity finding.Severity
	// Component names the part of the simulator the property is about.
	Component string
	// Remediation states what would address a violation, where that is
	// known and specific to this property.
	Remediation string
	// AppliesTo reports whether this property is meaningful under a
	// given configuration. Nil means it applies everywhere, which is the
	// normal case: a property that the vulnerable profile genuinely
	// violates still applies there -- that violation is the research
	// result. AppliesTo is for properties about controls a
	// configuration does not have at all.
	AppliesTo func(config.SecurityProfile) bool
	// Check adjudicates the property from before/after Oracle snapshots
	// and the action trace.
	Check func(in InvariantInput) InvariantVerdict
}

// Applicable reports whether this invariant can be evaluated under
// profile.
func (i Invariant) Applicable(profile config.SecurityProfile) bool {
	if i.AppliesTo == nil {
		return true
	}
	return i.AppliesTo(profile)
}

// InvariantInput is everything a Check is allowed to reason from.
type InvariantInput struct {
	Profile config.SecurityProfile
	Before  Snapshot
	After   Snapshot
	Steps   []Step
	// Assistant is set only for a candidate that exercised the banking
	// AI assistant. An invariant about the assistant reports
	// inconclusive when it is nil, rather than drawing a conclusion
	// from evidence it does not have.
	Assistant *AssistantEvidence
}

// InvariantVerdict is one Check's conclusion, with the reasoning and the
// evidence behind it.
type InvariantVerdict struct {
	Outcome  finding.Outcome
	Detail   string
	Evidence map[string]any
}

// CaptureSnapshot reads the simulator's observable state through the
// read-only Oracle. since bounds the audit query; pass the experiment's
// start time to see every event it produced.
func CaptureSnapshot(ctx context.Context, o harness.Oracle, since time.Time) (Snapshot, error) {
	state, err := o.LedgerSnapshot(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("capture snapshot: ledger: %w", err)
	}
	events, err := o.AuditEventsSince(ctx, since)
	if err != nil {
		return Snapshot{}, fmt.Errorf("capture snapshot: audit: %w", err)
	}
	return Snapshot{
		At:          time.Now(),
		Ledger:      state,
		AuditEvents: events,
		EntryCount:  len(state.Entries),
		InvariantOK: state.InvariantOK,
		AuditCount:  len(events),
	}, nil
}

// CoreInvariants returns the security properties this project can check
// independently today. The set is deliberately small: each entry is a
// property the existing read-only Oracle genuinely exposes evidence for,
// rather than one that merely sounds comprehensive.
func CoreInvariants() []Invariant {
	return []Invariant{
		doubleEntryInvariant(),
		valueExtractionInvariant(),
		rejectedOperationInvariant(),
	}
}

// doubleEntryInvariant checks the accounting property the Oracle
// computes directly: every transaction's entries sum to zero.
func doubleEntryInvariant() Invariant {
	return Invariant{
		ID: "ledger.double-entry",
		Description: "every transaction's ledger entries sum to zero, so no value is created or destroyed. " +
			"This is a property of ledger state only: it says whether the books are balanced, not whether " +
			"anything noticed them being unbalanced. An insider-style privileged write unbalances the ledger " +
			"under every configuration, including hardened, because it writes beneath the application entirely -- " +
			"what the hardened configuration adds is detection, which this property does not measure and the " +
			"corresponding scenario finding reports separately",
		Severity:  finding.SeverityCritical,
		Component: "ledger",
		Remediation: "enforce atomic double-entry writes for application-level operations, and rely on audit hash " +
			"chaining plus the ledger-integrity detection rule for writes that bypass the application",
		Check: func(in InvariantInput) InvariantVerdict {
			if !in.After.InvariantOK {
				return InvariantVerdict{
					Outcome: finding.OutcomeConfirmedViolation,
					Detail:  "the ledger contains at least one transaction whose entries do not sum to zero",
					Evidence: map[string]any{
						"violating_tx_ids":   txIDStrings(in.After.Ledger.ViolatingTxIDs),
						"entry_count_before": in.Before.EntryCount,
						"entry_count_after":  in.After.EntryCount,
					},
				}
			}
			if countMutations(in.Steps) == 0 {
				return InvariantVerdict{
					Outcome: finding.OutcomeInconclusive,
					Detail:  "no state-changing operation reached the simulator, so this property was never exercised",
				}
			}
			return InvariantVerdict{
				Outcome: finding.OutcomeBlocked,
				Detail:  "state-changing operations ran and the ledger remained balanced",
				Evidence: map[string]any{
					"entry_count_before": in.Before.EntryCount,
					"entry_count_after":  in.After.EntryCount,
				},
			}
		},
	}
}

// valueExtractionInvariant checks the core authorization property: an
// actor cannot remove value from an account they do not own.
//
// Only withdrawals and the debited side of a transfer count. A deposit
// into someone else's account moves value in, not out, so treating it
// as a violation would report a finding where no value was at risk.
//
// Ownership is established only from this trace's own successful
// create-account steps. An account whose owner this trace never
// established cannot be adjudicated, and the verdict says so rather than
// assuming either way.
func valueExtractionInvariant() Invariant {
	return Invariant{
		ID:          "authz.no-unauthorized-value-extraction",
		Description: "an actor cannot withdraw or transfer value out of an account they do not own",
		Severity:    finding.SeverityCritical,
		Component:   "backend",
		Remediation: "enforce the account-ownership authorization check on every debiting operation",
		Check: func(in InvariantInput) InvariantVerdict {
			owners := ownersFromTrace(in.Steps)

			var accepted, refused, unknown int
			var acceptedDetail []string
			for _, s := range in.Steps {
				if !s.Executed || s.TransportError != "" {
					continue
				}
				acct, ok := debitedAccount(s.Action)
				if !ok {
					continue
				}
				acctOwner, known := owners[acct]
				if !known {
					unknown++
					continue
				}
				if acctOwner == s.Action.Actor.ID {
					continue // the owner acting on their own account
				}
				if s.ResponseOK {
					accepted++
					acceptedDetail = append(acceptedDetail, fmt.Sprintf("%s extracted from %s (owned by %s) via %s",
						s.Action.Actor.ID, acct, acctOwner, s.Action.Op))
				} else {
					refused++
				}
			}

			switch {
			case accepted > 0:
				return InvariantVerdict{
					Outcome: finding.OutcomeConfirmedViolation,
					Detail:  "the simulator accepted a debiting operation from an actor who does not own the account",
					Evidence: map[string]any{
						"accepted_extractions": acceptedDetail,
						"refused_attempts":     refused,
						"entry_count_before":   in.Before.EntryCount,
						"entry_count_after":    in.After.EntryCount,
					},
				}
			case refused > 0:
				return InvariantVerdict{
					Outcome:  finding.OutcomeBlocked,
					Detail:   fmt.Sprintf("%d cross-actor extraction attempt(s) reached the simulator and all were refused", refused),
					Evidence: map[string]any{"refused_attempts": refused},
				}
			case unknown > 0:
				return InvariantVerdict{
					Outcome:  finding.OutcomeInconclusive,
					Detail:   fmt.Sprintf("%d debiting operation(s) targeted accounts whose ownership this trace never established", unknown),
					Evidence: map[string]any{"unattributable_operations": unknown},
				}
			default:
				return InvariantVerdict{
					Outcome: finding.OutcomeInconclusive,
					Detail:  "no cross-actor extraction was attempted, so this property was never exercised",
				}
			}
		},
	}
}

// rejectedOperationInvariant checks that an operation the banking system
// refused left no trace in the ledger.
//
// It can only conclude when attribution is unambiguous: if every
// state-changing operation in the trace was refused, any ledger growth
// must have come from a refused one. With a mix of accepted and refused
// operations the change cannot be attributed, and the verdict is
// inconclusive rather than a guess in either direction.
func rejectedOperationInvariant() Invariant {
	return Invariant{
		ID:          "ledger.rejected-operation-no-effect",
		Description: "an operation the banking system refused leaves the ledger unchanged",
		Severity:    finding.SeverityHigh,
		Component:   "ledger",
		Remediation: "wrap every operation's ledger writes in a transaction that rolls back on refusal",
		Check: func(in InvariantInput) InvariantVerdict {
			var accepted, refused int
			for _, s := range in.Steps {
				switch {
				case s.IsSuccessfulMutation():
					accepted++
				case s.IsRefusedMutation():
					refused++
				}
			}

			if refused == 0 {
				return InvariantVerdict{
					Outcome: finding.OutcomeInconclusive,
					Detail:  "no state-changing operation was refused, so this property was never exercised",
				}
			}
			if accepted > 0 {
				return InvariantVerdict{
					Outcome: finding.OutcomeInconclusive,
					Detail:  fmt.Sprintf("%d accepted and %d refused state-changing operations ran; a ledger change cannot be attributed to the refused ones", accepted, refused),
					Evidence: map[string]any{
						"accepted_mutations": accepted,
						"refused_mutations":  refused,
					},
				}
			}
			if in.After.EntryCount != in.Before.EntryCount {
				return InvariantVerdict{
					Outcome: finding.OutcomeConfirmedViolation,
					Detail:  "every state-changing operation was refused, yet the ledger changed",
					Evidence: map[string]any{
						"refused_mutations":  refused,
						"entry_count_before": in.Before.EntryCount,
						"entry_count_after":  in.After.EntryCount,
					},
				}
			}
			return InvariantVerdict{
				Outcome: finding.OutcomeBlocked,
				Detail:  fmt.Sprintf("%d state-changing operation(s) were refused and the ledger was unchanged", refused),
				Evidence: map[string]any{
					"refused_mutations": refused,
					"entry_count":       in.After.EntryCount,
				},
			}
		},
	}
}

// ownersFromTrace maps account ID to owner, from this trace's own
// successful create-account responses. Nothing else is trusted as a
// source of ownership: the simulator's own response is the only record
// of who an account was created for.
func ownersFromTrace(steps []Step) map[string]domain.PrincipalID {
	owners := make(map[string]domain.PrincipalID)
	for _, s := range steps {
		if s.Action.Op != OpCreateAccount || !s.Executed || !s.ResponseOK {
			continue
		}
		acct := s.ResponseData["account"]
		ownerID := s.Action.Params["owner"]
		if acct == "" || ownerID == "" {
			continue
		}
		owners[acct] = domain.PrincipalID(ownerID)
	}
	return owners
}

// debitedAccount returns the account an action removes value from, and
// whether the action removes value at all.
func debitedAccount(a Action) (string, bool) {
	switch a.Op {
	case OpWithdraw:
		return a.Params["account"], true
	case OpTransfer:
		return a.Params["from"], true
	default:
		return "", false
	}
}

// countMutations counts state-changing operations that actually reached
// the simulator, accepted or refused. An action the validation boundary
// refused never ran and exercised nothing.
func countMutations(steps []Step) int {
	n := 0
	for _, s := range steps {
		if s.Executed && s.TransportError == "" && IsMutatingOp(s.Action.Op) {
			n++
		}
	}
	return n
}

func txIDStrings(ids []domain.TransactionID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, string(id))
	}
	return out
}
