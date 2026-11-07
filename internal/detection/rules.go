package detection

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/ledger"
)

// BalanceInvariantRuleID identifies the balance-invariant-violation rule.
const BalanceInvariantRuleID domain.DetectionRuleID = "balance-invariant-violation"

// balanceInvariantRule polls ledger.Store.CheckInvariant whenever the
// latest event in its window is a "backend" component event -- i.e. on
// every ledger-related operation, rather than on a fixed timer. Chosen
// because the ledger only changes as a result of such an operation, so a
// timer would either lag behind a violation or burn cycles polling
// between operations for no benefit.
type balanceInvariantRule struct {
	ledger ledger.Store

	// mu guards reported: Evaluate can be called concurrently (handle
	// runs synchronously from each Record call, and multiple goroutines
	// may call Record at once).
	mu       sync.Mutex
	reported map[domain.TransactionID]bool
}

// NewBalanceInvariantRule returns a Rule that flags any transaction
// whose entries do not net to zero (ledger.Store.CheckInvariant), e.g. an
// entry inserted directly into storage, bypassing AppendTransaction's
// own balance check.
func NewBalanceInvariantRule(l ledger.Store) Rule {
	return &balanceInvariantRule{ledger: l, reported: make(map[domain.TransactionID]bool)}
}

func (r *balanceInvariantRule) ID() domain.DetectionRuleID {
	return BalanceInvariantRuleID
}

func (r *balanceInvariantRule) Evaluate(window []audit.Event) (bool, string) {
	if len(window) == 0 {
		return false, ""
	}
	if window[len(window)-1].Component != "backend" {
		return false, ""
	}

	ok, bad, err := r.ledger.CheckInvariant(context.Background())
	if err != nil {
		// A failing invariant check is itself suspicious -- e.g. an
		// attacker holding a lock on ledger.db past its busy_timeout
		// could otherwise make the check fail and hide a violation
		// completely, by having Evaluate treat it the same as "no
		// violation" (security review finding I9).
		return true, fmt.Sprintf("invariant check failed: %v", err)
	}
	if ok {
		return false, ""
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	var newBad []domain.TransactionID
	for _, tx := range bad {
		if !r.reported[tx] {
			r.reported[tx] = true
			newBad = append(newBad, tx)
		}
	}
	if len(newBad) == 0 {
		// Every currently-offending transaction was already reported --
		// don't re-trigger a fresh detection event on every subsequent
		// backend operation, which would grow the audit log without
		// bound and bury any genuinely new detection in a flood of
		// repeats of the same one (security review finding I10).
		return false, ""
	}
	return true, fmt.Sprintf("ledger invariant violated, offending tx(s): %v", newBad)
}

// AuditChainRuleID identifies the audit-chain-violation rule.
const AuditChainRuleID domain.DetectionRuleID = "audit-chain-violation"

// auditChainRule re-verifies the audit hash chain (audit.Stream.
// VerifyChain) on every non-detection event -- the same "trigger on
// real activity rather than a fixed timer" choice balanceInvariantRule
// makes, and for the same reason: a raw-SQL tamper (e.g.
// PrivilegedAccess.RawAuditWrite, which always leaves hash=NULL) itself
// emits no event of its own to react to, so the next ordinary event is
// what gives this rule a chance to notice. ATTACK_SURFACES.md §3 calls
// for exactly this detection path ("hash-chain re-verification... by
// the Detection Engine"), which Milestone 6 had not yet implemented --
// it shipped only the balance-invariant rule.
type auditChainRule struct {
	stream audit.Stream

	// mu guards reportedBreak. Latched per distinct break location
	// (rather than a single permanent bool) so that if VerifyChain's
	// report ever changes -- a different event ID, or a transition
	// to/from "truncated, no single row to blame" (brokenAt == nil) --
	// that counts as a new, genuinely different break worth reporting
	// again, not a repeat of the first one (security review finding I1:
	// a single global bool meant one false positive, caused by a
	// since-fixed race in VerifyChain, permanently silenced the rule for
	// any real tamper that happened afterward in the same run).
	mu            sync.Mutex
	reportedBreak string // "" means nothing reported yet
}

// auditBreakKey canonicalizes a VerifyChain break report into a
// comparable string: a specific event ID, or a fixed marker for
// "truncated, no single row to blame" (brokenAt == nil).
func auditBreakKey(brokenAt *string) string {
	if brokenAt == nil {
		return "<truncated>"
	}
	return *brokenAt
}

// NewAuditChainRule returns a Rule that flags a broken audit hash chain.
// Under a stream with hashChained=false (vulnerable mode),
// VerifyChain's ErrChainNotEnabled is treated as "nothing to check", not
// a trigger -- there is no chain to have broken.
func NewAuditChainRule(a audit.Stream) Rule {
	return &auditChainRule{stream: a}
}

func (r *auditChainRule) ID() domain.DetectionRuleID {
	return AuditChainRuleID
}

func (r *auditChainRule) Evaluate(window []audit.Event) (bool, string) {
	if len(window) == 0 {
		return false, ""
	}

	ok, brokenAt, err := r.stream.VerifyChain(context.Background())
	if err != nil {
		if errors.Is(err, audit.ErrChainNotEnabled) {
			return false, ""
		}
		return true, fmt.Sprintf("audit chain verification failed: %v", err)
	}
	if ok {
		return false, ""
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	key := auditBreakKey(brokenAt)
	if r.reportedBreak == key {
		return false, ""
	}
	r.reportedBreak = key

	if brokenAt != nil {
		return true, fmt.Sprintf("audit hash chain broken at event %s", *brokenAt)
	}
	return true, "audit hash chain broken (trailing event(s) missing)"
}
