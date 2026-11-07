package detection

import (
	"context"
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
