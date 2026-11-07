// Package harness implements the attack execution framework: a
// registry of Scenarios, a read-only Oracle for verifying outcomes, a
// PrivilegedAccess channel simulating an insider/root-level bypass, and
// a Runner that ties them together into a common Result schema.
package harness

import (
	"context"
	"fmt"
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/keystore"
	"banksec-lab/internal/ledger"
)

// Oracle is the read-only view a Scenario's Verify step uses to decide
// whether an attack actually succeeded -- never trusting Exec's own
// claim (see Runner.Run's doc comment). It can only read; writing is
// PrivilegedAccess's job.
type Oracle interface {
	LedgerSnapshot(ctx context.Context) (ledger.State, error)
	KeySnapshot(ctx context.Context, keyID string) (keystore.KeyMeta, error)
	AuditEventsSince(ctx context.Context, t time.Time) ([]audit.Event, error)
}

type oracle struct {
	ledger   ledger.Store
	keystore keystore.Store
	audit    audit.Stream
}

// NewOracle constructs an Oracle reading from the given stores.
func NewOracle(l ledger.Store, k keystore.Store, a audit.Stream) Oracle {
	return &oracle{ledger: l, keystore: k, audit: a}
}

// LedgerSnapshot computes the invariant result in Go from a single
// AllEntries read, rather than a second, separate CheckInvariant query:
// two queries against a table a writer can change in between would let
// a concurrent AppendTransaction/PrivilegedAccess.RawLedgerWrite produce
// a torn State -- Entries implying a different set of violating
// transactions than ViolatingTxIDs actually names -- which could make a
// Scenario's Verify draw a wrong conclusion (security review finding
// I5). One query's result is self-consistent by construction.
func (o *oracle) LedgerSnapshot(ctx context.Context) (ledger.State, error) {
	entries, err := o.ledger.AllEntries(ctx)
	if err != nil {
		return ledger.State{}, fmt.Errorf("ledger snapshot: all entries: %w", err)
	}

	sums := make(map[domain.TransactionID]domain.Money, len(entries))
	for _, e := range entries {
		sums[e.TxID] += e.Amount
	}
	var bad []domain.TransactionID
	for txID, sum := range sums {
		if sum != 0 {
			bad = append(bad, txID)
		}
	}
	return ledger.State{Entries: entries, InvariantOK: len(bad) == 0, ViolatingTxIDs: bad}, nil
}

// KeySnapshot returns a key's lifecycle metadata only -- never its
// material. Exposing material to a Scenario's Verify step would make
// the Oracle itself a privileged channel; that's PrivilegedAccess's
// explicit, separately-gated job (internal/harness/privileged.go). Uses
// Store.Meta, not Store.Get: Get both decrypts material (just to throw
// it away) and records a key_access audit event, which would make a
// Verify step merely checking a key's metadata indistinguishable from a
// real material access in the audit trail, and would abort on a revoked
// key instead of reporting its (perfectly readable) revocation status
// (security review finding I4).
func (o *oracle) KeySnapshot(ctx context.Context, keyID string) (keystore.KeyMeta, error) {
	return o.keystore.Meta(ctx, keyID)
}

func (o *oracle) AuditEventsSince(ctx context.Context, t time.Time) ([]audit.Event, error) {
	return o.audit.Since(ctx, t)
}
