package harness

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/ledger"
)

// PrivilegedAccess simulates an insider/root-level bypass: direct SQL
// access to the ledger/audit/keystore SQLite files, entirely outside
// internal/backend and internal/keystore's own Go APIs (so, for
// example, RawKeyBytes returns whatever bytes are actually stored --
// plaintext in vulnerable mode, still-wrapped ciphertext in hardened
// mode -- never decrypting, since this path never goes through
// keystore.Store at all).
//
// Its only inputs are local SQLite file paths, supplied once by
// harness.Environment at construction -- never a network address or
// externally-supplied DSN. The constructor is unexported specifically
// so a Scenario cannot build its own PrivilegedAccess pointed at an
// arbitrary (e.g. a different Environment's, or an unrelated) file
// (security review finding C1).
//
// This narrows, but does not eliminate, what a Scenario's Exec can
// reach: Exec is ordinary in-process Go code with the full privileges
// of this process, so it could still open its own database/sql
// connection to any file it can name, or import net/os directly. Go
// gives no in-process sandbox for that. "Attacks cannot target systems
// outside the simulator" holds for what this framework's own API
// surface offers a Scenario, and for trusted, reviewed Scenario
// implementations (the only kind this project registers) -- it is not
// a security boundary against deliberately adversarial Scenario code.
// Real enforcement against that would require running each Scenario's
// Exec in its own OS process with a restricted working directory, which
// is out of this milestone's scope.
type PrivilegedAccess interface {
	RawLedgerWrite(ctx context.Context, entries []ledger.Entry) error
	RawAuditWrite(ctx context.Context, e audit.Event) error
	RawKeyBytes(ctx context.Context, id string) ([]byte, error)
}

type privilegedAccess struct {
	ledgerPath   string
	auditPath    string
	keystorePath string
}

// newPrivilegedAccess constructs a PrivilegedAccess over the given local
// SQLite file paths. Unexported: only harness.NewLocalEnvironment calls
// this, with paths it created itself -- see PrivilegedAccess's doc
// comment for why.
func newPrivilegedAccess(ledgerPath, auditPath, keystorePath string) PrivilegedAccess {
	return &privilegedAccess{ledgerPath: ledgerPath, auditPath: auditPath, keystorePath: keystorePath}
}

func (p *privilegedAccess) RawLedgerWrite(ctx context.Context, entries []ledger.Entry) error {
	db, err := sql.Open("sqlite", p.ledgerPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return fmt.Errorf("open ledger %s: %w", p.ledgerPath, err)
	}
	defer db.Close()

	for _, e := range entries {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO entries (tx_id, account_id, amount, timestamp) VALUES (?, ?, ?, ?)`,
			string(e.TxID), string(e.AccountID), int64(e.Amount), e.Timestamp.UnixNano(),
		); err != nil {
			return fmt.Errorf("raw insert entry: %w", err)
		}
	}
	return nil
}

func (p *privilegedAccess) RawAuditWrite(ctx context.Context, e audit.Event) error {
	db, err := sql.Open("sqlite", p.auditPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return fmt.Errorf("open audit stream %s: %w", p.auditPath, err)
	}
	defer db.Close()

	var txID, attackID sql.NullString
	if e.TxID != nil {
		txID = sql.NullString{String: string(*e.TxID), Valid: true}
	}
	if e.AttackID != nil {
		attackID = sql.NullString{String: *e.AttackID, Valid: true}
	}

	// hash is left NULL: this write never goes through the audit
	// package's hash-chaining logic at all, by design -- simulating an
	// insider or attacker writing straight to the database file,
	// exactly the threat VerifyChain exists to detect (Milestone 8's
	// audit-tampering scenario).
	if _, err := db.ExecContext(ctx,
		`INSERT INTO events (id, timestamp, type, component, actor, operation, outcome, tx_id, attack_id, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		e.ID, e.Timestamp.UnixNano(), e.Type, e.Component, string(e.Actor), e.Operation, e.Outcome, txID, attackID,
	); err != nil {
		return fmt.Errorf("raw insert event: %w", err)
	}
	return nil
}

func (p *privilegedAccess) RawKeyBytes(ctx context.Context, id string) ([]byte, error) {
	db, err := sql.Open("sqlite", p.keystorePath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open keystore %s: %w", p.keystorePath, err)
	}
	defer db.Close()

	var material []byte
	if err := db.QueryRowContext(ctx, `SELECT material FROM keys WHERE id = ?`, id).Scan(&material); err != nil {
		return nil, fmt.Errorf("raw query key material: %w", err)
	}
	return material, nil
}
