package ledger

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"banksec-lab/internal/domain"
)

type sqliteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (creating if necessary) a double-entry ledger store
// at path.
func NewSQLiteStore(path string) (Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open ledger store %s: %w", path, err)
	}
	const schema = `
CREATE TABLE IF NOT EXISTS entries (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	tx_id      TEXT NOT NULL,
	account_id TEXT NOT NULL,
	amount     INTEGER NOT NULL,
	timestamp  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_account_id ON entries(account_id);
CREATE TABLE IF NOT EXISTS accounts (
	id    TEXT PRIMARY KEY,
	owner TEXT NOT NULL
);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create ledger schema: %w", err)
	}
	return &sqliteStore{db: db}, nil
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}

func (s *sqliteStore) CreateAccount(ctx context.Context, owner domain.PrincipalID) (domain.AccountID, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate account id: %w", err)
	}
	acct := domain.AccountID("acct-" + hex.EncodeToString(raw))

	if _, err := s.db.ExecContext(ctx, `INSERT INTO accounts (id, owner) VALUES (?, ?)`, string(acct), string(owner)); err != nil {
		return "", fmt.Errorf("insert account: %w", err)
	}
	return acct, nil
}

func (s *sqliteStore) AccountOwner(ctx context.Context, acct domain.AccountID) (domain.PrincipalID, bool, error) {
	var owner string
	err := s.db.QueryRowContext(ctx, `SELECT owner FROM accounts WHERE id = ?`, string(acct)).Scan(&owner)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("query account owner: %w", err)
	}
	return domain.PrincipalID(owner), true, nil
}

func (s *sqliteStore) AppendTransaction(ctx context.Context, entries []Entry) error {
	var sum domain.Money
	for _, e := range entries {
		next := sum + e.Amount
		// Overflow check: if the operands share a sign but the result's
		// sign differs, int64 addition wrapped around.
		if (e.Amount > 0 && next < sum) || (e.Amount < 0 && next > sum) {
			return ErrAmountOverflow
		}
		sum = next
	}
	if sum != 0 {
		return ErrUnbalancedEntries
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO entries (tx_id, account_id, amount, timestamp) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx, string(e.TxID), string(e.AccountID), int64(e.Amount), e.Timestamp.UnixNano()); err != nil {
			return fmt.Errorf("insert entry: %w", err)
		}
	}

	return tx.Commit()
}

func (s *sqliteStore) Balance(ctx context.Context, acct domain.AccountID) (domain.Money, error) {
	var total sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT SUM(amount) FROM entries WHERE account_id = ?`, string(acct)).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("query balance: %w", err)
	}
	return domain.Money(total.Int64), nil
}

func (s *sqliteStore) History(ctx context.Context, acct domain.AccountID) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tx_id, account_id, amount, timestamp FROM entries WHERE account_id = ? ORDER BY timestamp ASC, id ASC`,
		string(acct))
	if err != nil {
		return nil, fmt.Errorf("query history: %w", err)
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var txID, accountID string
		var amount, ts int64
		if err := rows.Scan(&txID, &accountID, &amount, &ts); err != nil {
			return nil, fmt.Errorf("scan history row: %w", err)
		}
		out = append(out, Entry{
			TxID:      domain.TransactionID(txID),
			AccountID: domain.AccountID(accountID),
			Amount:    domain.Money(amount),
			Timestamp: time.Unix(0, ts),
		})
	}
	return out, rows.Err()
}

func (s *sqliteStore) CheckInvariant(ctx context.Context) (bool, []domain.TransactionID, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tx_id FROM entries GROUP BY tx_id HAVING SUM(amount) != 0`)
	if err != nil {
		return false, nil, fmt.Errorf("check invariant: %w", err)
	}
	defer rows.Close()

	var bad []domain.TransactionID
	for rows.Next() {
		var txID string
		if err := rows.Scan(&txID); err != nil {
			return false, nil, fmt.Errorf("scan invariant row: %w", err)
		}
		bad = append(bad, domain.TransactionID(txID))
	}
	if err := rows.Err(); err != nil {
		return false, nil, err
	}
	return len(bad) == 0, bad, nil
}
