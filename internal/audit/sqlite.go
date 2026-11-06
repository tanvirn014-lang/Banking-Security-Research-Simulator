package audit

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"banksec-lab/internal/domain"
)

type sqliteStream struct {
	db *sql.DB

	mu        sync.Mutex
	nextSubID int
	subs      map[int]func(Event)
}

// NewSQLiteStream opens (creating if necessary) an audit event stream at
// path. path must be a different file than the ledger's and keystore's.
func NewSQLiteStream(path string) (Stream, error) {
	// busy_timeout: see internal/ledger/sqlite.go's NewSQLiteStore for why
	// -- concurrent writers (e.g. multiple backend operations recording
	// audit events around the same time) must wait and retry, not fail
	// outright with SQLITE_BUSY.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open audit stream %s: %w", path, err)
	}
	const schema = `
CREATE TABLE IF NOT EXISTS events (
	id         TEXT PRIMARY KEY,
	timestamp  INTEGER NOT NULL,
	type       TEXT NOT NULL,
	component  TEXT NOT NULL,
	actor      TEXT NOT NULL,
	operation  TEXT NOT NULL,
	outcome    TEXT NOT NULL,
	tx_id      TEXT,
	attack_id  TEXT
);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create audit schema: %w", err)
	}
	return &sqliteStream{db: db, subs: make(map[int]func(Event))}, nil
}

func (s *sqliteStream) Close() error {
	return s.db.Close()
}

func (s *sqliteStream) Record(ctx context.Context, e Event) error {
	var txID, attackID sql.NullString
	if e.TxID != nil {
		txID = sql.NullString{String: string(*e.TxID), Valid: true}
	}
	if e.AttackID != nil {
		attackID = sql.NullString{String: *e.AttackID, Valid: true}
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO events (id, timestamp, type, component, actor, operation, outcome, tx_id, attack_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.Timestamp.UnixNano(), e.Type, e.Component, string(e.Actor), e.Operation, e.Outcome, txID, attackID)
	if err != nil {
		return fmt.Errorf("record event: %w", err)
	}

	s.mu.Lock()
	subs := make([]func(Event), 0, len(s.subs))
	for _, fn := range s.subs {
		subs = append(subs, fn)
	}
	s.mu.Unlock()

	for _, fn := range subs {
		fn(e)
	}
	return nil
}

func (s *sqliteStream) Since(ctx context.Context, t time.Time) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, timestamp, type, component, actor, operation, outcome, tx_id, attack_id
		 FROM events WHERE timestamp >= ? ORDER BY timestamp ASC`,
		t.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		var actor, txID, attackID sql.NullString
		if err := rows.Scan(&e.ID, &ts, &e.Type, &e.Component, &actor, &e.Operation, &e.Outcome, &txID, &attackID); err != nil {
			return nil, fmt.Errorf("scan event row: %w", err)
		}
		e.Timestamp = time.Unix(0, ts)
		e.Actor = domain.PrincipalID(actor.String)
		if txID.Valid {
			v := domain.TransactionID(txID.String)
			e.TxID = &v
		}
		if attackID.Valid {
			v := attackID.String
			e.AttackID = &v
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *sqliteStream) Subscribe(fn func(Event)) (unsubscribe func()) {
	s.mu.Lock()
	id := s.nextSubID
	s.nextSubID++
	s.subs[id] = fn
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		delete(s.subs, id)
		s.mu.Unlock()
	}
}
