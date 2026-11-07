package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"banksec-lab/internal/domain"
)

type sqliteStream struct {
	db          *sql.DB
	hashChained bool

	// chainMu serializes "read chain state, then insert" so two
	// concurrent Record calls under hashChained=true can never both
	// extend the chain from the same prior state -- SQLite's own write
	// locking does not make that sequence atomic on its own.
	chainMu sync.Mutex
	// chainKey is this stream's HMAC key: without it, an attacker who
	// can only write to the events table (e.g. via raw SQL) cannot
	// recompute a valid hash after tampering -- unlike a keyless hash,
	// which anyone can recompute from public data (security review
	// finding C1). Persisted in checkpointPath, never in the events
	// table itself.
	chainKey []byte
	// chainCount/chainHash mirror the external checkpoint file in
	// memory, to avoid a disk round trip on every Record; VerifyChain
	// re-reads the file from disk rather than trusting these, so a
	// checkpoint rolled back by a separate process is still caught.
	chainCount int64
	chainHash  []byte
	// checkpointPath holds the chain's HMAC key and running
	// count/head-hash, outside the main database file (finding C2): an
	// attacker who deletes trailing rows via raw SQL against the events
	// table leaves an internally-consistent, merely shorter chain --
	// nothing in that table alone can reveal that rows are missing off
	// the end. The checkpoint is what lets VerifyChain notice.
	checkpointPath string

	mu        sync.Mutex
	nextSubID int
	subs      map[int]func(Event)
}

// NewSQLiteStream opens (creating if necessary) an audit event stream at
// path. path must be a different file than the ledger's and keystore's.
// hashChained=true (hardened mode) makes every recorded event's hash a
// keyed (HMAC-SHA256) function of the previous event's hash plus an
// external checkpoint file (path+".chainkey"), enabling VerifyChain to
// detect a row modified or deleted outside of Record. Vulnerable mode
// (hashChained=false) stores no hash at all -- the deliberately
// exploitable surface: a tampered row is otherwise indistinguishable
// from a genuine one. Reopening an existing stream file with a different
// hashChained value than it was created with is rejected: see
// checkOrSetMode.
func NewSQLiteStream(path string, hashChained bool) (Stream, error) {
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
	attack_id  TEXT,
	hash       BLOB
);
CREATE TABLE IF NOT EXISTS stream_meta (
	hash_chained INTEGER NOT NULL
);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create audit schema: %w", err)
	}
	if err := checkOrSetMode(db, path, hashChained); err != nil {
		db.Close()
		return nil, err
	}

	s := &sqliteStream{db: db, hashChained: hashChained, subs: make(map[int]func(Event))}

	if hashChained {
		s.checkpointPath = path + ".chainkey"
		cp, err := loadOrCreateCheckpoint(s.checkpointPath)
		if err != nil {
			db.Close()
			return nil, err
		}
		key, err := hex.DecodeString(cp.Key)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("decode chain key from %s: %w", s.checkpointPath, err)
		}
		lastHash, err := hex.DecodeString(cp.LastHash)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("decode chain checkpoint hash from %s: %w", s.checkpointPath, err)
		}
		s.chainKey = key
		s.chainCount = cp.Count
		s.chainHash = lastHash
	}

	return s, nil
}

// checkOrSetMode records which mode (hashChained or not) this stream
// file was created under, and rejects reopening it in the other mode.
// Without this, a stream created with hashChained=false and later
// reopened with hashChained=true would try to hash-verify rows that
// were never given a hash (failing deep inside Record/VerifyChain with a
// confusing error), and the reverse direction would silently stop
// checking a chain that real callers may still believe is protected
// (security review finding I7).
func checkOrSetMode(db *sql.DB, path string, hashChained bool) error {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM stream_meta`).Scan(&count); err != nil {
		return fmt.Errorf("query stream_meta: %w", err)
	}
	if count == 0 {
		if _, err := db.Exec(`INSERT INTO stream_meta (hash_chained) VALUES (?)`, boolToInt(hashChained)); err != nil {
			return fmt.Errorf("init stream_meta: %w", err)
		}
		return nil
	}
	var stored int
	if err := db.QueryRow(`SELECT hash_chained FROM stream_meta LIMIT 1`).Scan(&stored); err != nil {
		return fmt.Errorf("read stream_meta: %w", err)
	}
	if (stored != 0) != hashChained {
		return fmt.Errorf("audit stream %s: opened with hashChained=%v but was created with hashChained=%v -- reopen with the original mode, or use a separate file",
			path, hashChained, stored != 0)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// chainCheckpoint is the sidecar file format for a hash-chained stream's
// HMAC key and running chain head.
type chainCheckpoint struct {
	Key      string `json:"key"`
	Count    int64  `json:"count"`
	LastHash string `json:"last_hash"`
}

func loadOrCreateCheckpoint(path string) (chainCheckpoint, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var cp chainCheckpoint
		if jsonErr := json.Unmarshal(data, &cp); jsonErr != nil {
			return chainCheckpoint{}, fmt.Errorf("parse chain checkpoint %s: %w", path, jsonErr)
		}
		return cp, nil
	}
	if !os.IsNotExist(err) {
		return chainCheckpoint{}, fmt.Errorf("read chain checkpoint %s: %w", path, err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return chainCheckpoint{}, fmt.Errorf("generate chain key: %w", err)
	}
	cp := chainCheckpoint{Key: hex.EncodeToString(key), Count: 0, LastHash: hex.EncodeToString(genesisHash)}
	if err := saveCheckpoint(path, cp); err != nil {
		return chainCheckpoint{}, err
	}
	return cp, nil
}

func saveCheckpoint(path string, cp chainCheckpoint) error {
	data, err := json.Marshal(cp)
	if err != nil {
		return fmt.Errorf("encode chain checkpoint: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write chain checkpoint %s: %w", path, err)
	}
	return nil
}

// genesisHash is the prevHash fed into the first event in a chain.
var genesisHash = make([]byte, sha256.Size)

func writeLenPrefixed(buf *bytes.Buffer, s string) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	buf.Write(lenBuf[:])
	buf.WriteString(s)
}

func writeNullable(buf *bytes.Buffer, s sql.NullString) {
	if s.Valid {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	writeLenPrefixed(buf, s.String)
}

// eventHashInput builds the exact byte sequence HMACed into an event's
// chain entry: prevHash, the timestamp, then every stored column, each
// length-prefixed (a 4-byte big-endian length followed by its bytes).
// Length-prefixing (rather than a delimiter join) is required because
// several fields are client- or business-logic-controlled strings
// (Actor, Operation, Outcome): a delimiter join would let a byte
// sequence straddling two fields' boundary be shifted between them
// without changing the joined bytes at all (security review finding
// C3) -- length prefixes make that impossible regardless of field
// content, including embedded NUL bytes.
func eventHashInput(prevHash []byte, id string, timestamp int64, typ, component, actor, operation, outcome string, txID, attackID sql.NullString) []byte {
	var buf bytes.Buffer
	buf.Write(prevHash)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(timestamp))
	buf.Write(tsBuf[:])
	writeLenPrefixed(&buf, id)
	writeLenPrefixed(&buf, typ)
	writeLenPrefixed(&buf, component)
	writeLenPrefixed(&buf, actor)
	writeLenPrefixed(&buf, operation)
	writeLenPrefixed(&buf, outcome)
	writeNullable(&buf, txID)
	writeNullable(&buf, attackID)
	return buf.Bytes()
}

// chainHash is eventHashInput's result, keyed with HMAC-SHA256 under key
// (see chainKey's doc comment for why this must be keyed, not a plain
// hash).
func chainHash(key, prevHash []byte, id string, timestamp int64, typ, component, actor, operation, outcome string, txID, attackID sql.NullString) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(eventHashInput(prevHash, id, timestamp, typ, component, actor, operation, outcome, txID, attackID))
	return mac.Sum(nil)
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

	// chainMu is released before subscribers run, below -- NOT deferred
	// to function return. A subscriber (e.g. the Detection Engine) may
	// call Record again synchronously from within its own callback (see
	// audit.Stream's Subscribe doc comment); since sync.Mutex is not
	// reentrant, still holding chainMu at that point would deadlock the
	// nested call against itself.
	s.chainMu.Lock()

	var hash []byte
	if s.hashChained {
		prevHash := s.chainHash
		if prevHash == nil {
			prevHash = genesisHash
		}
		hash = chainHash(s.chainKey, prevHash, e.ID, e.Timestamp.UnixNano(), e.Type, e.Component, string(e.Actor), e.Operation, e.Outcome, txID, attackID)
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO events (id, timestamp, type, component, actor, operation, outcome, tx_id, attack_id, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.Timestamp.UnixNano(), e.Type, e.Component, string(e.Actor), e.Operation, e.Outcome, txID, attackID, hash)
	if err != nil {
		s.chainMu.Unlock()
		return fmt.Errorf("record event: %w", err)
	}

	if s.hashChained {
		s.chainCount++
		s.chainHash = hash
		if err := saveCheckpoint(s.checkpointPath, chainCheckpoint{
			Key:      hex.EncodeToString(s.chainKey),
			Count:    s.chainCount,
			LastHash: hex.EncodeToString(s.chainHash),
		}); err != nil {
			s.chainMu.Unlock()
			return fmt.Errorf("persist chain checkpoint: %w", err)
		}
	}
	s.chainMu.Unlock()

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
	return s.queryEvents(ctx, `WHERE timestamp >= ?`, []any{t.UnixNano()})
}

// Filter implements Stream.Filter: a zero-value Filter field adds no
// constraint to the query.
func (s *sqliteStream) Filter(ctx context.Context, f Filter) ([]Event, error) {
	var conditions []string
	var args []any

	if f.Component != "" {
		conditions = append(conditions, "component = ?")
		args = append(args, f.Component)
	}
	if f.AttackID != nil {
		conditions = append(conditions, "attack_id = ?")
		args = append(args, *f.AttackID)
	}
	if !f.Since.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, f.Since.UnixNano())
	}
	if !f.Until.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, f.Until.UnixNano())
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}
	return s.queryEvents(ctx, where, args)
}

// queryEvents runs a SELECT over the events table with the given
// WHERE clause (may be empty) and args, ordered by timestamp ascending.
// Every value is passed as a bound parameter (?), never concatenated
// into the query string, so Filter's caller-supplied Component/AttackID
// values cannot inject SQL.
func (s *sqliteStream) queryEvents(ctx context.Context, where string, args []any) ([]Event, error) {
	query := `SELECT id, timestamp, type, component, actor, operation, outcome, tx_id, attack_id
		 FROM events ` + where + ` ORDER BY timestamp ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
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

// VerifyChain recomputes the HMAC chain over every stored row (detecting
// any row whose content or hash was modified), then compares the final
// count and hash against the external checkpoint file (detecting rows
// deleted from the end, which leave the remaining chain internally
// consistent but shorter than it should be -- security review finding
// C2). This is not a complete defense against an attacker who can also
// read and rewrite the checkpoint file alongside the database file: a
// fully tamper-proof design would anchor the chain head outside this
// host entirely, which is out of this milestone's scope.
func (s *sqliteStream) VerifyChain(ctx context.Context) (ok bool, brokenAt *string, err error) {
	if !s.hashChained {
		return false, nil, ErrChainNotEnabled
	}

	cp, err := loadOrCreateCheckpoint(s.checkpointPath)
	if err != nil {
		return false, nil, fmt.Errorf("read chain checkpoint for verification: %w", err)
	}
	wantFinalHash, err := hex.DecodeString(cp.LastHash)
	if err != nil {
		return false, nil, fmt.Errorf("decode checkpoint hash: %w", err)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, timestamp, type, component, actor, operation, outcome, tx_id, attack_id, hash
		 FROM events ORDER BY rowid ASC`)
	if err != nil {
		return false, nil, fmt.Errorf("query events for chain verification: %w", err)
	}
	defer rows.Close()

	prevHash := genesisHash
	var count int64
	for rows.Next() {
		var id, typ, component, actor, operation, outcome string
		var ts int64
		var txID, attackID sql.NullString
		var storedHash []byte
		if err := rows.Scan(&id, &ts, &typ, &component, &actor, &operation, &outcome, &txID, &attackID, &storedHash); err != nil {
			return false, nil, fmt.Errorf("scan event row for chain verification: %w", err)
		}

		want := chainHash(s.chainKey, prevHash, id, ts, typ, component, actor, operation, outcome, txID, attackID)
		if storedHash == nil || !bytes.Equal(want, storedHash) {
			brokenID := id
			return false, &brokenID, rows.Err()
		}
		prevHash = want
		count++
	}
	if err := rows.Err(); err != nil {
		return false, nil, err
	}

	if count != cp.Count || !bytes.Equal(prevHash, wantFinalHash) {
		// Every stored row matched its predecessor, yet the chain as a
		// whole doesn't reach the length/head the checkpoint says it
		// should -- rows were removed from the end. There is no single
		// row to blame (nothing stored contradicts anything else), so
		// brokenAt is nil; ok=false is the signal.
		return false, nil, nil
	}

	return true, nil, nil
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
