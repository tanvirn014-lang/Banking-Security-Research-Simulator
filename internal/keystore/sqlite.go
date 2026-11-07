package keystore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/crypto"
	"banksec-lab/internal/domain"
)

const keyMaterialBytes = 32

// storeKeyBytes is the size of the wrapping key used to encrypt
// generated material at rest. 32 bytes matches crypto.Engine's
// "standard" (AES-GCM) key size.
const storeKeyBytes = 32

type sqliteStore struct {
	db            *sql.DB
	engine        crypto.Engine
	encryptAtRest bool
	// storeKey wraps generated material before it is persisted, when
	// encryptAtRest is true. Loaded from (or generated into) a sidecar
	// file beside the database -- never from the database itself, since
	// storing it there would make "encrypted at rest" meaningless -- and
	// persisted so a hardened keystore can still decrypt its own keys
	// after the process restarts (security review finding I5; a bare
	// in-memory-only key broke every CLI invocation after the first).
	storeKey []byte
	audit    audit.Stream
}

// NewSQLiteStore opens (creating if necessary) a key store at path. path
// must be a different file than the ledger's, per ARCHITECTURE.md §7.
// engine performs the at-rest wrapping when encryptAtRest is true
// ("standard" profile, AES-GCM); when encryptAtRest is false (vulnerable
// mode), generated material is persisted as plaintext. Every
// Generate/Get/Rotate/Revoke call records exactly one audit.Event (never
// including key material) to auditStream; if that recording itself
// fails, the operation fails closed (security review finding I8) rather
// than silently succeeding with no access trail.
func NewSQLiteStore(path string, engine crypto.Engine, encryptAtRest bool, auditStream audit.Stream) (Store, error) {
	// busy_timeout: see internal/ledger/sqlite.go's NewSQLiteStore for why.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open keystore %s: %w", path, err)
	}
	const schema = `
CREATE TABLE IF NOT EXISTS keys (
	id         TEXT PRIMARY KEY,
	profile    TEXT NOT NULL,
	material   BLOB NOT NULL,
	wrapped    INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	rotated_at INTEGER,
	revoked_at INTEGER
);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create keystore schema: %w", err)
	}

	var storeKey []byte
	if encryptAtRest {
		storeKey, err = loadOrCreateStoreKey(path + ".key")
		if err != nil {
			db.Close()
			return nil, err
		}
	}

	return &sqliteStore{db: db, engine: engine, encryptAtRest: encryptAtRest, storeKey: storeKey, audit: auditStream}, nil
}

// loadOrCreateStoreKey reads a hex-encoded wrapping key from a sidecar
// file at path, generating and persisting a fresh one (mode 0600) on
// first use.
func loadOrCreateStoreKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		key, decErr := hex.DecodeString(strings.TrimSpace(string(data)))
		if decErr != nil {
			return nil, fmt.Errorf("decode store key %s: %w", path, decErr)
		}
		if len(key) != storeKeyBytes {
			return nil, fmt.Errorf("store key %s: expected %d bytes, got %d", path, storeKeyBytes, len(key))
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read store key %s: %w", path, err)
	}

	key := make([]byte, storeKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate store key: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		return nil, fmt.Errorf("write store key %s: %w", path, err)
	}
	return key, nil
}

// recordAudit emits one audit.Event for a keystore operation and reports
// whether that succeeded. It never includes key material -- only the
// operation name and its outcome. Uses context.WithoutCancel so a
// caller's context being canceled right as its own operation finishes
// can't itself cause an unaudited access.
func (s *sqliteStore) recordAudit(ctx context.Context, operation, outcome string) error {
	id, err := newKeyID()
	if err != nil {
		return fmt.Errorf("generate audit event id: %w", err)
	}
	if err := s.audit.Record(context.WithoutCancel(ctx), audit.Event{
		ID:        id,
		Timestamp: time.Now(),
		Type:      "key_access",
		Component: "keystore",
		Operation: operation,
		Outcome:   outcome,
	}); err != nil {
		return fmt.Errorf("record keystore audit event for %s: %w", operation, err)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// encodeIDBound prefixes material with id (length-prefixed), so the
// wrapped ciphertext is bound to the row it belongs to -- see unwrap.
func encodeIDBound(id string, material []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(id)))
	out := make([]byte, 0, 4+len(id)+len(material))
	out = append(out, lenBuf[:]...)
	out = append(out, id...)
	out = append(out, material...)
	return out
}

func decodeIDBound(plaintext []byte) (id string, material []byte, err error) {
	if len(plaintext) < 4 {
		return "", nil, fmt.Errorf("wrapped plaintext too short")
	}
	idLen := binary.BigEndian.Uint32(plaintext[:4])
	if uint64(idLen) > uint64(len(plaintext)-4) {
		return "", nil, fmt.Errorf("wrapped plaintext id length out of range")
	}
	return string(plaintext[4 : 4+idLen]), plaintext[4+idLen:], nil
}

// wrap encrypts material for storage under id when encryptAtRest is
// true, or returns it unchanged otherwise.
func (s *sqliteStore) wrap(id string, material []byte) ([]byte, error) {
	if !s.encryptAtRest {
		return material, nil
	}
	ciphertext, err := s.engine.Encrypt("standard", s.storeKey, encodeIDBound(id, material))
	if err != nil {
		return nil, fmt.Errorf("encrypt key material at rest: %w", err)
	}
	return ciphertext, nil
}

// unwrap reverses wrap, and rejects ciphertext that doesn't decode to
// the expected id. crypto.Engine's Encrypt has no associated-data
// parameter, so id is bound by being encrypted as part of the plaintext
// instead -- without this, an attacker who can write to keystore.db
// could copy one key's ciphertext into a different key's row, and Get
// would silently return the wrong key's material (security review
// finding I4).
func (s *sqliteStore) unwrap(id string, stored []byte) ([]byte, error) {
	if !s.encryptAtRest {
		return stored, nil
	}
	plaintext, err := s.engine.Decrypt("standard", s.storeKey, stored)
	if err != nil {
		return nil, fmt.Errorf("decrypt key material at rest: %w", err)
	}
	gotID, material, err := decodeIDBound(plaintext)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped key material: %w", err)
	}
	if gotID != id {
		return nil, fmt.Errorf("wrapped key material for %q does not match its own row (got id %q) -- possible row tampering", id, gotID)
	}
	return material, nil
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}

func newKeyID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate key id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func newKeyMaterial() ([]byte, error) {
	material := make([]byte, keyMaterialBytes)
	if _, err := rand.Read(material); err != nil {
		return nil, fmt.Errorf("generate key material: %w", err)
	}
	return material, nil
}

func (s *sqliteStore) Generate(ctx context.Context, profile domain.CryptoProfileName) (meta KeyMeta, err error) {
	outcome := "ok"
	defer func() {
		if auditErr := s.recordAudit(ctx, "Generate", outcome); auditErr != nil && err == nil {
			err = auditErr
		}
	}()

	id, err := newKeyID()
	if err != nil {
		outcome = "error"
		return KeyMeta{}, err
	}
	material, err := newKeyMaterial()
	if err != nil {
		outcome = "error"
		return KeyMeta{}, err
	}
	stored, err := s.wrap(id, material)
	if err != nil {
		outcome = "error"
		return KeyMeta{}, err
	}
	now := time.Now()

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO keys (id, profile, material, wrapped, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, string(profile), stored, boolToInt(s.encryptAtRest), now.UnixNano())
	if err != nil {
		outcome = "error"
		return KeyMeta{}, fmt.Errorf("insert key: %w", err)
	}

	return KeyMeta{ID: id, Profile: profile, CreatedAt: now}, nil
}

// queryRow fetches and decrypts one key row, without recording an audit
// event -- used both by the public Get (which records one) and by Rotate
// (which must inspect the post-rotation row without attributing a second,
// spurious "Get" event to what is really one "Rotate" operation).
func (s *sqliteStore) queryRow(ctx context.Context, id string) ([]byte, KeyMeta, error) {
	var profile string
	var material []byte
	var wrapped int
	var createdAt int64
	var rotatedAt, revokedAt sql.NullInt64

	err := s.db.QueryRowContext(ctx,
		`SELECT profile, material, wrapped, created_at, rotated_at, revoked_at FROM keys WHERE id = ?`, id,
	).Scan(&profile, &material, &wrapped, &createdAt, &rotatedAt, &revokedAt)
	if err == sql.ErrNoRows {
		return nil, KeyMeta{}, ErrKeyNotFound
	}
	if err != nil {
		return nil, KeyMeta{}, fmt.Errorf("query key: %w", err)
	}

	meta := metaFromRow(id, profile, createdAt, rotatedAt, revokedAt)
	if meta.RevokedAt != nil {
		return nil, meta, ErrKeyRevoked
	}
	if (wrapped != 0) != s.encryptAtRest {
		// A store opened with encryptAtRest=false reading a row written
		// under encryptAtRest=true (or vice versa) would otherwise
		// return raw ciphertext as if it were the plaintext key, or try
		// to AES-GCM-decrypt an already-plaintext key, silently
		// (security review finding I6).
		return nil, meta, fmt.Errorf("key %s: stored wrapped=%v but store opened with encryptAtRest=%v -- reopen with the original mode",
			id, wrapped != 0, s.encryptAtRest)
	}
	plaintext, err := s.unwrap(id, material)
	if err != nil {
		return nil, meta, err
	}
	return plaintext, meta, nil
}

func (s *sqliteStore) Get(ctx context.Context, id string) (material []byte, meta KeyMeta, err error) {
	outcome := "ok"
	defer func() {
		if auditErr := s.recordAudit(ctx, "Get", outcome); auditErr != nil && err == nil {
			// The lookup itself succeeded, but we can't prove it was
			// audited -- fail closed rather than hand back key material
			// with a silently-missing access trail (finding I8).
			material = nil
			err = auditErr
		}
	}()

	material, meta, err = s.queryRow(ctx, id)
	if err != nil {
		outcome = "error"
	}
	return material, meta, err
}

func (s *sqliteStore) Rotate(ctx context.Context, id string) (meta KeyMeta, err error) {
	outcome := "ok"
	defer func() {
		if auditErr := s.recordAudit(ctx, "Rotate", outcome); auditErr != nil && err == nil {
			err = auditErr
		}
	}()

	material, err := newKeyMaterial()
	if err != nil {
		outcome = "error"
		return KeyMeta{}, err
	}
	stored, err := s.wrap(id, material)
	if err != nil {
		outcome = "error"
		return KeyMeta{}, err
	}
	now := time.Now()

	res, err := s.db.ExecContext(ctx,
		`UPDATE keys SET material = ?, wrapped = ?, rotated_at = ? WHERE id = ? AND revoked_at IS NULL`,
		stored, boolToInt(s.encryptAtRest), now.UnixNano(), id)
	if err != nil {
		outcome = "error"
		return KeyMeta{}, fmt.Errorf("rotate key: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		outcome = "error"
		// The WHERE clause's revoked_at IS NULL means 0 rows affected
		// could mean either "no such key" or "this key is revoked" --
		// without distinguishing them, Rotate used to happily generate
		// and store fresh material for a revoked key (finding I13).
		if _, _, checkErr := s.queryRow(ctx, id); errors.Is(checkErr, ErrKeyRevoked) {
			return KeyMeta{}, ErrKeyRevoked
		}
		return KeyMeta{}, ErrKeyNotFound
	}

	_, rowMeta, err := s.queryRow(ctx, id)
	if err != nil && !errors.Is(err, ErrKeyRevoked) {
		outcome = "error"
		return KeyMeta{}, err
	}
	return rowMeta, nil
}

func (s *sqliteStore) Revoke(ctx context.Context, id string) (err error) {
	outcome := "ok"
	defer func() {
		if auditErr := s.recordAudit(ctx, "Revoke", outcome); auditErr != nil && err == nil {
			err = auditErr
		}
	}()

	res, err := s.db.ExecContext(ctx,
		`UPDATE keys SET revoked_at = ? WHERE id = ?`,
		time.Now().UnixNano(), id)
	if err != nil {
		outcome = "error"
		return fmt.Errorf("revoke key: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		outcome = "error"
		return ErrKeyNotFound
	}
	return nil
}

func metaFromRow(id, profile string, createdAt int64, rotatedAt, revokedAt sql.NullInt64) KeyMeta {
	meta := KeyMeta{
		ID:        id,
		Profile:   domain.CryptoProfileName(profile),
		CreatedAt: time.Unix(0, createdAt),
	}
	if rotatedAt.Valid {
		t := time.Unix(0, rotatedAt.Int64)
		meta.RotatedAt = &t
	}
	if revokedAt.Valid {
		t := time.Unix(0, revokedAt.Int64)
		meta.RevokedAt = &t
	}
	return meta
}
