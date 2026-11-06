package keystore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"banksec-lab/internal/domain"
)

const keyMaterialBytes = 32

type sqliteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (creating if necessary) a key store at path. path
// must be a different file than the ledger's, per ARCHITECTURE.md §7.
func NewSQLiteStore(path string) (Store, error) {
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
	created_at INTEGER NOT NULL,
	rotated_at INTEGER,
	revoked_at INTEGER
);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create keystore schema: %w", err)
	}
	return &sqliteStore{db: db}, nil
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

func (s *sqliteStore) Generate(ctx context.Context, profile domain.CryptoProfileName) (KeyMeta, error) {
	id, err := newKeyID()
	if err != nil {
		return KeyMeta{}, err
	}
	material, err := newKeyMaterial()
	if err != nil {
		return KeyMeta{}, err
	}
	now := time.Now()

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO keys (id, profile, material, created_at) VALUES (?, ?, ?, ?)`,
		id, string(profile), material, now.UnixNano())
	if err != nil {
		return KeyMeta{}, fmt.Errorf("insert key: %w", err)
	}

	return KeyMeta{ID: id, Profile: profile, CreatedAt: now}, nil
}

func (s *sqliteStore) Get(ctx context.Context, id string) ([]byte, KeyMeta, error) {
	var profile string
	var material []byte
	var createdAt int64
	var rotatedAt, revokedAt sql.NullInt64

	err := s.db.QueryRowContext(ctx,
		`SELECT profile, material, created_at, rotated_at, revoked_at FROM keys WHERE id = ?`, id,
	).Scan(&profile, &material, &createdAt, &rotatedAt, &revokedAt)
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
	return material, meta, nil
}

func (s *sqliteStore) Rotate(ctx context.Context, id string) (KeyMeta, error) {
	material, err := newKeyMaterial()
	if err != nil {
		return KeyMeta{}, err
	}
	now := time.Now()

	res, err := s.db.ExecContext(ctx,
		`UPDATE keys SET material = ?, rotated_at = ? WHERE id = ?`,
		material, now.UnixNano(), id)
	if err != nil {
		return KeyMeta{}, fmt.Errorf("rotate key: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return KeyMeta{}, ErrKeyNotFound
	}

	_, meta, err := s.Get(ctx, id)
	if err != nil && !errors.Is(err, ErrKeyRevoked) {
		return KeyMeta{}, err
	}
	return meta, nil
}

func (s *sqliteStore) Revoke(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE keys SET revoked_at = ? WHERE id = ?`,
		time.Now().UnixNano(), id)
	if err != nil {
		return fmt.Errorf("revoke key: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
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
