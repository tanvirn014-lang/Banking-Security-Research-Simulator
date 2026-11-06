// Package keystore implements key lifecycle storage, physically separate
// from the ledger's database (ARCHITECTURE.md §7). This task's store is
// the plaintext-at-rest baseline; encrypted-at-rest arrives in Milestone 5.
package keystore

import (
	"context"
	"time"

	"banksec-lab/internal/apperr"
	"banksec-lab/internal/domain"
)

// KeyMeta is a key's lifecycle metadata (never the key material itself).
type KeyMeta struct {
	ID        string
	Profile   domain.CryptoProfileName
	CreatedAt time.Time
	RotatedAt *time.Time
	RevokedAt *time.Time
}

// Store is the key lifecycle storage interface.
type Store interface {
	Generate(ctx context.Context, profile domain.CryptoProfileName) (KeyMeta, error)
	Get(ctx context.Context, id string) (material []byte, meta KeyMeta, err error)
	Rotate(ctx context.Context, id string) (KeyMeta, error)
	Revoke(ctx context.Context, id string) error
	// Close releases the store's underlying resources.
	Close() error
}

var ErrKeyRevoked = apperr.New(apperr.CodeConflict, "key has been revoked")
var ErrKeyNotFound = apperr.New(apperr.CodeNotFound, "key not found")
