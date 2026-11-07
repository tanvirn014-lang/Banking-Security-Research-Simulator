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
	// Meta returns a key's lifecycle metadata only -- it never decrypts
	// or returns material, and (unlike Get) it is not itself an access-
	// auditable material access: it does not record a key_access audit
	// event, and a revoked key's metadata is returned with no error
	// (RevokedAt set), rather than ErrKeyRevoked. For a purely
	// informational lifecycle read -- e.g. internal/harness's read-only
	// Oracle -- that distinction matters: Get would otherwise pollute
	// the audit trail with reads that are not real material access, and
	// would force a caller that just wants to know "is this revoked?"
	// to treat ErrKeyRevoked as a fatal error rather than an answer.
	Meta(ctx context.Context, id string) (KeyMeta, error)
	Rotate(ctx context.Context, id string) (KeyMeta, error)
	Revoke(ctx context.Context, id string) error
	// Close releases the store's underlying resources.
	Close() error
}

var ErrKeyRevoked = apperr.New(apperr.CodeConflict, "key has been revoked")
var ErrKeyNotFound = apperr.New(apperr.CodeNotFound, "key not found")
