package keystore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/crypto"
	"banksec-lab/internal/testsupport"
)

func newTestAuditStream(t *testing.T) audit.Stream {
	t.Helper()
	a, err := audit.NewSQLiteStream(testsupport.TempSQLitePath(t), false)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStream: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func newTestKeystore(t *testing.T) Store {
	t.Helper()
	s, err := NewSQLiteStore(testsupport.TempSQLitePath(t), crypto.NewEngine(), false, newTestAuditStream(t))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func newTestKeystoreAt(t *testing.T, path string, encryptAtRest bool) Store {
	t.Helper()
	s, err := NewSQLiteStore(path, crypto.NewEngine(), encryptAtRest, newTestAuditStream(t))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func newTestKeystoreWithAudit(t *testing.T, a audit.Stream) Store {
	t.Helper()
	s, err := NewSQLiteStore(testsupport.TempSQLitePath(t), crypto.NewEngine(), false, a)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func rawMaterial(t *testing.T, path, id string) []byte {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer db.Close()
	var material []byte
	if err := db.QueryRow(`SELECT material FROM keys WHERE id = ?`, id).Scan(&material); err != nil {
		t.Fatalf("query raw material: %v", err)
	}
	return material
}

func TestGenerateGet_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestKeystore(t)

	meta, err := s.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if meta.ID == "" {
		t.Fatalf("expected a non-empty key ID")
	}

	material, gotMeta, err := s.Get(ctx, meta.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(material) == 0 {
		t.Fatalf("expected non-empty key material")
	}
	if gotMeta.ID != meta.ID {
		t.Fatalf("meta mismatch: got %q, want %q", gotMeta.ID, meta.ID)
	}
}

func TestRotate_UpdatesMetaAndMaterial(t *testing.T) {
	ctx := context.Background()
	s := newTestKeystore(t)

	meta, err := s.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	before, _, err := s.Get(ctx, meta.ID)
	if err != nil {
		t.Fatalf("Get before rotate: %v", err)
	}

	rotated, err := s.Rotate(ctx, meta.ID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.RotatedAt == nil {
		t.Fatalf("expected RotatedAt to be set after rotation")
	}

	after, _, err := s.Get(ctx, meta.ID)
	if err != nil {
		t.Fatalf("Get after rotate: %v", err)
	}
	if bytes.Equal(before, after) {
		t.Fatalf("expected key material to change after rotation")
	}
}

func TestRevoke_BlocksGet(t *testing.T) {
	ctx := context.Background()
	s := newTestKeystore(t)

	meta, err := s.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := s.Revoke(ctx, meta.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, _, err = s.Get(ctx, meta.ID)
	if !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("expected ErrKeyRevoked, got %v", err)
	}
}

func TestGet_UnknownID(t *testing.T) {
	ctx := context.Background()
	s := newTestKeystore(t)

	_, _, err := s.Get(ctx, "no-such-id")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestEncryptAtRest_RawRowIsCiphertext(t *testing.T) {
	ctx := context.Background()
	path := testsupport.TempSQLitePath(t)
	s := newTestKeystoreAt(t, path, true)

	meta, err := s.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	material, _, err := s.Get(ctx, meta.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	raw := rawMaterial(t, path, meta.ID)
	if bytes.Equal(raw, material) {
		t.Fatalf("expected raw row material to differ from Get's plaintext under encryptAtRest=true")
	}
}

func TestNoEncryptAtRest_RawRowIsPlaintext(t *testing.T) {
	ctx := context.Background()
	path := testsupport.TempSQLitePath(t)
	s := newTestKeystoreAt(t, path, false)

	meta, err := s.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	material, _, err := s.Get(ctx, meta.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	raw := rawMaterial(t, path, meta.ID)
	if !bytes.Equal(raw, material) {
		t.Fatalf("expected raw row material to equal Get's plaintext under encryptAtRest=false, got raw=%x material=%x", raw, material)
	}
}

func TestEachKeystoreOperation_EmitsOneAuditEvent(t *testing.T) {
	ctx := context.Background()
	a := newTestAuditStream(t)
	s := newTestKeystoreWithAudit(t, a)

	start := time.Now().Add(-time.Minute)

	meta, err := s.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, _, err := s.Get(ctx, meta.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.Rotate(ctx, meta.ID); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := s.Revoke(ctx, meta.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	events, err := a.Since(ctx, start)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}

	wantOps := []string{"Generate", "Get", "Rotate", "Revoke"}
	gotOps := make(map[string]int)
	for _, e := range events {
		if e.Component != "keystore" {
			t.Fatalf("expected Component %q, got %q (event %+v)", "keystore", e.Component, e)
		}
		gotOps[e.Operation]++
	}
	for _, op := range wantOps {
		if gotOps[op] != 1 {
			t.Fatalf("expected exactly one audit event for %q, got %d (all events: %+v)", op, gotOps[op], events)
		}
	}
}

func TestAuditEvents_NeverContainKeyMaterial(t *testing.T) {
	ctx := context.Background()
	a := newTestAuditStream(t)
	s := newTestKeystoreWithAudit(t, a)

	start := time.Now().Add(-time.Minute)

	meta, err := s.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	material, _, err := s.Get(ctx, meta.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := s.Rotate(ctx, meta.ID); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	events, err := a.Since(ctx, start)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}

	needle := hex.EncodeToString(material)
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("marshal events: %v", err)
	}
	if strings.Contains(string(encoded), needle) {
		t.Fatalf("audit events leaked key material: %s", encoded)
	}
	for _, e := range events {
		rendered := fmt.Sprintf("%+v", e)
		if strings.Contains(rendered, needle) {
			t.Fatalf("audit event %%+v rendering leaked key material: %s", rendered)
		}
	}
}

// TestCiphertextSwap_Rejected is the regression test for security review
// finding I4: wrap/unwrap had no way to bind a ciphertext to the row it
// belongs to, so copying one key's ciphertext into a different key's row
// via raw SQL made Get silently return the wrong key's material.
func TestCiphertextSwap_Rejected(t *testing.T) {
	ctx := context.Background()
	path := testsupport.TempSQLitePath(t)
	s := newTestKeystoreAt(t, path, true)

	metaA, err := s.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate A: %v", err)
	}
	metaB, err := s.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate B: %v", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE keys SET material = (SELECT material FROM keys WHERE id = ?) WHERE id = ?`, metaA.ID, metaB.ID); err != nil {
		t.Fatalf("copy A's ciphertext into B's row: %v", err)
	}

	if _, _, err := s.Get(ctx, metaB.ID); err == nil {
		t.Fatalf("expected Get(B) to reject material copied from A's row, got no error")
	}
}

// TestKeystore_StoreKeyPersistsAcrossReopen is the regression test for
// finding I5: the wrapping key was generated fresh on every
// NewSQLiteStore call and never persisted, so a hardened keystore
// couldn't decrypt its own keys after the process restarted -- yet the
// CLI opens a fresh keystore on every invocation against the same
// persistent keystore.db.
func TestKeystore_StoreKeyPersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := testsupport.TempSQLitePath(t)

	s1, err := NewSQLiteStore(path, crypto.NewEngine(), true, newTestAuditStream(t))
	if err != nil {
		t.Fatalf("NewSQLiteStore (first open): %v", err)
	}
	meta, err := s1.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want, _, err := s1.Get(ctx, meta.ID)
	if err != nil {
		t.Fatalf("Get before reopen: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := NewSQLiteStore(path, crypto.NewEngine(), true, newTestAuditStream(t))
	if err != nil {
		t.Fatalf("NewSQLiteStore (reopen): %v", err)
	}
	defer s2.Close()

	got, _, err := s2.Get(ctx, meta.ID)
	if err != nil {
		t.Fatalf("Get after reopening the same encrypted keystore: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("material changed across reopen: got %x want %x", got, want)
	}
}

// TestGet_WrappedModeMismatchRejected is the regression test for finding
// I6: a key wrapped under encryptAtRest=true, read back by a store
// opened with encryptAtRest=false, previously returned the raw
// ciphertext as if it were the plaintext key -- silently, with no error.
func TestGet_WrappedModeMismatchRejected(t *testing.T) {
	ctx := context.Background()
	path := testsupport.TempSQLitePath(t)

	s1, err := NewSQLiteStore(path, crypto.NewEngine(), true, newTestAuditStream(t))
	if err != nil {
		t.Fatalf("NewSQLiteStore (encrypted): %v", err)
	}
	meta, err := s1.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := NewSQLiteStore(path, crypto.NewEngine(), false, newTestAuditStream(t))
	if err != nil {
		t.Fatalf("NewSQLiteStore (plaintext mode): %v", err)
	}
	defer s2.Close()

	if _, _, err := s2.Get(ctx, meta.ID); err == nil {
		t.Fatalf("expected Get to reject a key wrapped under a different encryptAtRest mode, got no error")
	}
}

// TestGet_FailsWhenAuditRecordingFails is the regression test for
// finding I8: recordAudit discarded the underlying Record error, so Get
// returned key material successfully even when its own access couldn't
// be audited.
func TestGet_FailsWhenAuditRecordingFails(t *testing.T) {
	ctx := context.Background()
	a, err := audit.NewSQLiteStream(testsupport.TempSQLitePath(t), false)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStream: %v", err)
	}
	s, err := NewSQLiteStore(testsupport.TempSQLitePath(t), crypto.NewEngine(), true, a)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer s.Close()

	meta, err := s.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := a.Close(); err != nil {
		t.Fatalf("close audit stream: %v", err)
	}

	material, _, err := s.Get(ctx, meta.ID)
	if err == nil {
		t.Fatalf("expected Get to fail when its access can't be audited, got material=%x err=nil", material)
	}
	if material != nil {
		t.Fatalf("expected no key material returned when the access wasn't audited, got %x", material)
	}
}

// TestRotate_RevokedKeyRejected is the regression test for finding I13:
// Rotate's UPDATE had no revoked_at check, so it would generate and
// store fresh material for a revoked key (and report success), even
// though Get already correctly refused to return it.
func TestRotate_RevokedKeyRejected(t *testing.T) {
	ctx := context.Background()
	s := newTestKeystore(t)

	meta, err := s.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := s.Revoke(ctx, meta.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if _, err := s.Rotate(ctx, meta.ID); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("expected ErrKeyRevoked when rotating a revoked key, got %v", err)
	}
}
