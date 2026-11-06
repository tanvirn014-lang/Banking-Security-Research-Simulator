package keystore

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"banksec-lab/internal/testsupport"
)

func newTestKeystore(t *testing.T) Store {
	t.Helper()
	s, err := NewSQLiteStore(testsupport.TempSQLitePath(t))
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
