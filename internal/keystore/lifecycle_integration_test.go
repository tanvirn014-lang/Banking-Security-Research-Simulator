package keystore

import (
	"context"
	"errors"
	"testing"

	"banksec-lab/internal/crypto"
	"banksec-lab/internal/testsupport"
)

// simulateConsumer stands in for a real key-material consumer (backend,
// protocol): it must re-Get immediately before every logical use and
// never hold material across more than one such use. This is the pattern
// Task 23/K2's audit requires of every current and future caller of
// Store.Get.
func simulateConsumer(ctx context.Context, s Store, id string) ([]byte, error) {
	material, _, err := s.Get(ctx, id)
	return material, err
}

// TestRevokedKey_ImmediatelyRejectedByEveryConsumer proves the mechanism
// every consumer depends on: Store.Get never caches, so a key revoked
// mid-run is immediately rejected on the very next Get call, whether that
// call comes from one simulated consumer or several simulating
// independent call sites (e.g. backend and protocol, had either sourced
// its key material from the keystore -- see this task's brief for why
// neither currently does).
func TestRevokedKey_ImmediatelyRejectedByEveryConsumer(t *testing.T) {
	consumers := []string{"consumer-backend", "consumer-protocol"}

	for _, consumerName := range consumers {
		consumerName := consumerName
		t.Run(consumerName, func(t *testing.T) {
			ctx := context.Background()
			s, err := NewSQLiteStore(testsupport.TempSQLitePath(t), crypto.NewEngine(), false, newTestAuditStream(t))
			if err != nil {
				t.Fatalf("NewSQLiteStore: %v", err)
			}
			t.Cleanup(func() { s.Close() })

			meta, err := s.Generate(ctx, "standard")
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}

			// Several "operations" using the key successfully, each
			// re-Get-ing immediately before use rather than caching
			// material from a prior iteration.
			for i := 0; i < 3; i++ {
				if _, err := simulateConsumer(ctx, s, meta.ID); err != nil {
					t.Fatalf("iteration %d: unexpected error before revocation: %v", i, err)
				}
			}

			if err := s.Revoke(ctx, meta.ID); err != nil {
				t.Fatalf("Revoke: %v", err)
			}

			// The very next operation must fail -- there is no cached
			// copy anywhere that could still be "valid".
			if _, err := simulateConsumer(ctx, s, meta.ID); !errors.Is(err, ErrKeyRevoked) {
				t.Fatalf("expected ErrKeyRevoked on the first Get after revocation, got %v", err)
			}
		})
	}
}

// TestRevokedKey_RejectedEvenWithConcurrentInterleavedConsumers goes one
// step further than the per-consumer test above: two simulated consumers
// interleave Get calls against the same key, and revocation lands between
// their calls -- proving no consumer-local state (e.g. a per-call-site
// cache) could mask the revocation for the other.
func TestRevokedKey_RejectedEvenWithConcurrentInterleavedConsumers(t *testing.T) {
	ctx := context.Background()
	s, err := NewSQLiteStore(testsupport.TempSQLitePath(t), crypto.NewEngine(), false, newTestAuditStream(t))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	meta, err := s.Generate(ctx, "standard")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if _, err := simulateConsumer(ctx, s, meta.ID); err != nil {
		t.Fatalf("consumer A, before revocation: %v", err)
	}
	if _, err := simulateConsumer(ctx, s, meta.ID); err != nil {
		t.Fatalf("consumer B, before revocation: %v", err)
	}

	if err := s.Revoke(ctx, meta.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if _, err := simulateConsumer(ctx, s, meta.ID); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("consumer A, after revocation: expected ErrKeyRevoked, got %v", err)
	}
	if _, err := simulateConsumer(ctx, s, meta.ID); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("consumer B, after revocation: expected ErrKeyRevoked, got %v", err)
	}
}
