package keystore

import (
	"bytes"
	"context"
	"testing"
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/config"
	"banksec-lab/internal/crypto"
	"banksec-lab/internal/testsupport"
)

// TestKeystore_SecurityModeDifferential wires the keystore under both the
// hardened and vulnerable configs/*.json profiles and demonstrates, in
// one test, the plaintext-vs-ciphertext at-rest difference (Task K1)
// together with the access-audit trail (Task K3) that Milestone 5's
// requirements ask be shown "together".
func TestKeystore_SecurityModeDifferential(t *testing.T) {
	cases := []struct {
		name           string
		configPath     string
		wantCiphertext bool
	}{
		{name: "hardened", configPath: "../../configs/hardened.json", wantCiphertext: true},
		{name: "vulnerable", configPath: "../../configs/vulnerable.json", wantCiphertext: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			profile, err := config.Load(tc.configPath)
			if err != nil {
				t.Fatalf("config.Load(%s): %v", tc.configPath, err)
			}

			path := testsupport.TempSQLitePath(t)
			a, err := audit.NewSQLiteStream(testsupport.TempSQLitePath(t), profile.AuditHashChained)
			if err != nil {
				t.Fatalf("audit.NewSQLiteStream: %v", err)
			}
			t.Cleanup(func() { a.Close() })

			s, err := NewSQLiteStore(path, crypto.NewEngine(), profile.KeystoreEncryptedAtRest, a)
			if err != nil {
				t.Fatalf("NewSQLiteStore: %v", err)
			}
			t.Cleanup(func() { s.Close() })

			start := time.Now().Add(-time.Minute)

			meta, err := s.Generate(ctx, profile.CryptoProfile)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			material, _, err := s.Get(ctx, meta.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}

			// --- Plaintext-vs-ciphertext differential (K1) ---
			raw := rawMaterial(t, path, meta.ID)
			isCiphertext := !bytes.Equal(raw, material)
			if isCiphertext != tc.wantCiphertext {
				t.Fatalf("profile %q: expected raw-row-is-ciphertext=%v, got %v (raw=%x material=%x)",
					tc.name, tc.wantCiphertext, isCiphertext, raw, material)
			}

			// --- Access-audit trail (K3), same run ---
			events, err := a.Since(ctx, start)
			if err != nil {
				t.Fatalf("Since: %v", err)
			}
			gotOps := make(map[string]int)
			for _, e := range events {
				gotOps[e.Operation]++
			}
			for _, op := range []string{"Generate", "Get"} {
				if gotOps[op] != 1 {
					t.Fatalf("profile %q: expected exactly one audit event for %q, got %d", tc.name, op, gotOps[op])
				}
			}
		})
	}
}
