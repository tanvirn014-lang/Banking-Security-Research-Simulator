package harness

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/crypto"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/keystore"
	"banksec-lab/internal/ledger"
	"banksec-lab/internal/testsupport"
)

func TestPrivilegedAccess_RawLedgerWrite_BypassesInvariantCheck(t *testing.T) {
	ctx := context.Background()
	ledgerPath := testsupport.TempSQLitePath(t)

	l, err := ledger.NewSQLiteStore(ledgerPath)
	if err != nil {
		t.Fatalf("ledger.NewSQLiteStore: %v", err)
	}
	defer l.Close()

	priv := newPrivilegedAccess(ledgerPath, "", "")

	// A single, unmatched entry -- AppendTransaction's own balance check
	// would reject this outright. PrivilegedAccess must not.
	if err := priv.RawLedgerWrite(ctx, []ledger.Entry{
		{TxID: "insider-tx", AccountID: "acct-1", Amount: 1, Timestamp: time.Now()},
	}); err != nil {
		t.Fatalf("RawLedgerWrite: %v", err)
	}

	ok, bad, err := l.CheckInvariant(ctx)
	if err != nil {
		t.Fatalf("CheckInvariant: %v", err)
	}
	if ok || len(bad) != 1 || bad[0] != "insider-tx" {
		t.Fatalf("expected the raw write to have broken the invariant for tx 'insider-tx', got ok=%v bad=%v", ok, bad)
	}
}

func TestPrivilegedAccess_RawAuditWrite_BypassesHashChain(t *testing.T) {
	ctx := context.Background()
	auditPath := testsupport.TempSQLitePath(t)

	a, err := audit.NewSQLiteStream(auditPath, true)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStream: %v", err)
	}
	defer a.Close()
	if err := a.Record(ctx, audit.Event{ID: "e1", Timestamp: time.Now(), Type: "op"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	priv := newPrivilegedAccess("", auditPath, "")
	if err := priv.RawAuditWrite(ctx, audit.Event{ID: "insider-e", Timestamp: time.Now(), Type: "op"}); err != nil {
		t.Fatalf("RawAuditWrite: %v", err)
	}

	ok, _, err := a.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if ok {
		t.Fatalf("expected a raw-SQL audit write (no hash computed) to break the hash chain, got ok=true")
	}
}

func TestPrivilegedAccess_RawKeyBytes_ReturnsStoredRepresentationAsIs(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name          string
		encryptAtRest bool
	}{
		{"vulnerable_plaintext", false},
		{"hardened_ciphertext", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keystorePath := testsupport.TempSQLitePath(t)
			auditPath := testsupport.TempSQLitePath(t)
			a, err := audit.NewSQLiteStream(auditPath, false)
			if err != nil {
				t.Fatalf("audit.NewSQLiteStream: %v", err)
			}
			defer a.Close()

			k, err := keystore.NewSQLiteStore(keystorePath, crypto.NewEngine(), tc.encryptAtRest, a)
			if err != nil {
				t.Fatalf("keystore.NewSQLiteStore: %v", err)
			}
			defer k.Close()

			meta, err := k.Generate(ctx, domain.CryptoProfileName("standard"))
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			wantPlaintext, _, err := k.Get(ctx, meta.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}

			priv := newPrivilegedAccess("", "", keystorePath)
			raw, err := priv.RawKeyBytes(ctx, meta.ID)
			if err != nil {
				t.Fatalf("RawKeyBytes: %v", err)
			}

			if tc.encryptAtRest {
				if bytes.Equal(raw, wantPlaintext) {
					t.Fatalf("expected RawKeyBytes to return still-wrapped ciphertext under hardened mode, got the plaintext")
				}
			} else {
				if !bytes.Equal(raw, wantPlaintext) {
					t.Fatalf("expected RawKeyBytes to return the plaintext as-is under vulnerable mode, got %x want %x", raw, wantPlaintext)
				}
			}
		})
	}
}

// TestPrivilegedAccess_ConstructorOnlyAcceptsLocalPaths is a structural
// proxy for the user's "verify attacks cannot target systems outside
// the simulator" requirement, within what this is actually able to
// prove (see PrivilegedAccess's doc comment for the honest limits of
// that guarantee -- Go cannot sandbox arbitrary in-process code):
// newPrivilegedAccess's only inputs are plain strings (local SQLite file
// paths), never a network address, host, or connection type that could
// point anywhere else. It is also unexported, so no Scenario can call it
// directly with a path of its own choosing -- only
// harness.NewLocalEnvironment (environment.go) can.
func TestPrivilegedAccess_ConstructorOnlyAcceptsLocalPaths(t *testing.T) {
	fn := reflect.ValueOf(newPrivilegedAccess).Type()
	for i := 0; i < fn.NumIn(); i++ {
		if fn.In(i).Kind() != reflect.String {
			t.Fatalf("newPrivilegedAccess parameter %d has kind %v, want string (a local file path) -- any non-string parameter (e.g. a net.Addr or URL) would let a Scenario point PrivilegedAccess somewhere outside this simulator", i, fn.In(i).Kind())
		}
	}
}
