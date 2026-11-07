package protocol

import (
	"context"
	"strings"
	"testing"

	"banksec-lab/internal/backend"
)

// TestProtocol_NoOpRoutesToPrivilegedAccess is Milestone 7 Task 31's
// Review Focus #2. What this test itself actually proves is narrower
// than "structurally unreachable": it only checks that dispatch's
// current switch statement rejects each of a finite, enumerated list of
// plausible privileged-access-shaped Op strings as unknown -- a future
// `case "admin-ledger-write":` added by mistake would pass this test
// just fine. The real structural guarantee is the import graph:
// internal/protocol has no dependency on internal/harness (this test
// lives in internal/protocol precisely so that importing harness here,
// to call PrivilegedAccess directly, would be caught at compile time by
// whoever tried), and neither does cmd/banksec, which is what actually
// makes PrivilegedAccess unreachable from the one real external
// entrypoint. This test is a cheap, useful regression guard for the
// dispatch switch specifically, not a proof of the broader claim on its
// own (security review finding M4).
func TestProtocol_NoOpRoutesToPrivilegedAccess(t *testing.T) {
	ctx := context.Background()
	l, k, a := newTestStores(t)
	svc := backend.NewService(l, k, a, hardenedWireProfile())

	suspiciousOps := []string{
		"raw-ledger-write",
		"raw-audit-write",
		"raw-key-bytes",
		"rawledgerwrite",
		"RawLedgerWrite",
		"privileged",
		"privileged-access",
		"admin",
		"admin-write",
		"bypass",
		"bypass-invariant",
		"insider",
		"insider-access",
		"debug-write",
		"direct-sql",
	}

	for _, op := range suspiciousOps {
		t.Run(op, func(t *testing.T) {
			resp := dispatch(ctx, svc, Request{Op: op})
			if resp.OK {
				t.Fatalf("expected Op %q to be rejected, got OK response %+v", op, resp)
			}
			if !strings.Contains(resp.Error, "unknown operation") {
				t.Fatalf("expected Op %q to be rejected as an unknown operation, got error %q", op, resp.Error)
			}
		})
	}
}
