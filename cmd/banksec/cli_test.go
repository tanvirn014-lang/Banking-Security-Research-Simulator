package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"banksec-lab/internal/audit"
)

func outputField(t *testing.T, out, key string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return v
		}
	}
	t.Fatalf("expected key %q in CLI output, got %q", key, out)
	return ""
}

func TestCLI_DepositThenBalance(t *testing.T) {
	env := cliEnv{DataDir: t.TempDir(), ProfilePath: "../../configs/hardened.json"}

	createOut, err := runCLI(env, []string{"create-account", "--owner", "owner-1"})
	if err != nil {
		t.Fatalf("create-account: %v", err)
	}
	acct := outputField(t, createOut, "account")

	if _, err := runCLI(env, []string{"deposit", "--account", acct, "--amount", "1000", "--as", "owner-1"}); err != nil {
		t.Fatalf("deposit: %v", err)
	}

	balOut, err := runCLI(env, []string{"balance", "--account", acct, "--as", "owner-1"})
	if err != nil {
		t.Fatalf("balance: %v", err)
	}
	got, err := strconv.ParseInt(outputField(t, balOut, "balance"), 10, 64)
	if err != nil {
		t.Fatalf("parse balance: %v", err)
	}
	if got != 1000 {
		t.Fatalf("got balance %d, want 1000", got)
	}
}

func TestCLI_CreatesDataDirIfMissing(t *testing.T) {
	// A real CLI invocation names a data dir that doesn't exist yet on
	// first run (nothing has created it) -- wireClient must create it,
	// not fail.
	env := cliEnv{
		DataDir:     filepath.Join(t.TempDir(), "does", "not", "exist", "yet"),
		ProfilePath: "../../configs/hardened.json",
	}

	if _, err := runCLI(env, []string{"create-account", "--owner", "owner-1"}); err != nil {
		t.Fatalf("create-account against a not-yet-created data dir: %v", err)
	}
}

func TestCLI_AuditAndTransactionIDsSurviveAcrossInvocations(t *testing.T) {
	// Regression test for the ID-collision bug: two separate CLI
	// invocations (each a fresh runCLI call, as in real usage) must not
	// silently drop audit events or collide on transaction IDs.
	env := cliEnv{DataDir: t.TempDir(), ProfilePath: "../../configs/hardened.json"}

	createOut, err := runCLI(env, []string{"create-account", "--owner", "owner-1"})
	if err != nil {
		t.Fatalf("create-account: %v", err)
	}
	acct := outputField(t, createOut, "account")

	if _, err := runCLI(env, []string{"deposit", "--account", acct, "--amount", "500", "--as", "owner-1"}); err != nil {
		t.Fatalf("deposit 1: %v", err)
	}
	if _, err := runCLI(env, []string{"deposit", "--account", acct, "--amount", "500", "--as", "owner-1"}); err != nil {
		t.Fatalf("deposit 2: %v", err)
	}

	histOut, err := runCLI(env, []string{"history", "--account", acct, "--as", "owner-1"})
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if !strings.Contains(histOut, `"Amount":500`) {
		t.Fatalf("expected history to show the deposits, got %q", histOut)
	}

	balOut, err := runCLI(env, []string{"balance", "--account", acct, "--as", "owner-1"})
	if err != nil {
		t.Fatalf("balance: %v", err)
	}
	got, err := strconv.ParseInt(outputField(t, balOut, "balance"), 10, 64)
	if err != nil {
		t.Fatalf("parse balance: %v", err)
	}
	if got != 1000 {
		t.Fatalf("got balance %d, want 1000 (a dropped deposit would show 500)", got)
	}
}

func TestCLI_ForgedPrincipalStillRejectedServerSide(t *testing.T) {
	env := cliEnv{DataDir: t.TempDir(), ProfilePath: "../../configs/hardened.json"}

	createA, err := runCLI(env, []string{"create-account", "--owner", "owner-1"})
	if err != nil {
		t.Fatalf("create-account A: %v", err)
	}
	acctA := outputField(t, createA, "account")

	createB, err := runCLI(env, []string{"create-account", "--owner", "owner-2"})
	if err != nil {
		t.Fatalf("create-account B: %v", err)
	}
	acctB := outputField(t, createB, "account")

	if _, err := runCLI(env, []string{"deposit", "--account", acctA, "--amount", "1000", "--as", "owner-1"}); err != nil {
		t.Fatalf("deposit: %v", err)
	}

	// The CLI itself performs no authorization check (it is not a trust
	// boundary) -- this must be rejected by the Backend.
	_, err = runCLI(env, []string{"transfer", "--from", acctA, "--to", acctB, "--amount", "100", "--as", "owner-2"})
	if err == nil {
		t.Fatal("expected the forged transfer to be rejected, got no error")
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("expected a server-side unauthorized rejection, got: %v", err)
	}
}

// TestCLI_TypoDetectionRuleID_RejectedAtWiring is the regression test
// for security review finding I6: a typo'd or unknown rule ID in a
// profile's detection_rules used to silently result in zero detection
// rules registered, with nothing telling an operator that their
// "hardened"-named profile was actually running no detection at all.
func TestCLI_TypoDetectionRuleID_RejectedAtWiring(t *testing.T) {
	profilePath := filepath.Join(t.TempDir(), "typo-profile.json")
	const typoProfile = `{
		"name": "hardened",
		"crypto_profile": "standard",
		"min_accepted_crypto_profile": "standard",
		"protocol_auth_enforced": true,
		"authz_enforced": true,
		"atomicity_enforced": true,
		"keystore_encrypted_at_rest": true,
		"audit_hash_chained": true,
		"detection_rules": ["balance-invariant-violaton"]
	}`
	if err := os.WriteFile(profilePath, []byte(typoProfile), 0o600); err != nil {
		t.Fatalf("write temp profile: %v", err)
	}

	env := cliEnv{DataDir: t.TempDir(), ProfilePath: profilePath}
	if _, err := runCLI(env, []string{"create-account", "--owner", "owner-1"}); err == nil {
		t.Fatalf("expected a typo'd detection_rules entry to be rejected at wiring time, got no error")
	}
}

// breakLedgerInvariant inserts a single, unmatched entry directly into
// the ledger.db file, bypassing the backend entirely -- simulating a bug
// or an attacker writing straight to storage.
func breakLedgerInvariant(t *testing.T, dataDir string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "ledger.db"))
	if err != nil {
		t.Fatalf("open raw ledger db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(
		`INSERT INTO entries (tx_id, account_id, amount, timestamp) VALUES (?, ?, ?, ?)`,
		"unbalanced-tx", "acct-1", 1, time.Now().UnixNano(),
	); err != nil {
		t.Fatalf("insert unbalanced entry: %v", err)
	}
}

// TestDetectionEngine_RunsDuringNormalCLIOperation satisfies Milestone 6
// Task 29's Review Focus #5: the Detection Engine must be proven to run
// as part of normal backend operation -- wired into this CLI's own
// wiring (wireClient) as a background component alongside the protocol
// server -- not merely callable directly, as
// TestDetectionEngine_RuleTriggersOnViolation (internal/detection) does.
// This test never constructs a detection.Engine itself; it only drives
// the CLI exactly as a user would.
func TestDetectionEngine_RunsDuringNormalCLIOperation(t *testing.T) {
	env := cliEnv{DataDir: t.TempDir(), ProfilePath: "../../configs/hardened.json"}

	createOut, err := runCLI(env, []string{"create-account", "--owner", "owner-1"})
	if err != nil {
		t.Fatalf("create-account: %v", err)
	}
	acct := outputField(t, createOut, "account")

	if _, err := runCLI(env, []string{"deposit", "--account", acct, "--amount", "1000", "--as", "owner-1"}); err != nil {
		t.Fatalf("deposit: %v", err)
	}

	breakLedgerInvariant(t, env.DataDir)

	// An ordinary CLI invocation -- the detection engine wired into
	// wireClient must observe this invocation's own "backend" audit
	// event and flag the violation introduced above, with no test code
	// calling into internal/detection at all.
	if _, err := runCLI(env, []string{"balance", "--account", acct, "--as", "owner-1"}); err != nil {
		t.Fatalf("balance: %v", err)
	}

	// hardened.json sets audit_hash_chained=true, which wireClient passed
	// to the real stream -- reopening here must use the same mode.
	stream, err := audit.NewSQLiteStream(filepath.Join(env.DataDir, "audit.db"), true)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStream: %v", err)
	}
	defer stream.Close()

	events, err := stream.Since(context.Background(), time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	for _, e := range events {
		if e.Type == "detection" {
			return
		}
	}
	t.Fatalf("expected a detection event recorded during normal CLI operation, found none among %d events: %+v", len(events), events)
}
