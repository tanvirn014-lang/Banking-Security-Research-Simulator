package main

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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
