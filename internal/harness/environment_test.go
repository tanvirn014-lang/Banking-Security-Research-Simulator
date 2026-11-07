package harness

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"banksec-lab/internal/config"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/protocol"
)

func newTestEnvironment(t *testing.T, configPath string) *Environment {
	t.Helper()
	profile, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load(%s): %v", configPath, err)
	}
	env, err := NewLocalEnvironment(profile)
	if err != nil {
		t.Fatalf("NewLocalEnvironment: %v", err)
	}
	t.Cleanup(func() {
		if err := env.Close(); err != nil {
			t.Errorf("Environment.Close: %v", err)
		}
	})
	return env
}

// TestLocalEnvironment_UsesInMemoryTransportAndOwnTempFiles is the
// concrete test behind the user's "verify attacks cannot target systems
// outside the simulator" requirement: every store this Environment
// wires lives as a file under its own temp directory (never an
// externally-supplied path), and a full create-account/deposit/balance
// round trip works through protocol.Client with no network
// configuration of any kind -- protocol.NewPipeTransport is in-memory
// by construction, so there is nothing to configure.
func TestLocalEnvironment_UsesInMemoryTransportAndOwnTempFiles(t *testing.T) {
	env := newTestEnvironment(t, "../../configs/hardened.json")

	for _, name := range []string{"ledger.db", "audit.db", "keystore.db"} {
		path := filepath.Join(env.dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist under the environment's own temp dir: %v", path, err)
		}
	}

	ctx := context.Background()
	owner := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}

	createResp, err := env.Client.Send(ctx, protocol.Request{Op: "create-account", Actor: owner, Params: map[string]string{"owner": "owner-1"}})
	if err != nil || !createResp.OK {
		t.Fatalf("create-account: resp=%+v err=%v", createResp, err)
	}
	acct := createResp.Data["account"]

	depositResp, err := env.Client.Send(ctx, protocol.Request{Op: "deposit", Actor: owner, Params: map[string]string{"account": acct, "amount": "500"}})
	if err != nil || !depositResp.OK {
		t.Fatalf("deposit: resp=%+v err=%v", depositResp, err)
	}

	balResp, err := env.Client.Send(ctx, protocol.Request{Op: "balance", Actor: owner, Params: map[string]string{"account": acct}})
	if err != nil || !balResp.OK || balResp.Data["balance"] != "500" {
		t.Fatalf("balance: resp=%+v err=%v", balResp, err)
	}
}

// TestEnvironment_Close_WaitsForLeakedGoroutine is the regression test
// for security review finding I3: a Scenario whose Exec ignored its own
// ctx/Timeout left a goroutine still running after Run returned; Close
// used to tear down the stores immediately regardless, which on Windows
// made RemoveAll fail with "used by another process" (and on any OS let
// the leaked goroutine keep mutating a store Close was supposed to have
// finalized). Close now gives such a goroutine a bounded grace period.
func TestEnvironment_Close_WaitsForLeakedGoroutine(t *testing.T) {
	profile, err := config.Load("../../configs/hardened.json")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	env, err := NewLocalEnvironment(profile)
	if err != nil {
		t.Fatalf("NewLocalEnvironment: %v", err)
	}

	finishedWrite := make(chan struct{})
	s := Scenario{
		ID:      "test-close-waits",
		Timeout: 20 * time.Millisecond,
		Exec: func(ctx context.Context, client protocol.Client, priv PrivilegedAccess, rnd *rand.Rand) error {
			// Deliberately ignores ctx, like a non-cooperative Exec, but
			// finishes within Close's grace period.
			time.Sleep(300 * time.Millisecond)
			close(finishedWrite)
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) { return false, nil, nil },
	}
	r := NewRunner()
	if _, err := r.Run(context.Background(), s, env, 1); err == nil {
		t.Fatalf("expected Run to report Verify's own context-deadline error after the 20ms Timeout")
	}

	if err := env.Close(); err != nil {
		t.Fatalf("Close: expected no error (Close should have waited out the leaked goroutine's 300ms sleep within its 2s grace period), got %v", err)
	}
	select {
	case <-finishedWrite:
	default:
		t.Fatalf("expected the leaked goroutine to have finished before Close returned")
	}
	if _, err := os.Stat(env.dir); !os.IsNotExist(err) {
		t.Fatalf("expected the environment's temp dir to be fully removed after Close, stat err=%v", err)
	}
}
