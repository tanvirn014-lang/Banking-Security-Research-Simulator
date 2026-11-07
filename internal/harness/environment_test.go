package harness

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"banksec-lab/internal/backend"
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

// TestEnvironment_NewClientConnection_SharesSameBackend is the
// regression test for Milestone 8's concurrent-overdraft scenario
// (ATTACK_SURFACES.md §1): a single Client serializes its own Send
// calls (one full request/response round trip at a time over one
// connection), and the protocol Server itself processes one connection's
// frames strictly sequentially -- so no amount of concurrent goroutines
// calling the SAME Client can ever produce real concurrent dispatch into
// backend.Service. Genuinely concurrent protocol-mediated requests need
// separate connections against the same backend, which is what
// NewClientConnection provides.
func TestEnvironment_NewClientConnection_SharesSameBackend(t *testing.T) {
	env := newTestEnvironment(t, "../../configs/hardened.json")
	ctx := context.Background()
	owner := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}

	createResp, err := env.Client.Send(ctx, protocol.Request{Op: "create-account", Actor: owner, Params: map[string]string{"owner": "owner-1"}})
	if err != nil || !createResp.OK {
		t.Fatalf("create-account: resp=%+v err=%v", createResp, err)
	}
	acct := createResp.Data["account"]

	if resp, err := env.Client.Send(ctx, protocol.Request{Op: "deposit", Actor: owner, Params: map[string]string{"account": acct, "amount": "1000"}}); err != nil || !resp.OK {
		t.Fatalf("deposit: resp=%+v err=%v", resp, err)
	}

	second, err := env.NewClientConnection()
	if err != nil {
		t.Fatalf("NewClientConnection: %v", err)
	}

	// A balance read through the SECOND connection must see the deposit
	// made through the first -- proving both talk to the same
	// backend.Service, not two independent ones.
	balResp, err := second.Send(ctx, protocol.Request{Op: "balance", Actor: owner, Params: map[string]string{"account": acct}})
	if err != nil || !balResp.OK || balResp.Data["balance"] != "1000" {
		t.Fatalf("balance via second connection: resp=%+v err=%v", balResp, err)
	}
}

// TestEnvironment_GenerateTestKey_RoundTrips is the regression test for
// the GenerateTestKey fixture helper Milestone 8's key-management
// scenarios need: nothing in production actually calls
// keystore.Store.Generate (a known gap, ledgered since Milestone 5), so
// there is no protocol-level way for a Scenario to create a test key the
// way every other scenario creates its fixtures through env.Client.
func TestEnvironment_GenerateTestKey_RoundTrips(t *testing.T) {
	env := newTestEnvironment(t, "../../configs/hardened.json")
	ctx := context.Background()

	meta, material, err := env.GenerateTestKey(ctx, domain.CryptoProfileName("standard"))
	if err != nil {
		t.Fatalf("GenerateTestKey: %v", err)
	}
	if meta.ID == "" {
		t.Fatalf("expected a non-empty key ID")
	}
	if len(material) == 0 {
		t.Fatalf("expected non-empty key material")
	}
}

// TestEnvironment_Close_WaitsForClientConnectionServerGoroutines is the
// regression test for security review finding M3: NewClientConnection's
// (and NewLocalEnvironment's own) per-connection `go server.Serve(...)`
// goroutines were not tracked by e.execWG at all, so Close's
// execWG.Wait() returned without waiting for them, and Close could start
// tearing down the stores (and remove the temp dir) while a dispatch on
// one of those connections was still in flight -- especially relevant
// now that the concurrent-overdraft scenario opens 20 such connections
// per run. These goroutines are tracked the same way runner.go already
// tracks Exec/Verify goroutines (I3's fix), so Close waits for all of
// them (server.Serve returns promptly once ctx is canceled -- see
// protocol.Server.Serve's own doc comment) before closing the stores.
// slowBalanceService wraps a real backend.Service, delaying every
// Balance call -- used to hold a NewClientConnection dispatch open long
// enough to deterministically land Close() while it is still in flight.
type slowBalanceService struct {
	backend.Service
	delay time.Duration
}

func (s slowBalanceService) Balance(ctx context.Context, actor domain.Principal, acct domain.AccountID) (domain.Money, error) {
	time.Sleep(s.delay)
	return s.Service.Balance(ctx, actor, acct)
}

// TestEnvironment_Close_WaitsForClientConnectionServerGoroutines is the
// regression test for security review finding M3: NewClientConnection's
// (and NewLocalEnvironment's own) per-connection `go server.Serve(...)`
// goroutines were not tracked by e.execWG at all, so Close's
// execWG.Wait() returned without waiting for them, and Close could start
// tearing down the stores (and remove the temp dir) while a dispatch on
// one of those connections was still in flight -- especially relevant
// now that the concurrent-overdraft scenario opens 20 such connections
// per run. These goroutines are now tracked the same way runner.go
// already tracks Exec/Verify goroutines (I3's fix).
//
// A plain request/response round trip dispatches too fast to reliably
// land Close() mid-flight, so this swaps in a deliberately slow Balance
// (slowBalanceService) to hold the second connection's dispatch open for
// slowDispatch, fires it from a goroutine, gives it a moment to actually
// enter the slow call, and then measures how long Close() itself takes:
// without the fix, Close returns almost immediately (and the still-
// running dispatch then touches stores Close has already closed); with
// the fix, Close must block for roughly slowDispatch waiting for that
// goroutine to finish.
func TestEnvironment_Close_WaitsForClientConnectionServerGoroutines(t *testing.T) {
	profile, err := config.Load("../../configs/hardened.json")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	env, err := NewLocalEnvironment(profile)
	if err != nil {
		t.Fatalf("NewLocalEnvironment: %v", err)
	}

	ctx := context.Background()
	owner := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}
	createResp, err := env.Client.Send(ctx, protocol.Request{Op: "create-account", Actor: owner, Params: map[string]string{"owner": "owner-1"}})
	if err != nil || !createResp.OK {
		t.Fatalf("create-account: resp=%+v err=%v", createResp, err)
	}
	acct := createResp.Data["account"]

	const slowDispatch = 300 * time.Millisecond
	env.svc = slowBalanceService{Service: env.svc, delay: slowDispatch}

	second, err := env.NewClientConnection()
	if err != nil {
		t.Fatalf("NewClientConnection: %v", err)
	}

	dispatchStarted := make(chan struct{})
	go func() {
		close(dispatchStarted)
		second.Send(ctx, protocol.Request{Op: "balance", Actor: owner, Params: map[string]string{"account": acct}})
	}()
	<-dispatchStarted
	time.Sleep(50 * time.Millisecond) // let the goroutine actually enter the slow Balance call

	closeStart := time.Now()
	if err := env.Close(); err != nil {
		t.Fatalf("Close: expected no error waiting out the in-flight slow dispatch, got %v", err)
	}
	closeElapsed := time.Since(closeStart)
	if closeElapsed < slowDispatch/2 {
		t.Fatalf("expected Close to block for roughly %v waiting for the in-flight dispatch, returned after only %v", slowDispatch, closeElapsed)
	}
	if _, err := os.Stat(env.dir); !os.IsNotExist(err) {
		t.Fatalf("expected the environment's temp dir to be fully removed after Close, stat err=%v", err)
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
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
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
