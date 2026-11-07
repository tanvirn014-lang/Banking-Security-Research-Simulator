package harness

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/backend"
	"banksec-lab/internal/config"
	"banksec-lab/internal/crypto"
	"banksec-lab/internal/detection"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/keystore"
	"banksec-lab/internal/ledger"
	"banksec-lab/internal/protocol"
)

// Environment is a complete, isolated local simulator instance: its own
// temp-directory-backed ledger/keystore/audit stores, backend, a
// protocol client/server pair wired over an in-memory pipe (never a
// real socket), and a running Detection Engine -- everything a
// Scenario's Exec/Verify needs. Nothing in this wiring itself has a
// host, port, or external address, and PrivilegedAccess's constructor is
// unexported so a Scenario cannot ask it to open a path of its own
// choosing (see privileged.go). That is what "execution isolation" and
// "attacks cannot target systems outside the simulator" concretely mean
// here: a Scenario using only the Client/Oracle/Priv this Environment
// hands it cannot reach anything else. It is not a sandbox against
// adversarial Scenario code -- Exec is ordinary in-process Go with the
// full privileges of this process (it could open its own files, or
// import net/os directly), and multiple Environments' temp directories
// are all readable/writable by anything in the same process. This
// project only ever registers reviewed, trusted Scenario
// implementations; real isolation against untrusted ones would need
// per-Scenario OS-process sandboxing, out of this milestone's scope.
type Environment struct {
	// Profile is the SecurityProfile this environment was wired under
	// (e.g. configs/hardened.json or configs/vulnerable.json loaded by
	// the caller) -- Profile.Name becomes Result.TargetConfiguration.
	Profile config.SecurityProfile
	Client  protocol.Client
	Oracle  Oracle
	Priv    PrivilegedAccess

	dir      string
	ledger   ledger.Store
	keystore keystore.Store
	audit    audit.Stream
	cancel   context.CancelFunc
	ctx      context.Context
	svc      backend.Service
	engine   crypto.Engine
	// execWG tracks background goroutines runExecWithDeadline/
	// runVerifyWithDeadline (runner.go) launch for a Scenario's Exec/
	// Verify that outlives its own ctx -- Close gives them a bounded
	// grace period before tearing down the stores they may still be
	// using (security review finding I3).
	execWG sync.WaitGroup
}

// trackGoroutine registers one in-flight background goroutine against
// e.execWG and returns the function to call when it finishes.
func (e *Environment) trackGoroutine() func() {
	e.execWG.Add(1)
	return e.execWG.Done
}

// NewLocalEnvironment wires a fresh, isolated stack under profile, in a
// new temp directory. Close releases every resource and removes it.
func NewLocalEnvironment(profile config.SecurityProfile) (*Environment, error) {
	dir, err := os.MkdirTemp("", "harness-env-*")
	if err != nil {
		return nil, fmt.Errorf("create environment temp dir: %w", err)
	}

	ledgerPath := filepath.Join(dir, "ledger.db")
	auditPath := filepath.Join(dir, "audit.db")
	keystorePath := filepath.Join(dir, "keystore.db")

	l, err := ledger.NewSQLiteStore(ledgerPath)
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("open ledger: %w", err)
	}
	a, err := audit.NewSQLiteStream(auditPath, profile.AuditHashChained)
	if err != nil {
		l.Close()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("open audit stream: %w", err)
	}
	engine := crypto.NewEngine()
	k, err := keystore.NewSQLiteStore(keystorePath, engine, profile.KeystoreEncryptedAtRest, a)
	if err != nil {
		l.Close()
		a.Close()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("open keystore: %w", err)
	}

	svc := backend.NewService(l, k, a, profile)

	clientKey, serverKey, err := localAuthKeys(profile.CryptoProfile)
	if err != nil {
		l.Close()
		a.Close()
		k.Close()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("generate protocol auth keys: %w", err)
	}

	// See cmd/banksec/cli.go's identical check: a typo'd or unknown rule
	// ID in profile.DetectionRules must fail loudly here, not silently
	// result in zero rules actually running (security review finding
	// I6).
	knownDetectionRules := []domain.DetectionRuleID{detection.BalanceInvariantRuleID, detection.AuditChainRuleID}
	if err := detection.ValidateDetectionRules(profile.DetectionRules, knownDetectionRules); err != nil {
		l.Close()
		a.Close()
		k.Close()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("profile detection_rules: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	detectionEngine := detection.NewEngine()
	detection.RegisterConfigured(detectionEngine, detection.NewBalanceInvariantRule(l), profile.DetectionRules)
	detection.RegisterConfigured(detectionEngine, detection.NewAuditChainRule(a), profile.DetectionRules)
	if err := detectionEngine.Run(ctx, a); err != nil {
		cancel()
		l.Close()
		a.Close()
		k.Close()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("run detection engine: %w", err)
	}

	clientConn, serverConn := protocol.NewPipeTransport()
	server := protocol.NewServer(serverConn, engine, serverKey, profile)

	e := &Environment{
		Profile:  profile,
		Oracle:   NewOracle(l, k, a),
		Priv:     newPrivilegedAccess(ledgerPath, auditPath, keystorePath),
		dir:      dir,
		ledger:   l,
		keystore: k,
		audit:    a,
		cancel:   cancel,
		ctx:      ctx,
		svc:      svc,
		engine:   engine,
	}

	// Tracked via e.trackGoroutine like NewClientConnection's server
	// goroutine below: without this, Close's execWG.Wait() returned
	// immediately while this Environment's own server goroutine was
	// still live, so Close could tear down the stores while a dispatch
	// was still in flight (security review finding M3).
	done := e.trackGoroutine()
	go func() {
		defer done()
		server.Serve(ctx, svc)
	}()
	e.Client = protocol.NewClient(clientConn, engine, clientKey, profile)

	return e, nil
}

// GenerateTestKey generates a fresh key directly in this Environment's
// keystore and returns both its metadata and plaintext material. This
// is a test/scenario-fixture helper, not an attack primitive: nothing in
// production (cmd/banksec, internal/backend, internal/protocol) actually
// calls keystore.Store.Generate yet (a known architecture gap, ledgered
// since Milestone 5), so there is no protocol-level operation a
// Scenario's Exec could use to legitimately create a test key the way
// every other scenario creates its fixtures (accounts, deposits) through
// env.Client. Returning the plaintext material here is safe precisely
// because this is fixture setup, not the attack being measured -- the
// attack scenarios that use this (Milestone 8's key-management group)
// separately read the key back through env.Priv.RawKeyBytes, which is
// the actual thing being tested.
func (e *Environment) GenerateTestKey(ctx context.Context, profile domain.CryptoProfileName) (keystore.KeyMeta, []byte, error) {
	meta, err := e.keystore.Generate(ctx, profile)
	if err != nil {
		return keystore.KeyMeta{}, nil, fmt.Errorf("generate test key: %w", err)
	}
	material, _, err := e.keystore.Get(ctx, meta.ID)
	if err != nil {
		return keystore.KeyMeta{}, nil, fmt.Errorf("read back generated test key: %w", err)
	}
	return meta, material, nil
}

// RevokeTestKey revokes a key by ID directly in this Environment's
// keystore. Another fixture helper, for the same reason GenerateTestKey
// is one -- see its doc comment.
func (e *Environment) RevokeTestKey(ctx context.Context, id string) error {
	return e.keystore.Revoke(ctx, id)
}

// GetTestKey reads a key's material and metadata through
// keystore.Store.Get -- the *normal*, intended access path a real
// consumer would use (as opposed to env.Priv.RawKeyBytes, the insider
// bypass this task's key-exposure scenario targets). Used by the
// key-revocation scenario to confirm Get actually rejects a revoked key
// for "new operations", per ATTACK_SURFACES.md §4.
func (e *Environment) GetTestKey(ctx context.Context, id string) ([]byte, keystore.KeyMeta, error) {
	return e.keystore.Get(ctx, id)
}

// NewClientConnection wires an additional protocol client/server pair
// against this Environment's SAME backend.Service, over its own
// in-memory pipe. A single Client serializes its own Send/SendRawFrame
// calls (one full round trip at a time), and the protocol Server
// processes one connection's frames strictly sequentially -- so
// reaching genuinely concurrent requests into the backend (e.g. the
// concurrent-overdraft race, ATTACK_SURFACES.md §1) requires separate
// connections, not more goroutines calling one Client.
func (e *Environment) NewClientConnection() (protocol.AttackClient, error) {
	clientKey, serverKey, err := localAuthKeys(e.Profile.CryptoProfile)
	if err != nil {
		return nil, fmt.Errorf("generate protocol auth keys: %w", err)
	}
	clientConn, serverConn := protocol.NewPipeTransport()
	server := protocol.NewServer(serverConn, e.engine, serverKey, e.Profile)
	done := e.trackGoroutine()
	go func() {
		defer done()
		server.Serve(e.ctx, e.svc)
	}()
	client := protocol.NewClient(clientConn, e.engine, clientKey, e.Profile)
	ac, ok := client.(protocol.AttackClient)
	if !ok {
		return nil, fmt.Errorf("internal error: protocol.NewClient's result does not satisfy protocol.AttackClient")
	}
	return ac, nil
}

// Close releases every resource this Environment holds and removes its
// temp directory. If a Scenario's Exec or Verify ignored its own ctx and
// is still running in the background (see runner.go's goroutine-raced
// deadline enforcement), Close gives it up to 2 seconds to finish before
// proceeding anyway -- waiting unboundedly for code that may never
// return would make Close itself hang, which is worse than the
// documented risk of a still-running goroutine touching a store after
// Close has started tearing it down.
func (e *Environment) Close() error {
	e.cancel()

	waited := make(chan struct{})
	go func() {
		e.execWG.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
	}

	e.ledger.Close()
	e.keystore.Close()
	e.audit.Close()
	return os.RemoveAll(e.dir)
}

// localAuthKeys mirrors cmd/banksec/cli.go's protocolAuthKeys. Not
// importable from here: cmd/banksec depends on internal/harness's
// sibling packages, not the other way around, so the two small
// functions are kept separately rather than introducing a dependency
// in the wrong direction for ~15 lines of key generation.
func localAuthKeys(profile domain.CryptoProfileName) (clientKey, serverKey []byte, err error) {
	if profile == "pqc" {
		sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
		if err != nil {
			return nil, nil, fmt.Errorf("generate ML-DSA keypair: %w", err)
		}
		return sk.Bytes(), sk.PublicKey().Bytes(), nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, fmt.Errorf("generate symmetric key: %w", err)
	}
	return key, key, nil
}
