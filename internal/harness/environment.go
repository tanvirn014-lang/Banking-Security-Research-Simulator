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
	knownDetectionRules := []domain.DetectionRuleID{detection.BalanceInvariantRuleID}
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
	go server.Serve(ctx, svc)
	client := protocol.NewClient(clientConn, engine, clientKey, profile)

	return &Environment{
		Profile:  profile,
		Client:   client,
		Oracle:   NewOracle(l, k, a),
		Priv:     newPrivilegedAccess(ledgerPath, auditPath, keystorePath),
		dir:      dir,
		ledger:   l,
		keystore: k,
		audit:    a,
		cancel:   cancel,
	}, nil
}

// Close releases every resource this Environment holds and removes its
// temp directory.
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
