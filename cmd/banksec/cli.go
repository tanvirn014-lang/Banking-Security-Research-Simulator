package main

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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

// protocolAuthKeys generates the client/server key material appropriate
// for profile: a shared symmetric key for "standard"/"weak-educational"
// (both sides use the same bytes), or a fresh ML-DSA keypair for "pqc"
// (the client gets the private seed, the server gets the public key --
// see protocol.NewClient's doc comment for why these differ).
func protocolAuthKeys(profile domain.CryptoProfileName) (clientKey, serverKey []byte, err error) {
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

// cliEnv names where a CLI invocation's persistent storage and security
// profile live. Separate test runs use their own, isolated DataDir.
type cliEnv struct {
	DataDir     string
	ProfilePath string
}

// runCLI wires a full client-to-backend-to-vault stack for one command and
// sends it, printing "key=value" lines for the response's Data on success.
func runCLI(env cliEnv, args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: banksec <command> [flags]")
	}
	op := args[0]

	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	owner := fs.String("owner", "", "account owner principal ID")
	account := fs.String("account", "", "account ID")
	from := fs.String("from", "", "source account ID")
	to := fs.String("to", "", "destination account ID")
	amount := fs.String("amount", "", "amount in minor units")
	as := fs.String("as", "", "acting principal ID")
	if err := fs.Parse(args[1:]); err != nil {
		return "", fmt.Errorf("parse flags for %s: %w", op, err)
	}

	params, err := paramsForOp(op, *owner, *account, *from, *to, *amount)
	if err != nil {
		return "", err
	}

	client, cleanup, err := wireClient(env)
	if err != nil {
		return "", fmt.Errorf("wire backend: %w", err)
	}
	defer cleanup()

	resp, err := client.Send(context.Background(), protocol.Request{
		Op:     op,
		Actor:  domain.Principal{ID: domain.PrincipalID(*as), Role: domain.RoleAccountOwner},
		Params: params,
	})
	if err != nil {
		return "", fmt.Errorf("send request: %w", err)
	}
	if !resp.OK {
		return "", fmt.Errorf("%s", resp.Error)
	}

	var out strings.Builder
	for k, v := range resp.Data {
		fmt.Fprintf(&out, "%s=%s\n", k, v)
	}
	return out.String(), nil
}

func paramsForOp(op, owner, account, from, to, amount string) (map[string]string, error) {
	switch op {
	case "create-account":
		return map[string]string{"owner": owner}, nil
	case "deposit", "withdraw":
		return map[string]string{"account": account, "amount": amount}, nil
	case "transfer":
		return map[string]string{"from": from, "to": to, "amount": amount}, nil
	case "balance", "history":
		return map[string]string{"account": account}, nil
	default:
		return nil, fmt.Errorf("unknown command: %s", op)
	}
}

// wireClient wires config/ledger/keystore/audit/backend/protocol per
// ARCHITECTURE.md's order and returns a Client plus a cleanup function.
// The loaded SecurityProfile is not yet threaded into backend/protocol
// construction.
func wireClient(env cliEnv) (protocol.Client, func(), error) {
	profile, err := config.Load(env.ProfilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("load profile: %w", err)
	}

	if err := os.MkdirAll(env.DataDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create data dir %s: %w", env.DataDir, err)
	}

	l, err := ledger.NewSQLiteStore(filepath.Join(env.DataDir, "ledger.db"))
	if err != nil {
		return nil, nil, fmt.Errorf("open ledger: %w", err)
	}
	a, err := audit.NewSQLiteStream(filepath.Join(env.DataDir, "audit.db"), profile.AuditHashChained)
	if err != nil {
		l.Close()
		return nil, nil, fmt.Errorf("open audit stream: %w", err)
	}
	engine := crypto.NewEngine()
	k, err := keystore.NewSQLiteStore(filepath.Join(env.DataDir, "keystore.db"), engine, profile.KeystoreEncryptedAtRest, a)
	if err != nil {
		l.Close()
		a.Close()
		return nil, nil, fmt.Errorf("open keystore: %w", err)
	}

	svc := backend.NewService(l, k, a, profile)

	// Fresh per-invocation key material is enough: the client and server
	// above are both constructed right here, in the same process, and
	// never need to agree on a key across separate invocations.
	clientKey, serverKey, err := protocolAuthKeys(profile.CryptoProfile)
	if err != nil {
		l.Close()
		k.Close()
		a.Close()
		return nil, nil, fmt.Errorf("generate protocol auth keys: %w", err)
	}

	// A typo'd or unknown rule ID in profile.DetectionRules must fail
	// loudly here, not silently result in zero rules actually running
	// while the profile still claims e.g. "hardened" (security review
	// finding I6).
	knownDetectionRules := []domain.DetectionRuleID{detection.BalanceInvariantRuleID}
	if err := detection.ValidateDetectionRules(profile.DetectionRules, knownDetectionRules); err != nil {
		l.Close()
		k.Close()
		a.Close()
		return nil, nil, fmt.Errorf("profile detection_rules: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Wired as a background goroutine alongside the protocol server
	// below (Milestone 6, Task 29, Review Focus #5): the Detection
	// Engine must run as part of normal operation, not only be callable
	// directly from a test.
	detectionEngine := detection.NewEngine()
	detection.RegisterConfigured(detectionEngine, detection.NewBalanceInvariantRule(l), profile.DetectionRules)
	if err := detectionEngine.Run(ctx, a); err != nil {
		cancel()
		l.Close()
		k.Close()
		a.Close()
		return nil, nil, fmt.Errorf("run detection engine: %w", err)
	}

	clientConn, serverConn := protocol.NewPipeTransport()
	server := protocol.NewServer(serverConn, engine, serverKey, profile)
	go server.Serve(ctx, svc)

	client := protocol.NewClient(clientConn, engine, clientKey, profile)

	cleanup := func() {
		cancel()
		l.Close()
		k.Close()
		a.Close()
	}
	return client, cleanup, nil
}
