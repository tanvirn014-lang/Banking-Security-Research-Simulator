package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/backend"
	"banksec-lab/internal/config"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/keystore"
	"banksec-lab/internal/ledger"
	"banksec-lab/internal/protocol"
)

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
// construction -- Milestone 3 does that; loading it here now still
// validates the profile file eagerly and matches the documented wiring
// order.
func wireClient(env cliEnv) (protocol.Client, func(), error) {
	if _, err := config.Load(env.ProfilePath); err != nil {
		return nil, nil, fmt.Errorf("load profile: %w", err)
	}

	if err := os.MkdirAll(env.DataDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create data dir %s: %w", env.DataDir, err)
	}

	l, err := ledger.NewSQLiteStore(filepath.Join(env.DataDir, "ledger.db"))
	if err != nil {
		return nil, nil, fmt.Errorf("open ledger: %w", err)
	}
	k, err := keystore.NewSQLiteStore(filepath.Join(env.DataDir, "keystore.db"))
	if err != nil {
		l.Close()
		return nil, nil, fmt.Errorf("open keystore: %w", err)
	}
	a, err := audit.NewSQLiteStream(filepath.Join(env.DataDir, "audit.db"))
	if err != nil {
		l.Close()
		k.Close()
		return nil, nil, fmt.Errorf("open audit stream: %w", err)
	}

	svc := backend.NewService(l, k, a)

	clientConn, serverConn := protocol.NewPipeTransport()
	server := protocol.NewServer(serverConn)
	ctx, cancel := context.WithCancel(context.Background())
	go server.Serve(ctx, svc)

	client := protocol.NewClient(clientConn)

	cleanup := func() {
		cancel()
		l.Close()
		k.Close()
		a.Close()
	}
	return client, cleanup, nil
}
