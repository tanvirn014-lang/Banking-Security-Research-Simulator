// Package backend_test wires the full stack (ledger/keystore/audit/
// backend/protocol) to confirm the vulnerable/hardened differential holds
// simultaneously across all three security properties in one coherent
// run, not just in isolation per their own tasks' tests. It is an
// external test package (not package backend) because it needs
// internal/protocol, which itself imports internal/backend.
package backend_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"sync"
	"testing"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/backend"
	"banksec-lab/internal/config"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/keystore"
	"banksec-lab/internal/ledger"
	"banksec-lab/internal/protocol"
	"banksec-lab/internal/testsupport"
)

func e2eTestMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func e2ePrincipal(id string) domain.Principal {
	return domain.Principal{ID: domain.PrincipalID(id), Role: domain.RoleAccountOwner}
}

func TestSecurityMode_FullDifferential(t *testing.T) {
	cases := []struct {
		name                            string
		profile                         config.SecurityProfile
		wantCrossAccountTransferAllowed bool // authorization differential
		wantDowngradeAccepted           bool // protocol differential (representative of replay/tamper/downgrade,
		//                                      each independently and exhaustively tested at the frame level in
		//                                      internal/protocol/protocol_test.go)
		wantOverdraftPossible bool // concurrency differential
	}{
		{
			name: "hardened",
			profile: config.SecurityProfile{
				Name: "hardened", CryptoProfile: "standard", MinAcceptedCryptoProfile: "standard",
				ProtocolAuthEnforced: true, AuthzEnforced: true, AtomicityEnforced: true,
			},
			wantCrossAccountTransferAllowed: false,
			wantDowngradeAccepted:           false,
			wantOverdraftPossible:           false,
		},
		{
			name: "vulnerable",
			profile: config.SecurityProfile{
				Name: "vulnerable", CryptoProfile: "standard", MinAcceptedCryptoProfile: "standard",
				ProtocolAuthEnforced: false, AuthzEnforced: false, AtomicityEnforced: false,
			},
			wantCrossAccountTransferAllowed: true,
			wantDowngradeAccepted:           true,
			wantOverdraftPossible:           true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			l, err := ledger.NewSQLiteStore(testsupport.TempSQLitePath(t))
			if err != nil {
				t.Fatalf("ledger.NewSQLiteStore: %v", err)
			}
			t.Cleanup(func() { l.Close() })
			k, err := keystore.NewSQLiteStore(testsupport.TempSQLitePath(t))
			if err != nil {
				t.Fatalf("keystore.NewSQLiteStore: %v", err)
			}
			t.Cleanup(func() { k.Close() })
			a, err := audit.NewSQLiteStream(testsupport.TempSQLitePath(t))
			if err != nil {
				t.Fatalf("audit.NewSQLiteStream: %v", err)
			}
			t.Cleanup(func() { a.Close() })

			svc := backend.NewService(l, k, a, tc.profile)

			// --- 1. Authorization differential ---
			acctA, err := svc.CreateAccount(ctx, "owner-1")
			if err != nil {
				t.Fatalf("CreateAccount A: %v", err)
			}
			acctB, err := svc.CreateAccount(ctx, "owner-2")
			if err != nil {
				t.Fatalf("CreateAccount B: %v", err)
			}
			if err := svc.Deposit(ctx, e2ePrincipal("owner-1"), acctA, 1000); err != nil {
				t.Fatalf("Deposit: %v", err)
			}
			transferErr := svc.Transfer(ctx, e2ePrincipal("owner-2"), acctA, acctB, 100)
			gotCrossAccountAllowed := transferErr == nil
			if gotCrossAccountAllowed != tc.wantCrossAccountTransferAllowed {
				t.Errorf("authz: cross-account transfer allowed=%v, want %v (err=%v)",
					gotCrossAccountAllowed, tc.wantCrossAccountTransferAllowed, transferErr)
			}

			// --- 2. Protocol-layer differential (crypto-profile downgrade) ---
			macKey := []byte("e2e-test-mac-key")
			clientConn, serverConn := protocol.NewPipeTransport()
			server := protocol.NewServer(serverConn, e2eTestMAC, macKey, tc.profile)
			pctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go server.Serve(pctx, svc)

			// A client declaring a profile weaker than the server's
			// configured minimum -- the downgrade surface.
			weakClientProfile := tc.profile
			weakClientProfile.CryptoProfile = "weak-educational"
			client := protocol.NewClient(clientConn, e2eTestMAC, macKey, weakClientProfile)

			resp, err := client.Send(ctx, protocol.Request{Op: "create-account", Params: map[string]string{"owner": "owner-3"}})
			if err != nil {
				t.Fatalf("Send: %v", err)
			}
			if resp.OK != tc.wantDowngradeAccepted {
				t.Errorf("downgrade: accepted=%v, want %v (resp=%+v)", resp.OK, tc.wantDowngradeAccepted, resp)
			}

			// --- 3. Concurrency differential ---
			acctC, err := svc.CreateAccount(ctx, "owner-1")
			if err != nil {
				t.Fatalf("CreateAccount C: %v", err)
			}
			if err := svc.Deposit(ctx, e2ePrincipal("owner-1"), acctC, 1000); err != nil {
				t.Fatalf("Deposit C: %v", err)
			}
			const n = 20
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = svc.Transfer(ctx, e2ePrincipal("owner-1"), acctC, acctB, 100)
				}()
			}
			wg.Wait()

			bal, err := svc.Balance(ctx, e2ePrincipal("owner-1"), acctC)
			if err != nil {
				t.Fatalf("Balance: %v", err)
			}
			gotOverdraftOccurred := bal < 0
			if gotOverdraftOccurred != tc.wantOverdraftPossible {
				t.Errorf("concurrency: overdraft occurred=%v, want %v (balance=%d)",
					gotOverdraftOccurred, tc.wantOverdraftPossible, bal)
			}
		})
	}
}
