package harness

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"banksec-lab/internal/domain"
	"banksec-lab/internal/ledger"
	"banksec-lab/internal/protocol"
)

// This file holds exactly two small, real demonstration Scenarios,
// proving the framework built in this milestone actually works
// end-to-end -- per the user's explicit instruction not to build out
// Milestone 8's full attack catalog in this task. They are deliberately
// not registered under scenario_application.go/scenario_ledger.go
// (Milestone 8's Tasks 34/36 own those files and the full scenario
// sets).

// TestDemo_ForgedTransfer_SucceedsVulnerable_FailsHardened: an
// application-level demonstration, the same shape as cmd/banksec's
// existing TestCLI_ForgedPrincipalStillRejectedServerSide, driven
// entirely through protocol.Client (the one real external entrypoint).
func TestDemo_ForgedTransfer_SucceedsVulnerable_FailsHardened(t *testing.T) {
	cases := []struct {
		name        string
		configPath  string
		wantSuccess bool
	}{
		{"hardened", "../../configs/hardened.json", false},
		{"vulnerable", "../../configs/vulnerable.json", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnvironment(t, tc.configPath)
			r := NewRunner()

			var acctB string
			s := Scenario{
				ID:              "demo-forged-transfer",
				Category:        "application",
				TargetComponent: "backend",
				Exec: func(ctx context.Context, client protocol.Client, priv PrivilegedAccess, rnd *rand.Rand) error {
					ownerA := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}
					ownerB := domain.Principal{ID: "owner-2", Role: domain.RoleAccountOwner}

					createA, err := client.Send(ctx, protocol.Request{Op: "create-account", Actor: ownerA, Params: map[string]string{"owner": "owner-1"}})
					if err != nil || !createA.OK {
						return fmt.Errorf("create-account A: resp=%+v err=%v", createA, err)
					}
					acctA := createA.Data["account"]

					createB, err := client.Send(ctx, protocol.Request{Op: "create-account", Actor: ownerB, Params: map[string]string{"owner": "owner-2"}})
					if err != nil || !createB.OK {
						return fmt.Errorf("create-account B: resp=%+v err=%v", createB, err)
					}
					acctB = createB.Data["account"]

					if _, err := client.Send(ctx, protocol.Request{Op: "deposit", Actor: ownerA, Params: map[string]string{"account": acctA, "amount": "1000"}}); err != nil {
						return fmt.Errorf("deposit: %w", err)
					}

					// The forged step: owner-2 has no claim over acctA.
					// A non-nil error here (the expected hardened-mode
					// outcome) is not itself a failure of Exec -- only
					// Verify, via the Oracle, decides Success.
					client.Send(ctx, protocol.Request{Op: "transfer", Actor: ownerB, Params: map[string]string{"from": acctA, "to": acctB, "amount": "100"}})
					return nil
				},
				Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
					state, err := o.LedgerSnapshot(ctx)
					if err != nil {
						return false, nil, err
					}
					var acctBBalance domain.Money
					for _, e := range state.Entries {
						if e.AccountID == domain.AccountID(acctB) {
							acctBBalance += e.Amount
						}
					}
					return acctBBalance > 0, Evidence{EvidenceRecordsCompromised: int64(acctBBalance)}, nil
				},
			}

			result, err := r.Run(context.Background(), s, env, 1)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if result.Success != tc.wantSuccess {
				t.Fatalf("profile %q: expected Success=%v, got %v (result=%+v)", tc.name, tc.wantSuccess, result.Success, result)
			}
		})
	}
}

// TestDemo_LedgerTamper_DetectedHardened_UndetectedVulnerable: a
// ledger-level demonstration via PrivilegedAccess (the insider-style
// bypass), proving Oracle + the already-running Detection Engine work
// together. "Success" is from the attacker's perspective: the tamper
// broke the ledger invariant and went undetected.
func TestDemo_LedgerTamper_DetectedHardened_UndetectedVulnerable(t *testing.T) {
	cases := []struct {
		name        string
		configPath  string
		wantSuccess bool
	}{
		{"hardened", "../../configs/hardened.json", false},
		{"vulnerable", "../../configs/vulnerable.json", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnvironment(t, tc.configPath)
			r := NewRunner()

			var tamperedAt time.Time
			s := Scenario{
				ID:              "demo-ledger-tamper",
				Category:        "ledger",
				TargetComponent: "ledger",
				Exec: func(ctx context.Context, client protocol.Client, priv PrivilegedAccess, rnd *rand.Rand) error {
					owner := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}
					createResp, err := client.Send(ctx, protocol.Request{Op: "create-account", Actor: owner, Params: map[string]string{"owner": "owner-1"}})
					if err != nil || !createResp.OK {
						return fmt.Errorf("create-account: resp=%+v err=%v", createResp, err)
					}
					acct := createResp.Data["account"]

					// An unmatched entry -- a legitimate transaction
					// always has an offsetting entry; this bypasses
					// AppendTransaction's own balance check entirely.
					if err := priv.RawLedgerWrite(ctx, []ledger.Entry{
						{TxID: "insider-tx", AccountID: domain.AccountID(acct), Amount: 100000, Timestamp: time.Now()},
					}); err != nil {
						return err
					}
					tamperedAt = time.Now()

					// A follow-up backend operation: the Detection
					// Engine's balance-invariant rule triggers on every
					// "backend"-component event, per its own documented
					// choice (internal/detection/rules.go) -- the raw
					// write itself emits no audit event at all.
					_, err = client.Send(ctx, protocol.Request{Op: "balance", Actor: owner, Params: map[string]string{"account": acct}})
					return err
				},
				Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
					state, err := o.LedgerSnapshot(ctx)
					if err != nil {
						return false, nil, err
					}
					if state.InvariantOK {
						return false, nil, fmt.Errorf("test bug: the raw ledger write did not actually break the invariant")
					}

					events, err := o.AuditEventsSince(ctx, tamperedAt.Add(-time.Second))
					if err != nil {
						return false, nil, err
					}
					var detected bool
					evidence := Evidence{}
					for _, e := range events {
						if e.Type == "detection" {
							detected = true
							evidence[EvidenceDetectionLatencyMS] = e.Timestamp.Sub(tamperedAt).Milliseconds()
							break
						}
					}
					return !detected, evidence, nil
				},
			}

			result, err := r.Run(context.Background(), s, env, 1)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if result.Success != tc.wantSuccess {
				t.Fatalf("profile %q: expected Success=%v, got %v (result=%+v)", tc.name, tc.wantSuccess, result.Success, result)
			}
		})
	}
}
