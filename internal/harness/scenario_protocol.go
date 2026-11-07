package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"

	"banksec-lab/internal/domain"
	"banksec-lab/internal/protocol"
)

// All three protocol-level scenarios (ATTACK_SURFACES.md §2) use
// "deposit" as their target operation, not "create-account": a deposit
// lands in ledger entries, so its real-world effect (did the money
// actually get added, and how many times) is observable via
// Oracle.LedgerSnapshot -- a Response's own OK field is not
// authenticated at all (see protocol/client.go's doc comment) and would
// not be "verifying via the Oracle".

// ReplayScenarioID identifies the protocol replay scenario.
const ReplayScenarioID = "protocol-replay"

// NewReplayScenario sends one legitimate deposit, captures the frame it
// produced, and resends that identical frame (same sequence number, same
// auth tag). Success (from the attacker's perspective) is the deposit
// landing twice -- the account's balance doubling, not just once.
func NewReplayScenario() Scenario {
	const depositAmount = domain.Money(500)
	var acct domain.AccountID

	return Scenario{
		ID:              ReplayScenarioID,
		Category:        "protocol",
		TargetComponent: "protocol",
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
			ac, ok := env.Client.(protocol.AttackClient)
			if !ok {
				return fmt.Errorf("environment's Client does not support raw frame access (protocol.AttackClient)")
			}
			owner := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}

			createResp, err := ac.Send(ctx, protocol.Request{Op: "create-account", Actor: owner, Params: map[string]string{"owner": "owner-1"}})
			if err != nil || !createResp.OK {
				return fmt.Errorf("create-account: resp=%+v err=%v", createResp, err)
			}
			acct = domain.AccountID(createResp.Data["account"])

			depositResp, err := ac.Send(ctx, protocol.Request{
				Op:     "deposit",
				Actor:  owner,
				Params: map[string]string{"account": string(acct), "amount": strconv.FormatInt(int64(depositAmount), 10)},
			})
			if err != nil || !depositResp.OK {
				return fmt.Errorf("initial deposit: resp=%+v err=%v", depositResp, err)
			}

			frame, ok := ac.LastSentFrame()
			if !ok {
				return fmt.Errorf("expected a captured frame after the deposit Send")
			}

			// The replay: resend the identical frame, unmodified.
			ac.SendRawFrame(ctx, frame)
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			state, err := o.LedgerSnapshot(ctx)
			if err != nil {
				return false, nil, err
			}
			var bal domain.Money
			for _, e := range state.Entries {
				if e.AccountID == acct {
					bal += e.Amount
				}
			}
			if bal <= depositAmount {
				return false, nil, nil
			}
			return true, Evidence{EvidenceRecordsCompromised: int64(bal - depositAmount)}, nil
		},
	}
}

// TamperScenarioID identifies the protocol tamper scenario.
const TamperScenarioID = "protocol-tamper"

// NewTamperScenario sends one legitimate deposit, captures the frame,
// mutates its declared amount without recomputing the auth tag, and
// resends it. Success is the tampered (larger) amount landing in the
// ledger instead of the originally-authenticated one.
func NewTamperScenario() Scenario {
	const legitAmount = domain.Money(100)
	const tamperedAmount = domain.Money(100000)
	var acct domain.AccountID

	return Scenario{
		ID:              TamperScenarioID,
		Category:        "protocol",
		TargetComponent: "protocol",
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
			ac, ok := env.Client.(protocol.AttackClient)
			if !ok {
				return fmt.Errorf("environment's Client does not support raw frame access (protocol.AttackClient)")
			}
			owner := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}

			createResp, err := ac.Send(ctx, protocol.Request{Op: "create-account", Actor: owner, Params: map[string]string{"owner": "owner-1"}})
			if err != nil || !createResp.OK {
				return fmt.Errorf("create-account: resp=%+v err=%v", createResp, err)
			}
			acct = domain.AccountID(createResp.Data["account"])

			depositResp, err := ac.Send(ctx, protocol.Request{
				Op:     "deposit",
				Actor:  owner,
				Params: map[string]string{"account": string(acct), "amount": strconv.FormatInt(int64(legitAmount), 10)},
			})
			if err != nil || !depositResp.OK {
				return fmt.Errorf("legitimate deposit: resp=%+v err=%v", depositResp, err)
			}

			frame, ok := ac.LastSentFrame()
			if !ok {
				return fmt.Errorf("expected a captured frame after the deposit Send")
			}

			tamperedReq := protocol.Request{
				Op:     "deposit",
				Actor:  owner,
				Params: map[string]string{"account": string(acct), "amount": strconv.FormatInt(int64(tamperedAmount), 10)},
			}
			payload, err := json.Marshal(tamperedReq)
			if err != nil {
				return fmt.Errorf("marshal tampered request: %w", err)
			}
			frame.Payload = payload // AuthTag is left as-is: computed for the ORIGINAL payload, now stale.

			ac.SendRawFrame(ctx, frame)
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			state, err := o.LedgerSnapshot(ctx)
			if err != nil {
				return false, nil, err
			}
			var bal domain.Money
			for _, e := range state.Entries {
				if e.AccountID == acct {
					bal += e.Amount
				}
			}
			if bal < tamperedAmount {
				return false, nil, nil
			}
			return true, Evidence{EvidenceRecordsCompromised: int64(bal - legitAmount)}, nil
		},
	}
}

// DowngradeScenarioID identifies the protocol downgrade scenario.
const DowngradeScenarioID = "protocol-downgrade"

// NewDowngradeScenario constructs a validly-authenticated deposit frame
// declaring the weak-educational profile (a weaker scheme than the
// server's own configured minimum) and sends it directly. Success is
// the deposit landing despite the declared downgrade.
func NewDowngradeScenario() Scenario {
	const amount = domain.Money(250)
	var acct domain.AccountID

	return Scenario{
		ID:              DowngradeScenarioID,
		Category:        "protocol",
		TargetComponent: "protocol",
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
			ac, ok := env.Client.(protocol.AttackClient)
			if !ok {
				return fmt.Errorf("environment's Client does not support raw frame access (protocol.AttackClient)")
			}
			owner := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}

			createResp, err := ac.Send(ctx, protocol.Request{Op: "create-account", Actor: owner, Params: map[string]string{"owner": "owner-1"}})
			if err != nil || !createResp.OK {
				return fmt.Errorf("create-account: resp=%+v err=%v", createResp, err)
			}
			acct = domain.AccountID(createResp.Data["account"])

			req := protocol.Request{
				Op:     "deposit",
				Actor:  owner,
				Params: map[string]string{"account": string(acct), "amount": strconv.FormatInt(int64(amount), 10)},
			}
			payload, err := json.Marshal(req)
			if err != nil {
				return fmt.Errorf("marshal request: %w", err)
			}
			frame, err := ac.BuildFrame(domain.CryptoProfileName("weak-educational"), payload)
			if err != nil {
				return fmt.Errorf("build downgraded frame: %w", err)
			}

			ac.SendRawFrame(ctx, frame)
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			state, err := o.LedgerSnapshot(ctx)
			if err != nil {
				return false, nil, err
			}
			var bal domain.Money
			for _, e := range state.Entries {
				if e.AccountID == acct {
					bal += e.Amount
				}
			}
			if bal <= 0 {
				return false, nil, nil
			}
			return true, Evidence{EvidenceRecordsCompromised: int64(bal)}, nil
		},
	}
}
