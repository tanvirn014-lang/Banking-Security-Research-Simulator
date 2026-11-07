package harness

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"sync/atomic"

	"banksec-lab/internal/domain"
	"banksec-lab/internal/protocol"
)

// ConcurrentOverdraftScenarioID identifies the concurrent-overdraft race
// scenario (ATTACK_SURFACES.md §1).
const ConcurrentOverdraftScenarioID = "application-concurrent-overdraft"

// NewConcurrentOverdraftScenario returns a Scenario that funds one
// account and fires concurrentTransfers simultaneous transfer requests
// against it, each over its own protocol connection (a single
// protocol.Client serializes its own Send calls, so real concurrency at
// the backend needs separate connections -- see
// Environment.NewClientConnection). Success (from the attacker's
// perspective) is the account ending up overdrawn: a correctly
// serialized/locked backend should never let that happen regardless of
// how many requests race, since each would see the post-previous-
// transfer balance.
func NewConcurrentOverdraftScenario() Scenario {
	const startBalance = domain.Money(1000)
	const transferAmount = domain.Money(100)
	const concurrentTransfers = 20
	// sustainableTransfers is the most transfers of transferAmount that
	// startBalance could ever fund without going negative, however they
	// are ordered/interleaved -- any successful transfer beyond this is
	// money that should not exist.
	const sustainableTransfers = int64(startBalance / transferAmount)

	var acctA, acctB domain.AccountID
	var successfulTransfers int64 // atomic

	return Scenario{
		ID:              ConcurrentOverdraftScenarioID,
		Category:        "application",
		TargetComponent: "backend",
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
			owner := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}

			createA, err := env.Client.Send(ctx, protocol.Request{Op: "create-account", Actor: owner, Params: map[string]string{"owner": "owner-1"}})
			if err != nil || !createA.OK {
				return fmt.Errorf("create-account A: resp=%+v err=%v", createA, err)
			}
			acctA = domain.AccountID(createA.Data["account"])

			createB, err := env.Client.Send(ctx, protocol.Request{Op: "create-account", Actor: owner, Params: map[string]string{"owner": "owner-1"}})
			if err != nil || !createB.OK {
				return fmt.Errorf("create-account B: resp=%+v err=%v", createB, err)
			}
			acctB = domain.AccountID(createB.Data["account"])

			depositResp, err := env.Client.Send(ctx, protocol.Request{
				Op:     "deposit",
				Actor:  owner,
				Params: map[string]string{"account": string(acctA), "amount": strconv.FormatInt(int64(startBalance), 10)},
			})
			if err != nil || !depositResp.OK {
				return fmt.Errorf("deposit: resp=%+v err=%v", depositResp, err)
			}

			atomic.StoreInt64(&successfulTransfers, 0)
			var wg sync.WaitGroup
			for i := 0; i < concurrentTransfers; i++ {
				conn, err := env.NewClientConnection()
				if err != nil {
					return fmt.Errorf("new client connection %d: %w", i, err)
				}
				wg.Add(1)
				go func(c protocol.AttackClient) {
					defer wg.Done()
					resp, err := c.Send(ctx, protocol.Request{
						Op:     "transfer",
						Actor:  owner,
						Params: map[string]string{"from": string(acctA), "to": string(acctB), "amount": strconv.FormatInt(int64(transferAmount), 10)},
					})
					if err == nil && resp.OK {
						atomic.AddInt64(&successfulTransfers, 1)
					}
				}(conn)
			}
			wg.Wait()
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			state, err := o.LedgerSnapshot(ctx)
			if err != nil {
				return false, nil, err
			}
			var balA domain.Money
			for _, e := range state.Entries {
				if e.AccountID == acctA {
					balA += e.Amount
				}
			}
			if balA >= 0 {
				return false, nil, nil
			}
			compromised := atomic.LoadInt64(&successfulTransfers) - sustainableTransfers
			if compromised < 0 {
				compromised = 0
			}
			return true, Evidence{EvidenceRecordsCompromised: compromised}, nil
		},
	}
}

// AuthzBypassScenarioID identifies the authorization-bypass scenario
// (ATTACK_SURFACES.md §1's authorization-bypass variant).
const AuthzBypassScenarioID = "application-authz-bypass"

// NewAuthzBypassScenario returns a Scenario where a principal with no
// claim on an account issues a transfer from it. Success (from the
// attacker's perspective) is funds actually moving to the
// attacker-controlled destination account.
func NewAuthzBypassScenario() Scenario {
	const amount = domain.Money(100)

	var acctA, acctB domain.AccountID

	return Scenario{
		ID:              AuthzBypassScenarioID,
		Category:        "application",
		TargetComponent: "backend",
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
			ownerA := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}
			ownerB := domain.Principal{ID: "owner-2", Role: domain.RoleAccountOwner}

			createA, err := env.Client.Send(ctx, protocol.Request{Op: "create-account", Actor: ownerA, Params: map[string]string{"owner": "owner-1"}})
			if err != nil || !createA.OK {
				return fmt.Errorf("create-account A: resp=%+v err=%v", createA, err)
			}
			acctA = domain.AccountID(createA.Data["account"])

			createB, err := env.Client.Send(ctx, protocol.Request{Op: "create-account", Actor: ownerB, Params: map[string]string{"owner": "owner-2"}})
			if err != nil || !createB.OK {
				return fmt.Errorf("create-account B: resp=%+v err=%v", createB, err)
			}
			acctB = domain.AccountID(createB.Data["account"])

			depositResp, err := env.Client.Send(ctx, protocol.Request{
				Op:     "deposit",
				Actor:  ownerA,
				Params: map[string]string{"account": string(acctA), "amount": strconv.FormatInt(int64(1000), 10)},
			})
			if err != nil || !depositResp.OK {
				return fmt.Errorf("deposit: resp=%+v err=%v", depositResp, err)
			}

			// The forged step: ownerB has no claim over acctA. A non-nil
			// error here (the expected hardened-mode outcome) is not
			// itself a failure of Exec -- only Verify, via the Oracle,
			// decides Success.
			env.Client.Send(ctx, protocol.Request{
				Op:     "transfer",
				Actor:  ownerB,
				Params: map[string]string{"from": string(acctA), "to": string(acctB), "amount": strconv.FormatInt(int64(amount), 10)},
			})
			return nil
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			state, err := o.LedgerSnapshot(ctx)
			if err != nil {
				return false, nil, err
			}
			var balB domain.Money
			for _, e := range state.Entries {
				if e.AccountID == acctB {
					balB += e.Amount
				}
			}
			return balB > 0, Evidence{EvidenceRecordsCompromised: int64(balB)}, nil
		},
	}
}
