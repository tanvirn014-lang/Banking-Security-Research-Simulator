package harness

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/detection"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/ledger"
	"banksec-lab/internal/protocol"
)

// detectedBy reports whether events contains a detection event
// attributable to ruleID (matching recordTrigger's own
// "<ruleID>: <detail>" Operation format -- internal/detection/engine.go),
// recorded at or after since. Matching by rule ID (not just
// Type=="detection") and requiring Timestamp>=since -- not a
// several-second lookback window -- avoids crediting a tamper scenario
// with a detection that actually belongs to a different rule, or to an
// unrelated break that predates this scenario's own tamper (security
// review finding I4).
func detectedBy(events []audit.Event, ruleID domain.DetectionRuleID, since time.Time) *audit.Event {
	prefix := string(ruleID) + ":"
	for i := range events {
		e := &events[i]
		if e.Type == "detection" && !e.Timestamp.Before(since) && strings.HasPrefix(e.Operation, prefix) {
			return e
		}
	}
	return nil
}

// LedgerTamperScenarioID identifies the ledger-tamper scenario.
const LedgerTamperScenarioID = "ledger-tamper"

// NewLedgerTamperScenario uses PrivilegedAccess.RawLedgerWrite to insert
// an unbalanced entry directly, bypassing backend/AppendTransaction's
// own balance check entirely (ATTACK_SURFACES.md §3's structural
// prerequisite: PrivilegedAccess simulates insider/compromised-host
// access, never a remote attacker). Success (from the attacker's
// perspective) is the tamper breaking the ledger invariant *and* going
// undetected by the Detection Engine within this run. This is the same
// mechanism Milestone 7's own representative demonstration
// (TestDemo_LedgerTamper_DetectedHardened_UndetectedVulnerable,
// demo_test.go) already proved works end-to-end; this is that mechanism
// as a real, registered Scenario rather than a one-off demo.
func NewLedgerTamperScenario() Scenario {
	var tamperedAt time.Time
	var tamperAttempted bool

	return Scenario{
		ID:              LedgerTamperScenarioID,
		Category:        "ledger",
		TargetComponent: "ledger",
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
			owner := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}
			createResp, err := env.Client.Send(ctx, protocol.Request{Op: "create-account", Actor: owner, Params: map[string]string{"owner": "owner-1"}})
			if err != nil || !createResp.OK {
				return fmt.Errorf("create-account: resp=%+v err=%v", createResp, err)
			}
			acct := createResp.Data["account"]

			// An unmatched entry -- a legitimate transaction always has an
			// offsetting entry; this bypasses AppendTransaction's own
			// balance check entirely.
			if err := env.Priv.RawLedgerWrite(ctx, []ledger.Entry{
				{TxID: "insider-ledger-tx", AccountID: domain.AccountID(acct), Amount: 100000, Timestamp: time.Now()},
			}); err != nil {
				return err
			}
			tamperedAt = time.Now()
			tamperAttempted = true

			// A follow-up backend operation: the Detection Engine's
			// balance-invariant rule triggers on every "backend"-component
			// event (internal/detection/rules.go) -- the raw write itself
			// emits no audit event at all.
			_, err = env.Client.Send(ctx, protocol.Request{Op: "balance", Actor: owner, Params: map[string]string{"account": acct}})
			return err
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			if !tamperAttempted {
				// Exec failed before ever reaching the raw write -- this is
				// an attack-infrastructure failure, not a (successful or
				// unsuccessful) attack. Reporting Success here either way
				// would misattribute the outcome (security review finding
				// I3).
				return false, nil, fmt.Errorf("exec did not reach the raw ledger write")
			}

			state, err := o.LedgerSnapshot(ctx)
			if err != nil {
				return false, nil, err
			}
			if state.InvariantOK {
				return false, nil, fmt.Errorf("the raw ledger write did not actually break the invariant")
			}

			events, err := o.AuditEventsSince(ctx, tamperedAt)
			if err != nil {
				return false, nil, err
			}
			evidence := Evidence{}
			detected := detectedBy(events, detection.BalanceInvariantRuleID, tamperedAt)
			if detected != nil {
				evidence[EvidenceDetectionLatencyMS] = detected.Timestamp.Sub(tamperedAt).Milliseconds()
			}
			return detected == nil, evidence, nil
		},
	}
}

// AuditTamperScenarioID identifies the audit-tamper scenario.
const AuditTamperScenarioID = "audit-tamper"

// NewAuditTamperScenario uses PrivilegedAccess.RawAuditWrite to insert a
// raw audit event directly, bypassing the audit package's hash-chaining
// logic entirely (RawAuditWrite always writes hash=NULL -- see
// privileged.go). Success is the tamper breaking the hash chain *and*
// going undetected within this run: in hardened mode, the Detection
// Engine's audit-chain-violation rule (added for this task -- see its
// doc comment) re-verifies the chain on the next event and flags the
// break; in vulnerable mode (hashChained=false), there is no chain to
// break in the first place, so nothing is ever flagged.
func NewAuditTamperScenario() Scenario {
	var tamperedAt time.Time
	var tamperAttempted bool

	return Scenario{
		ID:              AuditTamperScenarioID,
		Category:        "ledger",
		TargetComponent: "audit",
		Exec: func(ctx context.Context, env *Environment, rnd *rand.Rand) error {
			owner := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}
			createResp, err := env.Client.Send(ctx, protocol.Request{Op: "create-account", Actor: owner, Params: map[string]string{"owner": "owner-1"}})
			if err != nil || !createResp.OK {
				return fmt.Errorf("create-account: resp=%+v err=%v", createResp, err)
			}
			acct := createResp.Data["account"]

			if err := env.Priv.RawAuditWrite(ctx, audit.Event{
				ID:        "insider-audit-event",
				Timestamp: time.Now(),
				Type:      "op",
				Component: "insider",
				Operation: "tamper",
				Outcome:   "ok",
			}); err != nil {
				return err
			}
			tamperedAt = time.Now()
			tamperAttempted = true

			// A follow-up backend operation: the audit-chain-violation
			// rule re-verifies the chain on every non-detection event --
			// the raw write itself emits no legitimately-chained event.
			_, err = env.Client.Send(ctx, protocol.Request{Op: "balance", Actor: owner, Params: map[string]string{"account": acct}})
			return err
		},
		Verify: func(ctx context.Context, o Oracle) (bool, Evidence, error) {
			if !tamperAttempted {
				return false, nil, fmt.Errorf("exec did not reach the raw audit write")
			}

			events, err := o.AuditEventsSince(ctx, tamperedAt)
			if err != nil {
				return false, nil, err
			}
			evidence := Evidence{}
			detected := detectedBy(events, detection.AuditChainRuleID, tamperedAt)
			if detected != nil {
				evidence[EvidenceDetectionLatencyMS] = detected.Timestamp.Sub(tamperedAt).Milliseconds()
			}
			return detected == nil, evidence, nil
		},
	}
}
