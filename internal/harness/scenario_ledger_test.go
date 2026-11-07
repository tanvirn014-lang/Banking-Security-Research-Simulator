package harness

import (
	"context"
	"fmt"
	"testing"
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/detection"
	"banksec-lab/internal/protocol"
)

func runLedgerScenarioBothProfiles(t *testing.T, newScenario func() Scenario) {
	t.Helper()
	cases := []struct {
		name        string
		configPath  string
		wantSuccess bool // success = tamper went undetected
	}{
		{"hardened", "../../configs/hardened.json", false},
		{"vulnerable", "../../configs/vulnerable.json", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnvironment(t, tc.configPath)
			r := NewRunner()
			s := newScenario()

			result, err := r.Run(context.Background(), s, env, 1)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if result.Success != tc.wantSuccess {
				t.Fatalf("profile %q: expected Success=%v, got %v (result=%+v)", tc.name, tc.wantSuccess, result.Success, result)
			}
			if !tc.wantSuccess && result.DetectionLatencyMS == nil {
				t.Fatalf("expected DetectionLatencyMS to be populated when the tamper was detected, got nil")
			}
		})
	}
}

func TestScenario_LedgerTamper_DetectedHardened_UndetectedVulnerable(t *testing.T) {
	runLedgerScenarioBothProfiles(t, NewLedgerTamperScenario)
}

func TestScenario_AuditTamper_DetectedHardened_UndetectedVulnerable(t *testing.T) {
	runLedgerScenarioBothProfiles(t, NewAuditTamperScenario)
}

// alwaysErrClient is a protocol.Client stub whose Send always fails --
// used to simulate Exec failing before it ever reaches the raw
// PrivilegedAccess write, for the I3 regression tests below.
type alwaysErrClient struct{}

func (alwaysErrClient) Send(ctx context.Context, req protocol.Request) (protocol.Response, error) {
	return protocol.Response{}, fmt.Errorf("simulated client failure")
}

// TestScenario_LedgerTamper_ExecFailure_ReturnsErrorNotSuccess and
// TestScenario_AuditTamper_ExecFailure_ReturnsErrorNotSuccess are the
// regression tests for security review finding I3: both Verifys
// previously reported Success=true ("undetected") whenever Exec failed
// before ever reaching the raw write -- indistinguishable from a
// genuinely successful, undetected attack, when nothing was actually
// attacked at all.
func TestScenario_LedgerTamper_ExecFailure_ReturnsErrorNotSuccess(t *testing.T) {
	env := newTestEnvironment(t, "../../configs/hardened.json")
	env.Client = alwaysErrClient{}
	r := NewRunner()

	if _, err := r.Run(context.Background(), NewLedgerTamperScenario(), env, 1); err == nil {
		t.Fatalf("expected Run to report an error when Exec never reached the raw ledger write, got nil")
	}
}

func TestScenario_AuditTamper_ExecFailure_ReturnsErrorNotSuccess(t *testing.T) {
	env := newTestEnvironment(t, "../../configs/hardened.json")
	env.Client = alwaysErrClient{}
	r := NewRunner()

	if _, err := r.Run(context.Background(), NewAuditTamperScenario(), env, 1); err == nil {
		t.Fatalf("expected Run to report an error when Exec never reached the raw audit write, got nil")
	}
}

// TestDetectedBy_IgnoresUnrelatedRuleAndStaleEvents is the regression
// test for security review finding I4: both tamper scenarios' Verify
// previously counted *any* Type=="detection" event in a 1-second
// lookback window as "its own" detection, regardless of which rule
// produced it or whether it predated the tamper. detectedBy must match
// only the named rule's own events, timestamped at or after since.
func TestDetectedBy_IgnoresUnrelatedRuleAndStaleEvents(t *testing.T) {
	since := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	staleButRightRule := audit.Event{
		Type: "detection", Operation: string(detection.BalanceInvariantRuleID) + ": ledger invariant violated",
		Timestamp: since.Add(-time.Second), // before `since`: too old
	}
	rightTimeWrongRule := audit.Event{
		Type: "detection", Operation: string(detection.AuditChainRuleID) + ": audit hash chain broken",
		Timestamp: since.Add(time.Second), // after `since`, but the WRONG rule
	}
	theOneThatMatches := audit.Event{
		Type: "detection", Operation: string(detection.BalanceInvariantRuleID) + ": ledger invariant violated, offending tx(s): [tx1]",
		Timestamp: since.Add(2 * time.Second),
	}

	events := []audit.Event{staleButRightRule, rightTimeWrongRule, theOneThatMatches}

	got := detectedBy(events, detection.BalanceInvariantRuleID, since)
	if got == nil {
		t.Fatalf("expected to find the one matching event (right rule, not stale)")
	}
	if got.Timestamp != theOneThatMatches.Timestamp {
		t.Fatalf("expected to match theOneThatMatches, got %+v", got)
	}

	if got := detectedBy(events, detection.AuditChainRuleID, since.Add(5*time.Second)); got != nil {
		t.Fatalf("expected no match for a rule/time combination nothing in events satisfies, got %+v", got)
	}
}
