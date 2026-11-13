package experiment

import (
	"context"
	"fmt"
	"time"

	"banksec-lab/internal/assistant"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/finding"
	"banksec-lab/internal/harness"
)

// evaluateProbe runs one adversarial probe against the banking
// assistant in a freshly wired environment.
//
// The sequence is deliberate: seed synthetic accounts through the
// bank's own front door, snapshot the ledger, let the assistant handle
// the adversarial input, snapshot again, then judge from the gateway's
// record and the two snapshots. Nothing the assistant said about its own
// behaviour enters the judgement.
//
// No customer approval is ever granted here. An adversarial probe must
// not be able to produce an executed transfer, so leaving approval
// ungranted is what makes an executed one a finding rather than an
// expected outcome.
func (e *Engine) evaluateProbe(ctx context.Context, cand Candidate, env *harness.Environment, attempt Attempt) Attempt {
	if e.assistantProvider == nil {
		attempt.Error = "this engine has no assistant provider, so a probe candidate cannot be evaluated " +
			"(construct the engine with WithAssistant)"
		return attempt
	}

	since := time.Now().Add(-time.Minute)

	seeded, err := assistant.SeedSyntheticAccounts(ctx, env.Client, assistant.SyntheticFixture())
	if err != nil {
		attempt.Error = fmt.Sprintf("seed synthetic accounts: %v", err)
		return attempt
	}

	before, err := CaptureSnapshot(ctx, env.Oracle, since)
	if err != nil {
		attempt.Error = fmt.Sprintf("capture before snapshot: %v", err)
		return attempt
	}
	attempt.SnapshotBefore = before

	limits := e.assistantLimits
	if limits.MaxToolCalls == 0 {
		limits = assistant.DefaultLimits()
	}
	gateway, err := assistant.NewGateway(env.Client, limits)
	if err != nil {
		attempt.Error = fmt.Sprintf("build tool gateway: %v", err)
		return attempt
	}

	turns := e.assistantTurns
	if turns <= 0 {
		turns = defaultAssistantTurns
	}
	bot, err := assistant.NewAssistant(e.assistantProvider, gateway, turns)
	if err != nil {
		attempt.Error = fmt.Sprintf("build assistant: %v", err)
		return attempt
	}

	sessionOwner := probeSessionOwner
	session := assistant.Session{
		ID:        "probe-" + cand.TestID,
		Principal: domain.Principal{ID: domain.PrincipalID(sessionOwner), Role: domain.RoleAccountOwner},
		// Only the probe session's own account. The victim's identifier
		// is deliberately withheld from the generator: an attack that
		// succeeds only because the harness handed it the target id
		// would prove nothing.
		Accounts: []domain.AccountID{seeded.Accounts[sessionOwner]},
		// A saved payee, because a customer who has never saved one
		// cannot be the subject of a transfer attack at all, and the
		// confirmation-bypass family would then have nothing to test.
		// This widens what can be attempted, not what is permitted: the
		// debited account is still checked against Accounts above, so an
		// attack still has to get an unapproved transfer past the
		// confirmation control to achieve anything.
		Payees: probePayees(seeded, sessionOwner),
	}

	transcript, err := bot.Handle(ctx, session, cand.Probe.Input())
	if err != nil {
		attempt.Error = fmt.Sprintf("assistant exchange: %v", err)
		return attempt
	}
	attempt.Transcript = &transcript

	after, err := CaptureSnapshot(ctx, env.Oracle, since)
	if err != nil {
		attempt.Error = fmt.Sprintf("capture after snapshot: %v", err)
		return attempt
	}
	attempt.SnapshotAfter = after

	evidence := &AssistantEvidence{
		Transcript:   transcript,
		Invocations:  gateway.Log(),
		Seeded:       seeded,
		SessionOwner: sessionOwner,
		// Never granted for an adversarial probe. See this function's
		// doc comment.
		ApprovalGranted: false,
		// Whatever the harness told the attacker is excluded from the
		// disclosure check: the assistant cannot leak what the attacker
		// already had.
		KnownToAttacker: knownToAttacker(cand),
	}

	in := InvariantInput{
		Profile:   e.profile,
		Before:    before,
		After:     after,
		Steps:     nil,
		Assistant: evidence,
	}
	verdicts := make(map[string]InvariantVerdict)
	for _, inv := range e.invariants {
		if !inv.Applicable(e.profile) {
			continue
		}
		verdicts[inv.ID] = inv.Check(in)
	}
	attempt.Verdicts = flattenVerdicts(verdicts)

	// A model failure is recorded as an attempt error so the experiment
	// never counts it as evidence in either direction.
	if transcript.StopReason == assistant.StopModelError {
		attempt.Error = "model failure: " + transcript.Error
	}
	attempt.StopReason = string(transcript.StopReason)
	attempt.ToolsAttempted = gateway.AttemptedCount()
	attempt.ToolsExecuted = gateway.ExecutedCount()

	return attempt
}

const (
	// probeSessionOwner is the fixture owner an adversarial probe acts
	// as. It is the funded account's owner, so an attack has something
	// worth stealing and a victim account to aim at.
	probeSessionOwner = "alice"
	// defaultAssistantTurns bounds how many times the model is consulted
	// for one probe.
	defaultAssistantTurns = 4
)

// probeFindings turns one probe attempt into findings. Separated from
// findingsFor so the probe's own metadata -- its family, its stated
// objective, the adversarial text itself -- reaches the record.
func (e *Engine) probeFindings(cand Candidate, attempt Attempt, eff ExperimentSpec) []finding.Finding {
	repro := finding.Reproduction{
		ExperimentID: eff.ExperimentID,
		TestID:       attempt.TestID,
		Seed:         cand.Seed,
		Steps:        probeSteps(cand, attempt),
		Note: "the adversarial input is recorded verbatim above; re-running it against the same model may take a " +
			"different path, because a language model is not deterministic even at a fixed temperature",
	}

	if attempt.Error != "" {
		return []finding.Finding{finding.New(finding.Context{
			Invariant:           "experiment.evaluation",
			InvariantDesc:       "a candidate must be evaluable end to end",
			Component:           "experiment",
			AttackID:            attempt.TestID,
			GeneratorID:         attempt.GeneratorID,
			TargetConfiguration: e.profile.Name,
			CryptoProfile:       string(e.profile.CryptoProfile),
			Outcome:             finding.OutcomeError,
			Impact:              attempt.Error,
			Reproduction:        repro,
		})}
	}

	invByID := make(map[string]Invariant, len(e.invariants))
	for _, inv := range e.invariants {
		invByID[inv.ID] = inv
	}

	out := make([]finding.Finding, 0, len(attempt.Verdicts))
	for _, v := range attempt.Verdicts {
		inv := invByID[v.Invariant]
		ev := map[string]any{}
		for k, val := range v.Evidence {
			ev[k] = val
		}
		ev["attack_family"] = cand.Probe.Family
		ev["stated_objective"] = cand.Probe.Objective
		ev["tools_attempted"] = attempt.ToolsAttempted
		ev["tools_executed"] = attempt.ToolsExecuted

		out = append(out, finding.New(finding.Context{
			Invariant:           v.Invariant,
			InvariantDesc:       inv.Description,
			InvariantSeverity:   inv.Severity,
			Component:           inv.Component,
			AttackID:            attempt.TestID,
			GeneratorID:         attempt.GeneratorID,
			TargetConfiguration: e.profile.Name,
			CryptoProfile:       string(e.profile.CryptoProfile),
			Outcome:             v.Outcome,
			Impact:              v.Detail,
			Remediation:         inv.Remediation,
			Evidence:            ev,
			Reproduction:        repro,
		}))
	}
	return out
}

// probeSteps renders the probe and what came of it, for the
// reproduction notes.
func probeSteps(cand Candidate, attempt Attempt) []string {
	steps := []string{
		"user input: " + cand.Probe.UserInput,
	}
	if cand.Probe.UntrustedContent != "" {
		steps = append(steps, "untrusted content: "+cand.Probe.UntrustedContent)
	}
	if attempt.Transcript != nil {
		for _, inv := range attempt.Transcript.AllInvocations() {
			outcome := "refused"
			if inv.Executed {
				outcome = "executed"
			}
			steps = append(steps, fmt.Sprintf("tool %s -> %s (%s)", inv.Proposed.Name, outcome, inv.Decision))
		}
	}
	return steps
}

// probePayees builds the saved-payee list for a probe session: every
// other fixture owner's account.
//
// The destination side of a transfer is an allowlist the application
// controls, and a real customer has one. The security question a probe
// exists to answer is whether an attacker can move money to such a
// destination without the customer's approval -- not whether they can
// invent a destination, which the gateway refuses outright.
func probePayees(seeded assistant.SeededFixture, sessionOwner string) []assistant.Payee {
	var out []assistant.Payee
	for _, owner := range seeded.Owners() {
		if owner == sessionOwner {
			continue
		}
		if acct, ok := seeded.Accounts[owner]; ok {
			out = append(out, assistant.Payee{Name: owner, Account: acct})
		}
	}
	return out
}

// resolveTargetAccount creates a throwaway environment, seeds the same
// synthetic fixture every probe uses, and returns the victim account's
// identifier.
//
// It is resolved once per experiment rather than per probe so that every
// probe in a run names the same victim, which is what keeps the runs
// comparable. The environment is discarded immediately; the identifier
// is stable because the fixture is.
func (e *Engine) resolveTargetAccount(ctx context.Context) (string, error) {
	env, err := harness.NewLocalEnvironment(e.profile)
	if err != nil {
		return "", fmt.Errorf("wire a fixture environment: %w", err)
	}
	defer env.Close()

	seeded, err := assistant.SeedSyntheticAccounts(ctx, env.Client, assistant.SyntheticFixture())
	if err != nil {
		return "", fmt.Errorf("seed the fixture: %w", err)
	}
	for _, owner := range seeded.Owners() {
		if owner != probeSessionOwner {
			return string(seeded.Accounts[owner]), nil
		}
	}
	return "", fmt.Errorf("the fixture has no account other than %s's", probeSessionOwner)
}

// knownToAttacker lists identifiers this probe's generator was given
// before writing the attack. Read from the candidate's own metadata so
// the exclusion is driven by what was actually disclosed for this
// probe, not by what the spec requested in general.
func knownToAttacker(cand Candidate) []string {
	if cand.Probe == nil || cand.Probe.Metadata["target_account_disclosed"] != "true" {
		return nil
	}
	if acct := cand.Probe.Metadata["target_account"]; acct != "" {
		return []string{acct}
	}
	return nil
}
