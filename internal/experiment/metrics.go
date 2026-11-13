package experiment

import (
	"context"
	"fmt"
	"sort"

	"banksec-lab/internal/finding"
)

// Metrics is one experiment's comparative measurements.
//
// Every ratio here is a pointer, and that is deliberate: a ratio whose
// denominator is zero is undefined, not zero. An experiment that found
// nothing has an undefined cost per finding, and reporting that as 0.0
// would make the worst possible result look like the best one. Each
// field's doc comment states its numerator, its denominator, and how to
// read it.
type Metrics struct {
	ExperimentID        string     `json:"experiment_id"`
	GeneratorID         string     `json:"generator_id"`
	TargetConfiguration string     `json:"target_configuration"`
	CryptoProfile       string     `json:"crypto_profile,omitempty"`
	StopReason          StopReason `json:"stop_reason"`

	// TestsProduced is how many candidates the generator proposed and
	// the engine evaluated.
	TestsProduced int `json:"tests_produced"`
	// ActionBudget and ActionsSpent are the configured ceiling and what
	// was actually submitted to the simulator. Two generators are only
	// comparable when their budgets match, so both are recorded.
	ActionBudget int   `json:"action_budget"`
	ActionsSpent int   `json:"actions_spent"`
	RuntimeMS    int64 `json:"runtime_ms"`

	// RawAttempts counts evaluated invariant judgements, before
	// deduplication. Deliberately kept apart from UniqueConfirmedFindings:
	// conflating the two is the easiest way to overstate a result.
	RawAttempts         int `json:"raw_attempts"`
	ConfirmedViolations int `json:"confirmed_violations"`
	Blocked             int `json:"blocked"`
	Inconclusive        int `json:"inconclusive"`
	Errors              int `json:"errors"`

	// UniqueConfirmedFindings counts distinct oracle-confirmed security
	// violations: the number of separate weaknesses, after collapsing
	// superficial variations of one weakness.
	//   numerator:   deduplicated findings whose outcome is confirmed_violation
	//   denominator: n/a (a count)
	UniqueConfirmedFindings int `json:"unique_confirmed_findings"`

	// FindingYieldPerAction is unique confirmed findings per action
	// actually submitted to the simulator. This is the per-budget figure
	// two generators are compared on.
	//   numerator:   UniqueConfirmedFindings
	//   denominator: ActionsSpent
	//   undefined:   when no action reached the simulator
	FindingYieldPerAction *float64 `json:"finding_yield_per_action,omitempty"`

	// VerificationRate is the proportion of evaluated judgements that
	// reached a conclusive verdict. A low rate means the experiment
	// mostly could not tell, which is a limitation of the experiment
	// rather than a property of the system.
	//   numerator:   confirmed_violation + blocked
	//   denominator: all evaluated judgements
	//   undefined:   when nothing was evaluated
	VerificationRate *float64 `json:"verification_rate,omitempty"`

	// InvariantCoverage is the proportion of the invariants this run
	// evaluated that it was actually able to decide. It measures what
	// the instrumentation reached, not how secure the system is.
	//   numerator:   distinct invariants with at least one conclusive verdict
	//   denominator: distinct invariants evaluated at all
	//   undefined:   when no invariant was evaluated
	InvariantCoverage *float64 `json:"invariant_coverage,omitempty"`

	// BenignTaskSuccessRate is how often a legitimate banking operation
	// -- an owner acting on their own account -- succeeded under this
	// configuration. A security control that blocks attacks by blocking
	// everything is not a good control, and this is what shows that.
	//   numerator:   accepted state-changing operations by the account's own owner
	//   denominator: all such operations submitted
	//   undefined:   when none was submitted, which is the case for
	//                baseline runs, whose scenarios keep no action trace
	BenignTaskSuccessRate *float64 `json:"benign_task_success_rate,omitempty"`

	// CostPerConfirmedFindingMS is wall-clock milliseconds per distinct
	// confirmed violation.
	//   numerator:   RuntimeMS
	//   denominator: UniqueConfirmedFindings
	//   undefined:   when nothing was confirmed -- not zero, and not
	//                infinite; the run simply has no cost-per-finding
	CostPerConfirmedFindingMS *float64 `json:"cost_per_confirmed_finding_ms,omitempty"`

	// ReproducedFindings and ReplayedFindings are populated only by
	// Engine.Replay. ReproducibilityRate is their ratio.
	ReplayedFindings    int      `json:"replayed_findings"`
	ReproducedFindings  int      `json:"reproduced_findings"`
	ReproducibilityRate *float64 `json:"reproducibility_rate,omitempty"`
	// ReproducibilityNote states what replay could and could not cover.
	ReproducibilityNote string `json:"reproducibility_note,omitempty"`
}

// ratio returns num/den, or nil when den is zero. Every undefined ratio
// in this package goes through here, so none of them can silently become
// a zero.
func ratio(num, den int) *float64 {
	if den == 0 {
		return nil
	}
	v := float64(num) / float64(den)
	return &v
}

func ratio64(num int64, den int) *float64 {
	if den == 0 {
		return nil
	}
	v := float64(num) / float64(den)
	return &v
}

// MetricsOf computes one run's metrics from its record.
func MetricsOf(rec Record) Metrics {
	m := Metrics{
		ExperimentID:        rec.Spec.ExperimentID,
		GeneratorID:         rec.GeneratorID,
		TargetConfiguration: rec.Spec.TargetProfile,
		CryptoProfile:       string(rec.Spec.CryptoProfile),
		StopReason:          rec.StopReason,
		TestsProduced:       rec.TestsProduced,
		ActionBudget:        rec.Spec.Budget.MaxActions,
		ActionsSpent:        rec.ActionsSpent,
		RuntimeMS:           rec.DurationMS,

		RawAttempts:         rec.Findings.RawAttempts,
		ConfirmedViolations: rec.Findings.ConfirmedViolations,
		Blocked:             rec.Findings.Blocked,
		Inconclusive:        rec.Findings.Inconclusive,
		Errors:              rec.Findings.Errors,
	}

	m.UniqueConfirmedFindings = rec.Findings.UniqueConfirmedViolations()
	m.FindingYieldPerAction = ratio(m.UniqueConfirmedFindings, m.ActionsSpent)
	m.VerificationRate = ratio(m.ConfirmedViolations+m.Blocked, m.RawAttempts)
	m.CostPerConfirmedFindingMS = ratio64(m.RuntimeMS, m.UniqueConfirmedFindings)
	m.InvariantCoverage = invariantCoverage(rec)
	m.BenignTaskSuccessRate = benignTaskSuccessRate(rec)

	return m
}

// invariantCoverage measures how much of what the run tried to check it
// could actually decide.
func invariantCoverage(rec Record) *float64 {
	evaluated := map[string]bool{}
	conclusive := map[string]bool{}
	for _, a := range rec.Attempts {
		for _, v := range a.Verdicts {
			evaluated[v.Invariant] = true
			if v.Outcome == finding.OutcomeConfirmedViolation || v.Outcome == finding.OutcomeBlocked {
				conclusive[v.Invariant] = true
			}
		}
	}
	return ratio(len(conclusive), len(evaluated))
}

// benignTaskSuccessRate measures whether legitimate banking work still
// works. Only an owner acting on their own account counts as benign;
// ownership comes from the trace's own create-account responses, so a
// run with no trace -- every baseline run -- has no rate rather than a
// fabricated one.
func benignTaskSuccessRate(rec Record) *float64 {
	var attempted, succeeded int

	for _, a := range rec.Attempts {
		owners := ownersFromTrace(a.Steps)
		for _, s := range a.Steps {
			if !s.Executed || s.TransportError != "" || !IsMutatingOp(s.Action.Op) {
				continue
			}
			if s.Action.Op == OpCreateAccount {
				attempted++
				if s.ResponseOK {
					succeeded++
				}
				continue
			}
			acct := s.Action.Params["account"]
			if s.Action.Op == OpTransfer {
				acct = s.Action.Params["from"]
			}
			ownerID, known := owners[acct]
			if !known || ownerID != s.Action.Actor.ID {
				continue // not a benign operation
			}
			attempted++
			if s.ResponseOK {
				succeeded++
			}
		}
	}

	return ratio(succeeded, attempted)
}

// Comparison holds the metrics of two or more conditions evaluated under
// comparable settings, plus whether that comparability actually holds.
type Comparison struct {
	Conditions []Metrics `json:"conditions"`
	// Comparable is false when the conditions did not run under
	// equivalent settings, in which case Caveats says why. A comparison
	// of incomparable runs is reported as such rather than quietly
	// presented as a result.
	Comparable bool     `json:"comparable"`
	Caveats    []string `json:"caveats,omitempty"`
}

// Compare assembles a comparison and checks that the conditions really
// are comparable: same target configuration, same crypto profile, and
// same action budget. Differing budgets are the usual way an unfair
// comparison creeps in, so it is checked rather than assumed.
func Compare(records ...Record) Comparison {
	c := Comparison{Comparable: true}
	for _, rec := range records {
		c.Conditions = append(c.Conditions, MetricsOf(rec))
	}
	if len(c.Conditions) < 2 {
		c.Comparable = false
		c.Caveats = append(c.Caveats, "a comparison needs at least two conditions")
		return c
	}

	base := c.Conditions[0]
	for _, m := range c.Conditions[1:] {
		if m.TargetConfiguration != base.TargetConfiguration {
			c.Comparable = false
			c.Caveats = append(c.Caveats, fmt.Sprintf(
				"conditions ran against different security configurations (%s vs %s)",
				base.TargetConfiguration, m.TargetConfiguration))
		}
		if m.CryptoProfile != base.CryptoProfile {
			c.Comparable = false
			c.Caveats = append(c.Caveats, fmt.Sprintf(
				"conditions ran under different cryptographic profiles (%q vs %q)",
				base.CryptoProfile, m.CryptoProfile))
		}
		if m.ActionBudget != base.ActionBudget {
			c.Comparable = false
			c.Caveats = append(c.Caveats, fmt.Sprintf(
				"conditions ran under different action budgets (%d vs %d)",
				base.ActionBudget, m.ActionBudget))
		}
	}

	// The per-action metrics are only meaningful when every condition
	// actually spent actions through the validation boundary. Baseline
	// scenarios execute their own Go code rather than submitting
	// Actions, so a static condition spends none, and its finding yield
	// is undefined rather than zero. Comparing a defined yield against
	// an undefined one is not a comparison, and saying so is the whole
	// point of this caveat: without it, a reader could conclude that
	// mutation "wins on yield" simply because the baseline has no yield
	// figure at all.
	var withActions, withoutActions int
	for _, m := range c.Conditions {
		if m.ActionsSpent > 0 {
			withActions++
		} else {
			withoutActions++
		}
	}
	if withActions > 0 && withoutActions > 0 {
		c.Caveats = append(c.Caveats,
			"per-action metrics (finding yield, cost per action) are not comparable across these conditions: "+
				"at least one spent no actions through the validation boundary, because baseline scenarios are "+
				"implemented as Go code rather than as submitted actions; compare them on unique confirmed "+
				"findings and runtime instead")
	}

	// A condition that stopped early for a reason unrelated to its
	// budget did not get an equal shot, which is a caveat rather than an
	// outright incomparability.
	for _, m := range c.Conditions {
		if m.StopReason == StopReasonError || m.StopReason == StopReasonCancelled {
			c.Caveats = append(c.Caveats, fmt.Sprintf(
				"condition %s/%s stopped early (%s), so its figures are not a full run",
				m.ExperimentID, m.GeneratorID, m.StopReason))
		}
	}

	sort.Strings(c.Caveats)
	return c
}

// Replay re-executes every recorded action plan in rec and reports how
// many of its confirmed violations reproduce.
//
// Only plan candidates can be replayed. Baseline scenarios are Go
// closures rather than recorded action sequences, so a record containing
// them can be re-run but not replayed action by action; Replay says so
// in the note rather than counting them either way. This is the
// distinction between exact replay and re-execution that the
// reproducibility figure depends on.
func (e *Engine) Replay(ctx context.Context, rec Record) (Metrics, error) {
	m := MetricsOf(rec)

	eff := rec.Spec.Effective()
	if eff.TargetProfile != e.profile.Name {
		return Metrics{}, fmt.Errorf("%w: cannot replay a record from profile %q on an engine loaded with %q",
			ErrInvalidSpec, eff.TargetProfile, e.profile.Name)
	}

	var replayable, skipped int
	for _, a := range rec.Attempts {
		if a.Plan == nil {
			skipped++
			continue
		}
		replayable++
	}
	if replayable == 0 {
		m.ReproducibilityNote = fmt.Sprintf(
			"nothing to replay: all %d attempt(s) are baseline scenarios, which are re-executed rather than replayed", skipped)
		return m, nil
	}

	// A fresh validator, so the replay is bounded exactly as the
	// original run was rather than inheriting a spent budget.
	validator, err := NewValidator(eff)
	if err != nil {
		return Metrics{}, err
	}

	var reproduced int
	for _, a := range rec.Attempts {
		if a.Plan == nil {
			continue
		}
		// Only attempts that originally confirmed something are worth
		// replaying for a reproducibility figure.
		if !attemptConfirmedViolation(a) {
			continue
		}
		m.ReplayedFindings++

		plan := a.Plan.Clone()
		cand := Candidate{
			TestID:           a.TestID + "/replay",
			GeneratorID:      a.GeneratorID,
			SourceScenarioID: a.SourceScenarioID,
			Seed:             rec.Spec.Seed,
			Mutations:        a.Mutations,
			Plan:             &plan,
		}
		again := e.evaluate(ctx, cand, validator)
		if again.Error == "" && attemptConfirmedViolation(again) {
			reproduced++
		}
	}

	m.ReproducedFindings = reproduced
	m.ReproducibilityRate = ratio(reproduced, m.ReplayedFindings)
	switch {
	case m.ReplayedFindings == 0:
		m.ReproducibilityNote = "no confirmed violation in this record was replayable, so the rate is undefined rather than zero"
	case skipped > 0:
		m.ReproducibilityNote = fmt.Sprintf(
			"%d plan-based finding(s) replayed exactly; %d baseline scenario attempt(s) were excluded because they are Go code, not recorded action sequences",
			m.ReplayedFindings, skipped)
	default:
		m.ReproducibilityNote = fmt.Sprintf("%d plan-based finding(s) replayed exactly", m.ReplayedFindings)
	}

	return m, nil
}
