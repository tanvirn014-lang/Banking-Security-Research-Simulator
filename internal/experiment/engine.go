package experiment

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"banksec-lab/internal/assistant"
	"banksec-lab/internal/config"
	"banksec-lab/internal/finding"
	"banksec-lab/internal/harness"
	"banksec-lab/internal/llm"
)

// categorySeverity bands a baseline scenario's confirmed success by the
// attack class it belongs to. It is a coarse, documented mapping, not a
// score: this project has no evidence that would support a CVSS vector,
// and an invented one would be worse than none. The bands say only that
// a ledger, key-management, or cryptographic compromise is treated as
// more severe than an application or protocol one.
var categorySeverity = map[string]finding.Severity{
	"ledger":         finding.SeverityCritical,
	"key-management": finding.SeverityCritical,
	"cryptographic":  finding.SeverityCritical,
	"application":    finding.SeverityHigh,
	"protocol":       finding.SeverityHigh,
}

func severityForCategory(category string) finding.Severity {
	if s, ok := categorySeverity[category]; ok {
		return s
	}
	return finding.SeverityMedium
}

// Engine runs one experiment: it drives a Generator, puts every
// generated action through the Validator, executes each candidate with
// the existing harness.Runner against a freshly wired Environment, and
// adjudicates the outcome with invariants the generator cannot reach.
//
// The Engine owns the isolation guarantee. Every candidate gets its own
// harness.Environment, with its own temp-directory-backed stores, which
// is torn down afterwards. Independent trials therefore cannot
// contaminate one another through shared state, which is what makes
// comparing two generators at the same budget meaningful.
type Engine struct {
	registry   harness.Registry
	runner     harness.Runner
	profile    config.SecurityProfile
	invariants []Invariant
	revision   string
	// assistantProvider is the model the banking assistant under test
	// runs on. Nil means probe candidates cannot be evaluated, which is
	// reported as an attempt error rather than silently skipped.
	assistantProvider llm.Provider
	assistantLimits   assistant.Limits
	assistantTurns    int
	// generatorProvider is the model that writes adversarial inputs. It
	// is deliberately a separate field from assistantProvider: the
	// attacker and the target must be configurable independently, so
	// that changing one cannot silently change the other.
	generatorProvider llm.Provider
}

// EngineOption configures an Engine.
type EngineOption func(*Engine)

// WithInvariants replaces the invariant set. Defaults to
// CoreInvariants.
func WithInvariants(invs []Invariant) EngineOption {
	return func(e *Engine) { e.invariants = invs }
}

// WithSourceRevision records which revision of the code was under test.
func WithSourceRevision(rev string) EngineOption {
	return func(e *Engine) { e.revision = rev }
}

// WithRunner replaces the harness runner. Defaults to
// harness.NewRunner.
func WithRunner(r harness.Runner) EngineOption {
	return func(e *Engine) { e.runner = r }
}

// WithAssistant enables probe candidates by supplying the model the
// banking assistant under test runs on, plus its gateway limits and
// turn budget. Without it, a probe candidate is recorded as an error:
// an experiment that cannot run the system under test has produced no
// evidence, and saying so is better than reporting an empty result as a
// secure one.
func WithAssistant(provider llm.Provider, limits assistant.Limits, maxTurns int) EngineOption {
	return func(e *Engine) {
		e.assistantProvider = provider
		e.assistantLimits = limits
		e.assistantTurns = maxTurns
		e.invariants = append(e.invariants, AssistantInvariants()...)
	}
}

// NewEngine builds an engine that runs experiments against profile,
// drawing baseline scenarios from reg.
func NewEngine(reg harness.Registry, profile config.SecurityProfile, opts ...EngineOption) (*Engine, error) {
	if reg == nil {
		return nil, errors.New("experiment engine: registry must not be nil")
	}
	if profile.Name == "" {
		return nil, errors.New("experiment engine: profile must be loaded (its Name is empty)")
	}
	e := &Engine{
		registry:   reg,
		runner:     harness.NewRunner(),
		profile:    profile,
		invariants: CoreInvariants(),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// Profile returns the security configuration this engine runs against.
func (e *Engine) Profile() config.SecurityProfile { return e.profile }

// NewGenerator builds the generator a spec asks for. An adaptive
// generator would be constructed here too; today there are two, and a
// spec naming anything else was already rejected by Validate.
func (e *Engine) NewGenerator(spec ExperimentSpec) (Generator, error) {
	eff := spec.Effective()
	switch eff.Generator {
	case GeneratorStatic:
		return NewStaticGenerator(e.registry, eff.SeedScenarios, eff.Safety.AllowPrivileged)
	case GeneratorMutation:
		return NewMutationGenerator(e.registry, eff)
	case GeneratorLLM:
		if e.assistantProvider == nil {
			return nil, fmt.Errorf("experiment engine: the llm generator needs an assistant to test " +
				"(construct the engine with WithAssistant)")
		}
		if e.generatorProvider == nil {
			return nil, fmt.Errorf("experiment engine: the llm generator needs its own model " +
				"(construct the engine with WithAttackGenerator)")
		}
		return NewLLMGenerator(e.generatorProvider, eff)
	default:
		return nil, fmt.Errorf("experiment engine: generator %q is not implemented", eff.Generator)
	}
}

// WithAttackGenerator supplies the model that writes adversarial
// inputs. Kept separate from WithAssistant so the attacker and the
// target are configured independently and can be different models.
func WithAttackGenerator(provider llm.Provider) EngineOption {
	return func(e *Engine) { e.generatorProvider = provider }
}

// Run executes one experiment end to end and returns its record.
//
// An error is returned only when the experiment could not be started at
// all -- an invalid spec, a generator that could not be constructed.
// Once running, a failure to evaluate one candidate is recorded as that
// attempt's Error and the experiment continues, unless the spec declares
// StopOnFirstError. A generator error is never recorded as an attack
// success.
func (e *Engine) Run(ctx context.Context, spec ExperimentSpec) (Record, error) {
	if err := spec.Validate(); err != nil {
		return Record{}, err
	}
	eff := spec.Effective()
	if eff.TargetProfile != e.profile.Name {
		return Record{}, fmt.Errorf("%w: target_profile %q does not match this engine's loaded profile %q",
			ErrInvalidSpec, eff.TargetProfile, e.profile.Name)
	}

	validator, err := NewValidator(eff)
	if err != nil {
		return Record{}, err
	}
	gen, err := e.NewGenerator(eff)
	if err != nil {
		return Record{}, err
	}

	return e.runLoop(ctx, eff, gen, validator), nil
}

// runLoop is Run's evaluation loop, split out so that generator failure
// paths can be exercised with a substituted generator. It takes an
// already-effective spec and an already-built validator, and never
// returns an error: every failure from here on is recorded in the
// Record rather than aborting it.
func (e *Engine) runLoop(ctx context.Context, eff ExperimentSpec, gen Generator, validator *Validator) Record {
	started := time.Now()
	rec := Record{
		Spec:           eff,
		GeneratorID:    gen.ID(),
		SourceRevision: e.revision,
		StartedAt:      started,
	}
	if sel, ok := gen.(interface{ Selected() []string }); ok {
		rec.SelectedScenarios = sel.Selected()
	}

	deadline := time.Time{}
	if eff.Budget.MaxDuration > 0 {
		deadline = started.Add(eff.Budget.MaxDuration)
	}

	var rawFindings []finding.Finding
	var summaries []AttemptSummary
	allPlans := true
	anyProbe := false

	rec.StopReason = StopReasonGeneratorExhausted
loop:
	for {
		switch {
		case ctx.Err() != nil:
			rec.StopReason = StopReasonCancelled
			break loop
		case len(rec.Attempts) >= eff.Budget.MaxTests:
			rec.StopReason = StopReasonTestBudget
			break loop
		case validator.Remaining() == 0:
			rec.StopReason = StopReasonActionBudget
			break loop
		case !deadline.IsZero() && !time.Now().Before(deadline):
			rec.StopReason = StopReasonTimeBudget
			break loop
		}

		obs := Observation{
			Spec:             eff,
			TestsProduced:    rec.TestsProduced,
			ActionsSpent:     validator.Spent(),
			ActionsRemaining: validator.Remaining(),
			Attempted:        summaries,
		}

		cand, genErr := gen.Next(ctx, obs)
		if errors.Is(genErr, ErrNoMoreCandidates) {
			rec.StopReason = StopReasonGeneratorExhausted
			break loop
		}
		if genErr != nil {
			// A generator failure is an experiment error, never an
			// attack result.
			rec.Errors = append(rec.Errors, fmt.Sprintf("generator: %v", genErr))
			rec.StopReason = StopReasonError
			break loop
		}
		if err := cand.Validate(); err != nil {
			rec.Errors = append(rec.Errors, fmt.Sprintf("generator produced an unusable candidate: %v", err))
			if eff.HasStopCondition(StopOnFirstError) {
				rec.StopReason = StopReasonError
				break loop
			}
			continue
		}
		rec.TestsProduced++
		if cand.Plan == nil {
			allPlans = false
		}
		if cand.Probe != nil {
			anyProbe = true
		}

		attempt := e.evaluate(ctx, cand, validator)
		rec.Attempts = append(rec.Attempts, attempt)

		if attempt.Error != "" {
			rec.Errors = append(rec.Errors, fmt.Sprintf("%s: %s", attempt.TestID, attempt.Error))
		}

		rawFindings = append(rawFindings, e.findingsFor(cand, attempt, eff)...)
		summaries = append(summaries, AttemptSummary{
			TestID:           attempt.TestID,
			SourceScenarioID: attempt.SourceScenarioID,
			ActionsExecuted:  attempt.ActionsExecuted(),
			Outcomes:         attempt.Outcomes(),
		})

		if attempt.Error != "" && eff.HasStopCondition(StopOnFirstError) {
			rec.StopReason = StopReasonError
			break loop
		}
		if eff.HasStopCondition(StopOnConfirmedViolation) && attemptConfirmedViolation(attempt) {
			rec.StopReason = StopReasonConfirmedViolation
			break loop
		}
	}

	rec.FinishedAt = time.Now()
	rec.DurationMS = rec.FinishedAt.Sub(started).Milliseconds()
	rec.ActionsSpent = validator.Spent()
	rec.Findings = finding.Dedupe(rawFindings)
	rec.Reproducibility = reproducibilityOf(gen, allPlans, anyProbe, len(rec.Attempts))

	return rec
}

// evaluate runs one candidate against its own fresh environment and
// returns its complete record. It never returns an error: a failure to
// evaluate is recorded in the Attempt, so the experiment can continue
// and the record can show that this candidate produced no result.
func (e *Engine) evaluate(ctx context.Context, cand Candidate, validator *Validator) Attempt {
	start := time.Now()
	attempt := Attempt{
		TestID:           cand.TestID,
		GeneratorID:      cand.GeneratorID,
		SourceScenarioID: cand.SourceScenarioID,
		Mutations:        cand.Mutations,
		Plan:             cand.Plan,
		Probe:            cand.Probe,
	}
	defer func() { attempt.DurationMS = time.Since(start).Milliseconds() }()

	env, err := harness.NewLocalEnvironment(e.profile)
	if err != nil {
		attempt.Error = fmt.Sprintf("wire environment: %v", err)
		return attempt
	}
	defer env.Close()

	switch {
	case cand.Plan != nil:
		return e.evaluatePlan(ctx, cand, validator, env, attempt)
	case cand.Probe != nil:
		return e.evaluateProbe(ctx, cand, env, attempt)
	default:
		return e.evaluateScenario(ctx, cand, env, attempt)
	}
}

// evaluatePlan runs a declarative candidate. The plan's own scenario
// adapter takes the snapshots and applies the invariants, because both
// must happen inside the Runner's Prereqs/Verify so they bracket Exec
// exactly.
func (e *Engine) evaluatePlan(ctx context.Context, cand Candidate, validator *Validator, env *harness.Environment, attempt Attempt) Attempt {
	run := &planRun{
		validator:  validator,
		profile:    e.profile,
		invariants: e.invariants,
		since:      time.Now().Add(-time.Minute),
	}

	result, err := e.runner.Run(ctx, planScenario(cand, run), env, cand.Seed)
	attempt.Result = resultRecordOf(result)
	attempt.Steps = run.Steps()
	attempt.StopReason = run.StopReason()
	before, after := run.Snapshots()
	attempt.SnapshotBefore = before
	attempt.SnapshotAfter = after
	attempt.Verdicts = flattenVerdicts(run.Verdicts())
	if err != nil {
		attempt.Error = err.Error()
	}
	return attempt
}

// evaluateScenario runs a baseline candidate. Its Exec is an opaque Go
// closure, so the snapshots are taken around the whole run here rather
// than inside it, and the step trace is necessarily empty -- which is
// why trace-dependent invariants report inconclusive for baseline
// candidates instead of guessing from evidence they do not have.
func (e *Engine) evaluateScenario(ctx context.Context, cand Candidate, env *harness.Environment, attempt Attempt) Attempt {
	since := time.Now().Add(-time.Minute)

	before, err := CaptureSnapshot(ctx, env.Oracle, since)
	if err != nil {
		attempt.Error = fmt.Sprintf("capture before snapshot: %v", err)
		return attempt
	}
	attempt.SnapshotBefore = before

	result, runErr := e.runner.Run(ctx, *cand.Scenario, env, cand.Seed)
	attempt.Result = resultRecordOf(result)
	if runErr != nil {
		attempt.Error = runErr.Error()
	}

	after, err := CaptureSnapshot(ctx, env.Oracle, since)
	if err != nil {
		if attempt.Error == "" {
			attempt.Error = fmt.Sprintf("capture after snapshot: %v", err)
		}
		return attempt
	}
	attempt.SnapshotAfter = after

	in := InvariantInput{Profile: e.profile, Before: before, After: after, Steps: nil}
	verdicts := make(map[string]InvariantVerdict)
	for _, inv := range e.invariants {
		if !inv.Applicable(e.profile) {
			continue
		}
		verdicts[inv.ID] = inv.Check(in)
	}
	attempt.Verdicts = flattenVerdicts(verdicts)
	return attempt
}

// findingsFor turns one attempt into findings.
//
// Every attempt contributes one finding per invariant evaluated. A
// baseline candidate additionally contributes a finding for the
// scenario's own adjudication, because a registered scenario's Verify is
// itself an oracle-backed check of a property the core invariants cannot
// express -- a replay being accepted, a revoked key still working. That
// verdict comes from the scenario's Verify reading the Oracle, never
// from its Exec's own claim: harness.Runner discards Exec's return value
// entirely.
func (e *Engine) findingsFor(cand Candidate, attempt Attempt, eff ExperimentSpec) []finding.Finding {
	if cand.Probe != nil {
		return e.probeFindings(cand, attempt, eff)
	}

	repro := finding.Reproduction{
		ExperimentID: eff.ExperimentID,
		TestID:       attempt.TestID,
		Seed:         cand.Seed,
		Steps:        renderSteps(attempt.Steps),
	}
	if cand.Plan == nil {
		repro.Note = "baseline scenario: its implementation is Go code in internal/harness, not a recorded action sequence, so the steps field is empty by design"
	}

	var out []finding.Finding

	if attempt.Error != "" {
		out = append(out, finding.New(finding.Context{
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
		}))
		return out
	}

	invByID := make(map[string]Invariant, len(e.invariants))
	for _, inv := range e.invariants {
		invByID[inv.ID] = inv
	}

	for _, v := range attempt.Verdicts {
		inv := invByID[v.Invariant]
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
			Evidence:            v.Evidence,
			Reproduction:        repro,
		}))
	}

	if cand.Scenario != nil {
		outcome := finding.OutcomeBlocked
		impact := "the registered scenario ran and its oracle-backed check did not confirm the attack succeeded"
		if attempt.Result.Success {
			outcome = finding.OutcomeConfirmedViolation
			impact = "the registered scenario's oracle-backed check confirmed the attack achieved its objective"
		}
		out = append(out, finding.New(finding.Context{
			Invariant:           "scenario." + cand.SourceScenarioID,
			InvariantDesc:       fmt.Sprintf("the %s attack scenario does not achieve its objective", cand.SourceScenarioID),
			InvariantSeverity:   severityForCategory(cand.Scenario.Category),
			Component:           cand.Scenario.TargetComponent,
			AttackID:            attempt.TestID,
			GeneratorID:         attempt.GeneratorID,
			TargetConfiguration: e.profile.Name,
			CryptoProfile:       string(e.profile.CryptoProfile),
			Outcome:             outcome,
			Impact:              impact,
			Reproduction:        repro,
		}))
	}

	return out
}

func attemptConfirmedViolation(a Attempt) bool {
	for _, v := range a.Verdicts {
		if v.Outcome == finding.OutcomeConfirmedViolation {
			return true
		}
	}
	return a.Result.Success
}

func flattenVerdicts(in map[string]InvariantVerdict) []VerdictRecord {
	out := make([]VerdictRecord, 0, len(in))
	for id, v := range in {
		out = append(out, VerdictRecord{
			Invariant: id,
			Outcome:   v.Outcome,
			Detail:    v.Detail,
			Evidence:  v.Evidence,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Invariant < out[j].Invariant })
	return out
}

func renderSteps(steps []Step) []string {
	if len(steps) == 0 {
		return nil
	}
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		line := s.Action.String() + " -> " + string(s.Validation.Decision)
		if s.Executed {
			if s.TransportError != "" {
				line += fmt.Sprintf(" transport_error=%q", s.TransportError)
			} else if s.ResponseOK {
				line += " accepted"
			} else {
				line += fmt.Sprintf(" refused=%q", s.ResponseError)
			}
		}
		out = append(out, line)
	}
	return out
}

func reproducibilityOf(gen Generator, allPlans, anyProbe bool, attempts int) Reproducibility {
	if attempts == 0 {
		return Reproducibility{Note: "no candidate was evaluated"}
	}
	if anyProbe {
		// A probe's adversarial text is recorded verbatim and can be
		// replayed exactly, but the assistant answering it is a language
		// model: the same input can take a different path on a new run
		// even at temperature zero. So the input replays and the outcome
		// may not, which is a different claim from either of the others.
		return Reproducibility{
			ExactReplaySupported: false,
			Note: "this run includes assistant probes; their adversarial inputs are recorded verbatim and can be " +
				"replayed exactly, but the assistant is a language model, so replaying an input may not reproduce " +
				"the same outcome -- reproducing a finding and reproducing a run are different claims here",
		}
	}
	if !allPlans {
		return Reproducibility{
			ExactReplaySupported: false,
			Note: "this run includes baseline scenarios, whose implementations are Go code rather than recorded action sequences; " +
				"re-running the same spec re-executes them, but the record cannot replay them action by action",
		}
	}
	return Reproducibility{
		ExactReplaySupported: true,
		Note:                 "every candidate is a recorded action plan and can be re-executed verbatim from this record",
	}
}
