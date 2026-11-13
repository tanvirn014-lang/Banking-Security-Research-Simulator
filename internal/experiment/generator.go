package experiment

import (
	"context"
	"errors"

	"banksec-lab/internal/finding"
	"banksec-lab/internal/harness"
)

// ErrNoMoreCandidates is what a Generator returns when it has nothing
// left to propose. The engine treats it as a clean stop, not a failure
// -- the same convention internal/agent uses for ErrNoActionsRemain.
var ErrNoMoreCandidates = errors.New("generator has no further candidates")

// Generator proposes the next test an experiment should run.
//
// This is the extension point the research design is built around. A
// generator may be arbitrarily open-ended in strategy -- the static
// corpus, bounded mutation, and in future a search algorithm, a
// reinforcement-learning policy, or a local LLM -- but whatever it
// proposes reaches the simulator only as a Candidate, through the
// validation boundary, and is adjudicated only by invariants it has no
// access to. Implementing this interface requires no change to the
// banking ledger, the action validator, or the independent oracle.
//
// A Generator need not plan a whole attack in advance. Next is called
// repeatedly and is handed an Observation of what has already been
// attempted and what budget remains, so a generator may decide its next
// move from prior results.
//
// Next must respect the remaining budget in the Observation it is given
// and must return ErrNoMoreCandidates rather than an empty candidate
// when it is finished. Any other error is recorded as an experiment
// error, never as an attack success.
type Generator interface {
	// ID identifies this generator in experiment records, e.g. "static".
	ID() string
	// Next proposes the next candidate, or returns ErrNoMoreCandidates.
	Next(ctx context.Context, obs Observation) (Candidate, error)
}

// Observation is the bounded view of experiment progress a Generator is
// given. It deliberately contains no Oracle, no Environment, and no key
// material: a generator learns what happened, not how to reach into the
// simulator directly.
type Observation struct {
	Spec             ExperimentSpec
	TestsProduced    int
	ActionsSpent     int
	ActionsRemaining int
	// Attempted summarizes every candidate already evaluated, oldest
	// first.
	Attempted []AttemptSummary
}

// AttemptSummary is what one evaluated candidate is reduced to for a
// generator's benefit: enough to steer, not enough to confuse a
// generator's claim with a verified result.
type AttemptSummary struct {
	TestID           string
	SourceScenarioID string
	ActionsExecuted  int
	// Outcomes maps invariant ID to what was concluded about it.
	Outcomes map[string]finding.Outcome
}

// ConfirmedViolation reports whether this attempt produced at least one
// oracle-confirmed violation.
func (a AttemptSummary) ConfirmedViolation() bool {
	for _, o := range a.Outcomes {
		if o == finding.OutcomeConfirmedViolation {
			return true
		}
	}
	return false
}

// ActionPlan is a declarative, serializable attack: an ordered sequence
// of proposed actions plus the metadata saying where it came from. This
// is what a dynamic generator produces, and what makes a generated
// finding reproducible -- a plan can be written into a record and read
// back, which an opaque Go closure cannot.
type ActionPlan struct {
	Actions []Action `json:"actions"`
}

// Len reports how many actions the plan proposes.
func (p ActionPlan) Len() int { return len(p.Actions) }

// Clone deep-copies the plan, so a generator can derive a variant
// without aliasing the plan it derived from.
func (p ActionPlan) Clone() ActionPlan {
	if p.Actions == nil {
		return ActionPlan{}
	}
	out := make([]Action, len(p.Actions))
	for i, a := range p.Actions {
		out[i] = a.Clone()
	}
	return ActionPlan{Actions: out}
}

// Candidate is one test a Generator proposes.
//
// Exactly one of Plan and Scenario is set, and that is a deliberate,
// documented asymmetry rather than an accident. The twelve registered
// baseline scenarios are Go closures that use capabilities no action
// sequence can express -- the harness's privileged insider writes and
// raw protocol frame access -- so they cannot be rewritten as plans
// without losing the attacks they implement. Reducing them to plans was
// considered and rejected for exactly that reason.
//
// Both kinds nonetheless travel the identical pipeline from here on:
// the same harness.Runner executes them, the same read-only
// harness.Oracle adjudicates them, the same harness.Result comes back,
// and the same core invariants are applied to the same before/after
// snapshots. What differs is only that a Plan's every action passes
// through the Validator and lands in the step trace, whereas a static
// Scenario's internal actions do not -- so trace-dependent invariants
// report inconclusive for static candidates rather than guessing.
type Candidate struct {
	// TestID uniquely identifies this candidate within the experiment.
	TestID string `json:"test_id"`
	// GeneratorID names the generator that produced it.
	GeneratorID string `json:"generator_id"`
	// SourceScenarioID names the registered scenario this candidate is,
	// or was derived from. Empty if neither.
	SourceScenarioID string `json:"source_scenario_id,omitempty"`
	// Mutations describes, in order, how this candidate differs from its
	// source. Empty for an unmodified baseline scenario. This is what
	// makes "do not merely rename static scenarios as dynamic"
	// checkable: a candidate claiming to be a mutation must say what it
	// changed.
	Mutations []string `json:"mutations,omitempty"`
	// Seed is the random seed this candidate was produced under, carried
	// into the harness run and into the finding's reproduction notes.
	Seed int64 `json:"seed"`
	// Plan is set for a generated, declarative candidate.
	Plan *ActionPlan `json:"plan,omitempty"`
	// Scenario is set for a baseline candidate drawn from the registry.
	Scenario *harness.Scenario `json:"-"`
	// Probe is set for a candidate that attacks the banking AI
	// assistant with an adversarial message rather than with banking
	// operations.
	Probe *Probe `json:"probe,omitempty"`
}

// kindCount reports how many of the three candidate shapes are set.
// Exactly one must be.
func (c Candidate) kindCount() int {
	n := 0
	for _, set := range []bool{c.Plan != nil, c.Scenario != nil, c.Probe != nil} {
		if set {
			n++
		}
	}
	return n
}

// Validate reports whether the candidate is structurally usable. A
// generator that returns a malformed candidate is an experiment error;
// the engine must never silently run something it cannot describe.
func (c Candidate) Validate() error {
	if c.TestID == "" {
		return errors.New("candidate has no test id")
	}
	if c.GeneratorID == "" {
		return errors.New("candidate has no generator id")
	}
	if c.kindCount() != 1 {
		return errors.New("candidate must carry exactly one of Plan, Scenario or Probe")
	}
	if c.Plan != nil && c.Plan.Len() == 0 {
		return errors.New("candidate plan proposes no actions")
	}
	if c.Probe != nil {
		if err := c.Probe.Validate(); err != nil {
			return err
		}
	}
	if len(c.Mutations) > 0 && c.Plan == nil {
		return errors.New("candidate claims mutations but carries no plan describing them")
	}
	return nil
}

// IsDerived reports whether this candidate was modified from its source
// rather than replayed unchanged.
func (c Candidate) IsDerived() bool { return len(c.Mutations) > 0 }
