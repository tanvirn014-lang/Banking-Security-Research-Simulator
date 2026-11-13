package experiment

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"banksec-lab/internal/config"
	"banksec-lab/internal/finding"
	"banksec-lab/internal/harness"
)

// planRun holds one plan candidate's execution state: the validation
// boundary it must pass through, the snapshots taken around it, the step
// trace it produced, and the invariant verdicts drawn from all of that.
//
// It is mutated from the goroutines harness.Runner uses to bound Exec
// and Verify against a deadline, so every field is guarded.
type planRun struct {
	validator  *Validator
	profile    config.SecurityProfile
	invariants []Invariant
	since      time.Time

	mu       sync.Mutex
	before   Snapshot
	after    Snapshot
	steps    []Step
	verdicts map[string]InvariantVerdict
	// stopped records why execution ended early, if it did.
	stopped string
}

// Steps returns a copy of the recorded trace.
func (r *planRun) Steps() []Step {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Step(nil), r.steps...)
}

// Verdicts returns a copy of the invariant verdicts.
func (r *planRun) Verdicts() map[string]InvariantVerdict {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]InvariantVerdict, len(r.verdicts))
	for k, v := range r.verdicts {
		out[k] = v
	}
	return out
}

// Snapshots returns the before and after state the invariants were
// judged from.
func (r *planRun) Snapshots() (before, after Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.before, r.after
}

// StopReason returns why execution ended early, or "" if it ran to
// completion.
func (r *planRun) StopReason() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopped
}

// planScenario adapts a declarative ActionPlan into the harness.Scenario
// the existing Runner executes. This is the single place a generated
// action can reach the simulator, and it reaches it only through
// env.Client -- the banking application's own front door -- after
// Validator.Validate returned DecisionAllow for it.
//
// Deliberately absent: any use of env.Priv. A generated plan has no
// privileged insider channel, no database handle, and no filesystem or
// network access. The strongest thing a generator can cause here is a
// request a hostile client could already have sent.
func planScenario(c Candidate, run *planRun) harness.Scenario {
	return harness.Scenario{
		ID:              c.TestID,
		Category:        "generated",
		TargetComponent: "backend",

		// Prereqs is where the before-snapshot is taken: the Runner
		// calls it after wiring the environment and before any Exec, and
		// it is handed the same read-only Oracle the verdicts will later
		// be drawn from.
		Prereqs: func(ctx context.Context, o harness.Oracle) (bool, error) {
			snap, err := CaptureSnapshot(ctx, o, run.since)
			if err != nil {
				return false, fmt.Errorf("capture before snapshot: %w", err)
			}
			run.mu.Lock()
			run.before = snap
			run.mu.Unlock()
			return true, nil
		},

		Exec: func(ctx context.Context, env *harness.Environment, _ *rand.Rand) error {
			// accounts maps an owner name to the account the simulator
			// actually created for them, so a plan written before any
			// account existed can still refer to one. See
			// resolvePlaceholders.
			accounts := map[string]string{}

			for i, planned := range c.Plan.Actions {
				if err := ctx.Err(); err != nil {
					run.recordStop("context deadline reached")
					return err
				}

				// The resolved action is what gets validated, sent, and
				// recorded: validating the unresolved form would check a
				// placeholder rather than the request actually sent.
				action := resolvePlaceholders(planned, accounts)
				decision := run.validator.Validate(action)
				step := Step{Index: i, Action: action, Validation: decision}

				if decision.Decision != DecisionAllow {
					run.appendStep(step)
					if decision.Decision == DecisionBudgetExhausted {
						run.recordStop("action budget exhausted")
						return nil
					}
					// A refused action is recorded and skipped. It never
					// reaches the simulator, and it is not an error: a
					// generator proposing something the boundary refuses
					// is a normal, recorded event.
					continue
				}

				start := time.Now()
				resp, err := env.Client.Send(ctx, action.Request())
				step.DurationMS = time.Since(start).Milliseconds()
				step.Executed = true
				if err != nil {
					step.TransportError = err.Error()
				} else {
					step.ResponseOK = resp.OK
					step.ResponseError = resp.Error
					step.ResponseData = resp.Data
					if action.Op == OpCreateAccount && resp.OK {
						if acct := resp.Data["account"]; acct != "" {
							accounts[action.Params["owner"]] = acct
						}
					}
				}
				run.appendStep(step)
			}
			return nil
		},

		// Verify is where adjudication happens, and it reads only the
		// Oracle and the recorded trace -- never anything Exec claimed
		// about itself. Success is reported if and only if an invariant
		// confirmed a violation.
		Verify: func(ctx context.Context, o harness.Oracle) (bool, harness.Evidence, error) {
			after, err := CaptureSnapshot(ctx, o, run.since)
			if err != nil {
				return false, nil, fmt.Errorf("capture after snapshot: %w", err)
			}

			run.mu.Lock()
			run.after = after
			before := run.before
			steps := append([]Step(nil), run.steps...)
			run.mu.Unlock()

			in := InvariantInput{Profile: run.profile, Before: before, After: after, Steps: steps}
			verdicts := make(map[string]InvariantVerdict)
			violated := false
			for _, inv := range run.invariants {
				if !inv.Applicable(run.profile) {
					continue
				}
				v := inv.Check(in)
				verdicts[inv.ID] = v
				if v.Outcome == finding.OutcomeConfirmedViolation {
					violated = true
				}
			}

			run.mu.Lock()
			run.verdicts = verdicts
			run.mu.Unlock()

			evidence := harness.Evidence{
				EvidenceRecordsCompromised: int64(countSuccessfulMutations(steps)),
			}
			return violated, evidence, nil
		},
	}
}

// AccountPlaceholderPrefix marks a parameter value that names an
// account indirectly, by the owner it was created for, e.g.
// "$acct:alice". A plan is written before any account exists, so it
// cannot contain real account IDs; this is how it refers to one.
const AccountPlaceholderPrefix = "$acct:"

// AccountPlaceholder builds the placeholder referring to the account
// created for owner.
func AccountPlaceholder(owner string) string {
	return AccountPlaceholderPrefix + owner
}

// resolvePlaceholders replaces account placeholders with the account IDs
// the simulator actually returned earlier in this run.
//
// An unresolvable placeholder is deliberately left as-is rather than
// blanked: it then reaches the validator as a well-formed but nonexistent
// account, which the simulator refuses -- a recorded, honest result.
// Blanking it would make the action malformed instead, hiding the fact
// that the plan referred to something that never came to exist.
func resolvePlaceholders(a Action, accounts map[string]string) Action {
	if len(a.Params) == 0 {
		return a
	}
	resolved := a.Clone()
	for k, v := range resolved.Params {
		if !strings.HasPrefix(v, AccountPlaceholderPrefix) {
			continue
		}
		ownerName := strings.TrimPrefix(v, AccountPlaceholderPrefix)
		if acct, ok := accounts[ownerName]; ok {
			resolved.Params[k] = acct
		}
	}
	return resolved
}

func (r *planRun) appendStep(s Step) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, s)
}

func (r *planRun) recordStop(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped == "" {
		r.stopped = reason
	}
}

// EvidenceRecordsCompromised re-exports the harness evidence key this
// package sets, so the mapping is visible here rather than as a bare
// string literal.
const EvidenceRecordsCompromised = harness.EvidenceRecordsCompromised

func countSuccessfulMutations(steps []Step) int {
	n := 0
	for _, s := range steps {
		if s.IsSuccessfulMutation() {
			n++
		}
	}
	return n
}
