package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"banksec-lab/internal/domain"
	"banksec-lab/internal/harness"
)

// Decision is one recorded step of an Agent's run: the Observation it
// saw, the Action its Policy chose from that Observation, and when.
type Decision struct {
	Obs       Observation
	Action    Action
	Timestamp time.Time
}

// AgentReport aggregates the controlled-experiment measurements the
// user's Milestone 10 instructions require, kept as separate, honestly
// -scoped fields rather than a single rolled-up "score":
//   - Attempts / ActionCallCount: how many scenario executions the
//     Agent actually made (identical in this baseline, since every step
//     that decides an Action also immediately executes it -- tracked as
//     two separate fields because a more sophisticated future Policy
//     could decide not to act on every Observation it makes). Both
//     count a step whose runner.Run call itself returned an error too
//     (security review finding M5) -- the Agent still genuinely made
//     that call; Attempts/ActionCallCount measure attempts made, not
//     attempts that cleanly completed.
//   - SuccessfulCompromises: how many of those executions' own
//     harness.Result reported Success=true (never Agent's own guess --
//     exactly the same "never trust Exec's own claim, only what Verify
//     observes through the Oracle" discipline harness.Runner itself
//     already enforces).
//   - TimeToCompromiseMS: real wall-clock time from this Run call's
//     start to its FIRST successful Result, or nil if none occurred.
//   - ObservationCount: how many times the Agent built an Observation
//     and asked its Policy to decide -- one more than ActionCallCount
//     whenever the run ends because the Policy reports
//     ErrNoActionsRemain (one last Observation was still built to learn
//     that there was nothing left to do).
//   - ComputationalCostMS: real, measured wall-clock duration of the
//     entire Run call -- this project's established "measure real cost
//     separately from theoretical/structural counts" discipline
//     (internal/quantum.CircuitTrace), applied here to the agent itself.
type AgentReport struct {
	Attempts              int
	SuccessfulCompromises int
	TimeToCompromiseMS    *int64
	ObservationCount      int
	ActionCallCount       int
	ComputationalCostMS   int64
}

// Agent drives a bounded sequence of attack attempts against a single
// harness.Environment, through harness's own already-reviewed,
// already-isolated interfaces (Registry to resolve an ActionKind to a
// Scenario, Runner to execute it, Oracle -- via Environment -- to build
// each step's Observation). Agent introduces no new capability and no
// new path outside the simulator: everything it touches, a human
// operator driving the harness directly could touch the exact same way.
//
// "No uncontrolled autonomous execution": Run never loops unboundedly.
// It stops at whichever comes first of Budget steps, the ctx being
// cancelled, Policy reporting ErrNoActionsRemain, or a Scenario
// execution/resolution error (the only cases that return a non-nil
// error — an exhausted action set is a clean, expected stop, not one).
//
// Not safe for concurrent use (security review finding M4): call Run
// from one goroutine at a time, and do not read or mutate DecisionLog or
// any other exported field while a Run call is in flight --
// DeterministicPolicy's own internal state has the same restriction.
// The goroutines harness.Runner.Run spawns internally touch only Env,
// never Agent's own fields, so they do not make concurrent Run calls on
// ONE Agent safe.
//
// Running the SAME ActionKind more than once against ONE shared
// Environment -- whether via one Agent's Policy choosing it twice, or
// via two different Agents/Policies sharing the same Env -- is also not
// guaranteed safe (security review finding I4): several Milestone 8
// scenarios use a fixed, non-unique offending-entity ID, so a second
// genuine attempt against an already-tripped Detection Engine rule can
// report a false "undetected" result purely because of that rule's own
// per-entity dedup latch (see DeterministicPolicy's own doc comment for
// the original discovery of this class of bug). DeterministicPolicy
// avoids it FOR ITSELF by never choosing the same ActionKind twice, but
// Agent does not and cannot enforce this across multiple Agents sharing
// one Env, or against a different Policy that might choose differently
// -- give each Agent (or each experiment that might repeat an
// ActionKind) its own fresh Environment.
type Agent struct {
	Policy      Policy
	ActionKinds []ActionKind
	Registry    harness.Registry
	Env         *harness.Environment
	Budget      int
	DecisionLog []Decision

	// Clock defaults to time.Now but accepts an injected clock (e.g.
	// internal/testsupport.FixedClock) so Decision.Timestamp values are
	// reproducible in tests that need exact field-by-field comparison
	// (Task 45's reproducibility test). A nil Clock is treated as
	// time.Now by Run itself (security review finding M3) -- safe for an
	// Agent built as a bare struct literal, not only via NewAgent.
	Clock func() time.Time

	actionKindSet map[ActionKind]bool
}

// NewAgent constructs an Agent bounded to exactly actionKinds -- Run
// will never resolve or execute a Scenario whose ID isn't in that list,
// regardless of what else registry happens to hold.
func NewAgent(policy Policy, actionKinds []ActionKind, registry harness.Registry, env *harness.Environment, budget int) *Agent {
	kinds := append([]ActionKind(nil), actionKinds...)
	return &Agent{
		Policy:        policy,
		ActionKinds:   kinds,
		Registry:      registry,
		Env:           env,
		Budget:        budget,
		Clock:         time.Now,
		actionKindSet: actionKindSetFrom(kinds),
	}
}

func actionKindSetFrom(kinds []ActionKind) map[ActionKind]bool {
	set := make(map[ActionKind]bool, len(kinds))
	for _, k := range kinds {
		set[k] = true
	}
	return set
}

// Run executes up to Budget attack attempts: build an Observation from
// the current Oracle state ("result interpretation" -- every
// Observation after the first reflects everything every earlier step's
// Scenario execution actually did) -> ask Policy to Decide -> resolve
// the chosen ActionKind to a registered Scenario -> execute it via
// runner.Run(ctx, scenario, a.Env, seed+step) -> record the Decision ->
// repeat. seed makes every scenario's own internal randomness (e.g. a
// concurrent-overdraft race's goroutine timing) reproducible exactly as
// it already is for any other harness.Runner caller.
//
// DecisionLog is reset to this call's own decisions at the start of Run
// (security review finding M5): an earlier version left it accumulating
// across repeated Run calls on one Agent, inconsistent with AgentReport
// being freshly computed every call -- reuse an Agent across multiple
// Run calls only when "DecisionLog reflects the most recent Run" is the
// semantics you want; construct a fresh Agent per Run otherwise.
func (a *Agent) Run(ctx context.Context, runner harness.Runner, seed int64) ([]harness.Result, AgentReport, error) {
	if a.Clock == nil {
		a.Clock = time.Now
	}
	if a.actionKindSet == nil {
		a.actionKindSet = actionKindSetFrom(a.ActionKinds)
	}
	a.DecisionLog = nil

	start := time.Now()
	var results []harness.Result
	var report AgentReport
	var firstCompromiseMS *int64

	for step := 0; step < a.Budget; step++ {
		if err := ctx.Err(); err != nil {
			return results, a.finalizeReport(report, results, firstCompromiseMS, start), err
		}

		obs, err := a.buildObservation(ctx, step, start)
		if err != nil {
			// Security review finding M1: an Oracle read failure is a
			// genuine infrastructure problem, not "nothing to observe
			// this step" -- a Policy deciding from a silently-empty
			// Observation could make a wildly wrong decision with no
			// indication anything went wrong. Reported as a Run-level
			// error instead.
			return results, a.finalizeReport(report, results, firstCompromiseMS, start), fmt.Errorf("agent: step %d: build observation: %w", step, err)
		}
		report.ObservationCount++

		action, err := a.Policy.Decide(obs)
		if err != nil {
			// Security review finding M2: errors.Is, not ==, so a
			// Policy that wraps ErrNoActionsRemain (e.g.
			// fmt.Errorf("llm policy: %w", ErrNoActionsRemain), exactly
			// the pattern a future LLMPolicy would use per
			// docs/AGENT_LLM_INTEGRATION.md) is still recognized as the
			// same clean, expected stop condition.
			if errors.Is(err, ErrNoActionsRemain) {
				break
			}
			return results, a.finalizeReport(report, results, firstCompromiseMS, start), fmt.Errorf("agent: step %d: policy: %w", step, err)
		}

		a.DecisionLog = append(a.DecisionLog, Decision{Obs: obs, Action: action, Timestamp: a.Clock()})

		// Security review finding I1: Action.Kind MUST be checked
		// against a.ActionKinds before it is ever resolved against the
		// Registry -- an earlier version resolved directly via
		// Registry.ByID, so a Policy returning a Kind that was
		// registered in the harness but NOT in this Agent's own bounded
		// ActionKinds list was executed anyway, silently defeating the
		// one safety boundary NewAgent's own doc comment (and
		// docs/AGENT_LLM_INTEGRATION.md §1/§2.2) explicitly promised:
		// "the LLM cannot expand its own action space."
		if !a.actionKindSet[action.Kind] {
			return results, a.finalizeReport(report, results, firstCompromiseMS, start), fmt.Errorf("agent: step %d: action %q is outside this Agent's bounded ActionKinds", step, action.Kind)
		}

		scenario, ok := a.Registry.ByID(string(action.Kind))
		if !ok {
			return results, a.finalizeReport(report, results, firstCompromiseMS, start), fmt.Errorf("agent: step %d: action %q is not a registered scenario", step, action.Kind)
		}

		result, err := runner.Run(ctx, scenario, a.Env, seed+int64(step))
		// Security review finding M5: the partial Result is preserved
		// even when runner.Run itself errors (mirroring
		// internal/benchmark.RunComparative's own "never discard a
		// partial result" discipline) -- DecisionLog and results/
		// ActionCallCount stay in sync, and whatever runner.Run managed
		// to fill in (e.g. Attempts) before erroring is not lost.
		report.ActionCallCount++
		results = append(results, result)
		if result.Success && firstCompromiseMS == nil {
			ms := time.Since(start).Milliseconds()
			firstCompromiseMS = &ms
		}
		if err != nil {
			return results, a.finalizeReport(report, results, firstCompromiseMS, start), fmt.Errorf("agent: step %d: run %q: %w", step, action.Kind, err)
		}
	}

	return results, a.finalizeReport(report, results, firstCompromiseMS, start), nil
}

func (a *Agent) finalizeReport(report AgentReport, results []harness.Result, firstCompromiseMS *int64, start time.Time) AgentReport {
	report.Attempts = len(results)
	for _, r := range results {
		if r.Success {
			report.SuccessfulCompromises++
		}
	}
	report.TimeToCompromiseMS = firstCompromiseMS
	report.ComputationalCostMS = time.Since(start).Milliseconds()
	return report
}

// buildObservation reads a.Env.Oracle's current state into an
// Observation -- the only way an Agent ever learns anything about the
// simulator. Audit events and the ledger invariant are read fresh every
// step, so a later step's Observation genuinely reflects the
// consequences of every earlier step's Scenario execution.
//
// runStart bounds RecentAudit to events since THIS Run call began
// (security review finding I4): an earlier version passed time.Time{}
// to AuditEventsSince, so every Observation included every audit event
// ever recorded in this Environment's lifetime, not "since the Agent's
// Run began" as originally documented.
//
// Returns an error if the Oracle itself fails (security review finding
// M1) -- the caller must not treat that the same as "nothing to see."
func (a *Agent) buildObservation(ctx context.Context, step int, runStart time.Time) (Observation, error) {
	obs := Observation{StepsRemaining: a.Budget - step}

	snap, err := a.Env.Oracle.LedgerSnapshot(ctx)
	if err != nil {
		return Observation{}, fmt.Errorf("ledger snapshot: %w", err)
	}
	seen := make(map[domain.AccountID]bool)
	balances := make(map[domain.AccountID]domain.Money)
	for _, e := range snap.Entries {
		if !seen[e.AccountID] {
			seen[e.AccountID] = true
			obs.VisibleAccounts = append(obs.VisibleAccounts, e.AccountID)
		}
		balances[e.AccountID] += e.Amount
	}
	obs.VisibleBalances = balances

	events, err := a.Env.Oracle.AuditEventsSince(ctx, runStart)
	if err != nil {
		return Observation{}, fmt.Errorf("audit events since: %w", err)
	}
	obs.RecentAudit = events

	return obs, nil
}
