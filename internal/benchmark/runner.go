// Package benchmark orchestrates repeated, controlled-seed, vulnerable
// -vs-hardened comparative runs of internal/harness Scenarios, per
// docs/BENCHMARK_METHODOLOGY.md, and aggregates/exports the results.
// It reuses harness.Result as-is for every run's own measurements
// (DEPENDENCY_GRAPH.md rule 2: the common result schema lives in
// internal/harness, never redefined here) -- RawRun only ADDS
// benchmark-level bookkeeping (a RunID, a real wall-clock Timestamp, and
// its OWN ScenarioID/Mode labels -- see RawRun's own doc comment on why
// those are not simply read back from harness.Result) around an
// unmodified harness.Result.
package benchmark

import (
	"context"
	"errors"
	"fmt"
	"time"

	"banksec-lab/internal/config"
	"banksec-lab/internal/harness"
)

// RawRun is one benchmark run's complete record: harness.Result exactly
// as the Runner produced it (including a non-nil RunErr when Run itself
// returned an error -- "preserve every raw run... including failures"
// per BENCHMARK_METHODOLOGY.md §1/§2), plus the benchmark-level
// bookkeeping BENCHMARK_METHODOLOGY.md §6 requires for the export
// format.
//
// ScenarioID and Mode are RunComparative's OWN labels for what it just
// ran -- "ledger-tamper" / "vulnerable" -- deliberately NOT read back
// from Result.AttackID/Result.TargetConfiguration (security review
// finding I2/I3): when RunErr != nil, Result can be its zero value
// (AttackID=="", TargetConfiguration==""), which would otherwise group
// an errored run into its own anonymous, scenario-less bucket in
// Summarize; and TargetConfiguration is populated from
// Environment.Profile.Name, which collides silently if a caller ever
// passes two SecurityProfiles with the same Name (RunComparative now
// rejects that case outright -- see its own doc comment). ScenarioID/
// Mode are always correct, regardless of what Result contains.
type RawRun struct {
	ScenarioID string
	Mode       string
	RunID      string
	Timestamp  time.Time
	Result     harness.Result
	// RunErr is the error (if any) harness.Runner.Run itself returned
	// for this specific run -- e.g. a Scenario with a nil Verify, or a
	// ctx deadline mid-run. Result is still recorded alongside it
	// (whatever harness.Runner.Run managed to fill in before erroring),
	// never discarded just because the run didn't complete cleanly.
	RunErr error
}

// RawResults is every raw run RunComparative collected, in execution
// order -- never filtered, never reduced to only successes.
type RawResults []RawRun

// ErrDuplicateModeNames is returned by RunComparative when vulnerable
// and hardened have the same Name -- security review finding I3: RawRun
// records BOTH profiles' runs under their own fixed "vulnerable"/
// "hardened" Mode labels regardless of Name, but harness.Result's own
// TargetConfiguration field (sourced from Environment.Profile.Name)
// would be IDENTICAL for both if their Names collided, silently erasing
// the one piece of per-run data that actually says which profile ran.
// Rejected outright rather than allowed to produce confusing output.
var ErrDuplicateModeNames = errors.New("benchmark: vulnerable and hardened profiles must have different Name values")

// RunComparative executes a FRESH Scenario instance (built by calling
// newScenario) reps times under each of vulnerable and hardened, per
// BENCHMARK_METHODOLOGY.md §2: for each rep, a FRESH harness.Environment
// is built under vulnerable and run with seed+rep, then a FRESH
// Environment is built under hardened and run with the SAME seed+rep --
// "never an incidental difference in starting data" between the two
// modes within one rep (only the profile differs).
//
// newScenario is called ONCE PER RUN (not once per rep, not once total)
// -- security review finding C1 (Critical): an earlier version of this
// function took a single harness.Scenario VALUE and reused it across
// every run. Several Milestone 8 scenarios carry closure state
// (tamperAttempted, stolenBytes, getAttempted, ...) that a SINGLE
// Scenario value accumulates across calls; reusing one instance meant a
// run whose Exec failed (e.g. because the preceding run's Environment
// was still being torn down, or any other infrastructure hiccup) could
// silently inherit the PREVIOUS run's leftover state and report a
// clean, WRONG result -- concretely reproduced as a false "successful
// key compromise" under hardened, copied from an unrelated prior
// vulnerable run. newScenario mirrors harness.Registry's own
// factory-per-lookup design (the same fix applied to the exact same
// class of bug when it was first found in Registry, security review
// finding I2 from Milestone 8's review) -- pass a Scenario constructor
// function (e.g. harness.NewLedgerTamperScenario) or a closure around
// reg.ByID(id), never a pre-built Scenario value.
//
// Every raw run is preserved, including one whose Run call itself
// returned an error (RawRun.RunErr) -- RunComparative itself only
// returns a non-nil error for something that prevents the EXPERIMENT
// from proceeding at all (ctx cancellation, mismatched profile Names, or
// failing to even construct an Environment), never for an individual
// run's own failure.
func RunComparative(ctx context.Context, h harness.Runner, newScenario func() harness.Scenario, vulnerable, hardened config.SecurityProfile, reps int, seed int64) (RawResults, error) {
	if vulnerable.Name == hardened.Name {
		return nil, fmt.Errorf("%w: both are %q", ErrDuplicateModeNames, vulnerable.Name)
	}

	var raw RawResults
	for rep := 0; rep < reps; rep++ {
		if err := ctx.Err(); err != nil {
			return raw, err
		}
		runSeed := seed + int64(rep)

		vulnRun, err := runOnce(ctx, h, newScenario(), vulnerable, runSeed, rep, "vulnerable")
		if err != nil {
			return raw, err
		}
		raw = append(raw, vulnRun)

		if err := ctx.Err(); err != nil {
			return raw, err
		}

		hardRun, err := runOnce(ctx, h, newScenario(), hardened, runSeed, rep, "hardened")
		if err != nil {
			return raw, err
		}
		raw = append(raw, hardRun)
	}
	return raw, nil
}

// runOnce builds one fresh Environment under profile, runs s (a FRESH
// instance -- see RunComparative's own doc comment) through it, and
// returns the resulting RawRun. The only error it returns is one that
// prevents the Environment itself from being built or cleanly torn down
// (e.g. a temp-dir failure) -- a failure WITHIN the run (Run itself
// erroring) is captured as RawRun.RunErr and returned normally, per
// RunComparative's own doc comment.
func runOnce(ctx context.Context, h harness.Runner, s harness.Scenario, profile config.SecurityProfile, seed int64, rep int, mode string) (result RawRun, err error) {
	env, err := harness.NewLocalEnvironment(profile)
	if err != nil {
		return RawRun{}, fmt.Errorf("benchmark: build %s environment for rep %d: %w", mode, rep, err)
	}
	defer func() {
		// Security review finding M8: a failure tearing down the
		// Environment (e.g. a locked temp file on Windows) was
		// previously silently discarded. Surfaced as this call's own
		// error only when the run itself didn't already report one --
		// an environment-teardown problem shouldn't mask a more
		// informative run-level error, but also shouldn't be lost
		// entirely when there is no run-level error to prioritize.
		if cerr := env.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("benchmark: close %s environment for rep %d: %w", mode, rep, cerr)
		}
	}()

	timestamp := time.Now()
	res, runErr := h.Run(ctx, s, env, seed)

	return RawRun{
		ScenarioID: s.ID,
		Mode:       mode,
		RunID:      fmt.Sprintf("%s-%s-rep%d-seed%d", s.ID, mode, rep, seed),
		Timestamp:  timestamp,
		Result:     res,
		RunErr:     runErr,
	}, nil
}
