package harness

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

// Result is the attack harness's common result schema. This is
// Milestone 11's "common result schema" (DEPENDENCY_GRAPH.md rule 2):
// benchmarking extends/aggregates it, it is never redefined there.
// Fields not applicable to a given scenario stay nil, never a
// fabricated zero -- see applyEvidence.
type Result struct {
	AttackID            string
	TargetConfiguration string // "vulnerable" | "hardened"
	AttackType          string
	Success             bool
	ExecutionTimeMS     int64
	TimeToCompromiseMS  *int64
	DataLeakedBytes     *int64
	RecordsCompromised  *int64
	DetectionLatencyMS  *int64
	Attempts            int
	ComputationalCost   *int64
	MemoryUsageBytes    *int64
	Seed                *int64
}

// Evidence keys a Scenario's Verify step may set; the Runner copies
// whichever of these are present into the matching Result field.
const (
	EvidenceTimeToCompromiseMS = "time_to_compromise_ms"
	EvidenceDataLeakedBytes    = "data_leaked_bytes"
	EvidenceRecordsCompromised = "records_compromised"
	EvidenceDetectionLatencyMS = "detection_latency_ms"
	EvidenceComputationalCost  = "computational_cost"
	EvidenceMemoryUsageBytes   = "memory_usage_bytes"
)

// defaultMaxAttempts bounds a scenario with a StopCond that never
// returns true (e.g. a bug, or a deliberately hostile Scenario) -- a
// backstop beneath the per-attempt ctx/Timeout handling, since StopCond
// alone has no other bound.
const defaultMaxAttempts = 100000

// Runner executes a Scenario against an Environment and adjudicates the
// outcome via the Oracle. It never trusts Exec's own return value as
// evidence of success -- only what Verify observes through the Oracle
// counts (see framework_test.go's
// TestRunner_NeverTrustsExecClaimOverOracle).
type Runner interface {
	Run(ctx context.Context, s Scenario, env *Environment, seed int64) (Result, error)
}

type runner struct{}

// NewRunner constructs a Runner.
func NewRunner() Runner { return &runner{} }

func (r *runner) Run(ctx context.Context, s Scenario, env *Environment, seed int64) (result Result, err error) {
	result = Result{
		AttackID:            s.ID,
		TargetConfiguration: env.Profile.Name,
		AttackType:          s.Category,
		Seed:                &seed,
	}
	start := time.Now()
	// Named return values: result is what the caller actually gets back
	// from every return statement below, so this deferred assignment
	// reaches them all (security review finding C2 -- the previous
	// local, non-named `result` variable was already copied into the
	// return value before this ran, so ExecutionTimeMS stayed 0 always).
	defer func() { result.ExecutionTimeMS = time.Since(start).Milliseconds() }()

	if s.Verify == nil {
		return result, fmt.Errorf("scenario %s: Verify must not be nil -- Runner never trusts Exec's own claim, so a Scenario with no way to adjudicate success cannot be run", s.ID)
	}

	if s.Prereqs != nil {
		ok, perr := runPrereqsRecovered(ctx, s, env.Oracle)
		if perr != nil {
			return result, fmt.Errorf("scenario %s: prereqs: %w", s.ID, perr)
		}
		if !ok {
			return result, nil
		}
	}

	for attempt := 0; ; attempt++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return result, fmt.Errorf("scenario %s: %w", s.ID, ctxErr)
		}
		if result.Attempts >= defaultMaxAttempts {
			return result, fmt.Errorf("scenario %s: exceeded max attempts (%d) without StopCond returning true", s.ID, defaultMaxAttempts)
		}
		result.Attempts++

		// Each attempt gets its own rand source, deterministically
		// derived from seed and the attempt number: reproducible given
		// the same seed, and never shared with a goroutine that might
		// outlive this attempt (security review finding I2 -- a single
		// rand.Rand shared across attempts was a data race whenever a
		// prior attempt's Exec leaked past its own deadline into a later
		// attempt).
		attemptRnd := rand.New(rand.NewSource(seed + int64(attempt)))

		execCtx := ctx
		var cancel context.CancelFunc
		if s.Timeout > 0 {
			execCtx, cancel = context.WithTimeout(ctx, s.Timeout)
		}

		// execErr is never used to decide Success: a real attacker's own
		// claim that Exec "worked" proves nothing by itself -- only what
		// Verify actually observes through the Oracle counts.
		_ = runExecWithDeadline(execCtx, s, env, attemptRnd)

		// Verify runs under the same execCtx as Exec: Scenario.Timeout's
		// doc comment says it "bounds one Exec+Verify attempt", so Verify
		// must be bounded too, not only Exec (security review finding
		// I1).
		success, evidence, verr := runVerifyWithDeadline(execCtx, s, env)
		if cancel != nil {
			cancel()
		}
		if verr != nil {
			return result, fmt.Errorf("scenario %s: verify: %w", s.ID, verr)
		}

		result.Success = success
		resetEvidenceFields(&result)
		if applyErr := applyEvidence(&result, evidence); applyErr != nil {
			return result, fmt.Errorf("scenario %s: %w", s.ID, applyErr)
		}

		stop := true
		if s.StopCond != nil {
			stop, err = runStopCondRecovered(s, evidence)
			if err != nil {
				return result, fmt.Errorf("scenario %s: stopcond: %w", s.ID, err)
			}
		}
		if stop {
			return result, nil
		}
	}
}

// runExecWithDeadline runs s.Exec in its own goroutine so a genuinely
// hung or ctx-ignoring Exec still lets Run return at ctx's deadline
// (leaking that one goroutine -- an accepted, documented tradeoff for a
// harness that must survive a deliberately or accidentally
// non-cooperative attack implementation) rather than hanging the whole
// run. The goroutine is tracked on env so Environment.Close can give it
// a bounded grace period before tearing down the stores it may still be
// using (security review finding I3).
func runExecWithDeadline(ctx context.Context, s Scenario, env *Environment, rnd *rand.Rand) error {
	if s.Exec == nil {
		return nil
	}
	done := make(chan error, 1)
	untrack := env.trackGoroutine()
	go func() {
		defer untrack()
		done <- runExecRecovered(ctx, s, env, rnd)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runExecRecovered converts a panic in Exec into a returned error
// instead of crashing the whole harness run.
func runExecRecovered(ctx context.Context, s Scenario, env *Environment, rnd *rand.Rand) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("scenario %s: exec panicked: %v", s.ID, r)
		}
	}()
	return s.Exec(ctx, env.Client, env.Priv, rnd)
}

// runVerifyWithDeadline mirrors runExecWithDeadline for Verify (see its
// doc comment): the same goroutine-raced deadline enforcement and
// goroutine tracking, since Verify is just as capable of hanging or
// panicking as Exec, and Timeout is documented to bound both.
func runVerifyWithDeadline(ctx context.Context, s Scenario, env *Environment) (success bool, evidence Evidence, err error) {
	type outcome struct {
		success  bool
		evidence Evidence
		err      error
	}
	done := make(chan outcome, 1)
	untrack := env.trackGoroutine()
	go func() {
		defer untrack()
		success, evidence, err := runVerifyRecovered(ctx, s, env.Oracle)
		done <- outcome{success, evidence, err}
	}()
	select {
	case o := <-done:
		return o.success, o.evidence, o.err
	case <-ctx.Done():
		return false, nil, ctx.Err()
	}
}

// runVerifyRecovered converts a panic in Verify into a returned error
// instead of crashing the whole harness run (security review finding
// C3 -- only Exec's panics were recovered before).
func runVerifyRecovered(ctx context.Context, s Scenario, o Oracle) (success bool, evidence Evidence, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("scenario %s: verify panicked: %v", s.ID, r)
		}
	}()
	return s.Verify(ctx, o)
}

// runPrereqsRecovered and runStopCondRecovered close the rest of finding
// C3: Prereqs and StopCond are ordinary Scenario-supplied functions too,
// just as capable of panicking as Exec/Verify, but (unlike those two)
// are expected to be quick checks rather than potentially-blocking
// attack code, so they are not goroutine-raced against a deadline --
// only recovered.
func runPrereqsRecovered(ctx context.Context, s Scenario, o Oracle) (ok bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("scenario %s: prereqs panicked: %v", s.ID, r)
		}
	}()
	return s.Prereqs(ctx, o)
}

func runStopCondRecovered(s Scenario, evidence Evidence) (stop bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("scenario %s: stopcond panicked: %v", s.ID, r)
		}
	}()
	return s.StopCond(evidence), nil
}

// resetEvidenceFields clears every evidence-derived Result field before
// a fresh Verify call -- security review finding M2: applyEvidence only
// ever set fields, never cleared them, so Evidence from a prior attempt
// could survive, misattributed, into a later attempt's Result even
// though that later attempt's own Evidence said nothing about it.
func resetEvidenceFields(result *Result) {
	result.TimeToCompromiseMS = nil
	result.DataLeakedBytes = nil
	result.RecordsCompromised = nil
	result.DetectionLatencyMS = nil
	result.ComputationalCost = nil
	result.MemoryUsageBytes = nil
}

// applyEvidence copies whichever of the well-known Evidence keys are
// present into the matching Result field. A key that is absent leaves
// its field nil (not applicable to this scenario); a key that is
// present but holds a value applyEvidence cannot interpret as an
// integer is an error, not a silent no-op -- indistinguishable from
// "absent" would hide a real bug in the Scenario's own Verify (security
// review finding M1).
func applyEvidence(result *Result, evidence Evidence) error {
	fields := []struct {
		key string
		dst **int64
	}{
		{EvidenceTimeToCompromiseMS, &result.TimeToCompromiseMS},
		{EvidenceDataLeakedBytes, &result.DataLeakedBytes},
		{EvidenceRecordsCompromised, &result.RecordsCompromised},
		{EvidenceDetectionLatencyMS, &result.DetectionLatencyMS},
		{EvidenceComputationalCost, &result.ComputationalCost},
		{EvidenceMemoryUsageBytes, &result.MemoryUsageBytes},
	}
	for _, f := range fields {
		v, ok := evidence[f.key]
		if !ok {
			continue
		}
		n, ok := toInt64(v)
		if !ok {
			return fmt.Errorf("evidence key %q has unsupported type %T (want an integer)", f.key, v)
		}
		val := n
		*f.dst = &val
	}
	return nil
}

// toInt64 accepts every common integer kind, plus an integral float64
// (e.g. from a JSON-decoded source), and reports false for anything
// else.
func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case uint:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), true
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
		return 0, false
	default:
		return 0, false
	}
}
