package quantum

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"time"
)

// ErrGroverNoMarkedElements is returned when oracle marks nothing in
// the search space: Grover's amplitude amplification has nothing to
// amplify toward, and running it anyway would just return an
// arbitrary, meaningless index.
var ErrGroverNoMarkedElements = errors.New("quantum: Grover's oracle marks no elements in the search space")

// ErrGroverMeasurementUnmarked is returned when the final measurement
// lands on a basis state the oracle does NOT mark -- a genuine,
// honestly-reported outcome of a probabilistic algorithm (Grover's own
// success probability is never exactly 1, especially when M > N/2; see
// this function's own doc comment), never silently swallowed into a
// false "success" the way Milestone 9 security review finding I1 found
// it previously was.
var ErrGroverMeasurementUnmarked = errors.New("quantum: Grover's final measurement did not land on an oracle-marked element")

// Grover searches an unstructured space of 2^searchSpaceBits elements
// for one marked by oracle, via a genuine simulation of amplitude
// amplification: uniform superposition (H on every qubit), then
// floor(pi/4 * sqrt(N/M)) iterations of [ApplyPhaseOracle(oracle),
// ApplyDiffusion()] (see circuit.go's doc comments on both), then a
// single MeasureAll.
//
// Disclosed simplification (also in docs/QUANTUM_METHODOLOGY.md): the
// optimal iteration count needs M, the number of marked elements. Real
// Grover usage either assumes M known or estimates it via quantum
// counting (not implemented here). This function classically pre-scans
// oracle over all N inputs once to determine M before building the
// circuit -- that pre-scan is NOT included in the returned
// CircuitTrace.OracleQueries, since it is this toy demo's own classical
// bookkeeping shortcut, not part of the O(sqrt(N/M)) theoretical query
// complexity being demonstrated.
//
// Deterministic by construction: NewCircuitWithRand is seeded from
// searchSpaceBits and M rather than wall-clock time, so a given
// (searchSpaceBits, oracle) pair returns the same result on every run
// whenever M (the number of marked elements) is the same.
func Grover(ctx context.Context, searchSpaceBits int, oracle func(x int) bool) (int, CircuitTrace, error) {
	start := time.Now()
	if err := ctx.Err(); err != nil {
		return 0, CircuitTrace{}, err
	}
	if searchSpaceBits < 0 || searchSpaceBits > MaxQubits {
		return 0, CircuitTrace{}, fmt.Errorf("quantum: Grover: %w", ErrQubitBoundExceeded)
	}

	n := 1 << uint(searchSpaceBits)
	m := 0
	for x := 0; x < n; x++ {
		if x%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, CircuitTrace{}, err
			}
		}
		if oracle(x) {
			m++
		}
	}
	if m == 0 {
		return 0, CircuitTrace{}, ErrGroverNoMarkedElements
	}
	if err := ctx.Err(); err != nil {
		return 0, CircuitTrace{}, err
	}

	// Security review finding I1: floor(pi/4*sqrt(N/M)), forced up to a
	// minimum of 1, OVERSHOOTS once M > N/2 -- the rotation angle per
	// iteration grows with M, so even 1 iteration can rotate PAST the
	// optimal point and drive the success probability toward 0 (the
	// review's own reproduction: bits=2, M=3 of N=4, 1 forced iteration,
	// exact success probability 0). When more than half the space is
	// already marked, amplitude amplification provides no benefit at
	// all -- the uniform superposition's OWN success probability (M/N)
	// already exceeds 50%, and any amplification iteration only makes it
	// worse. So: 0 iterations whenever M > N/2 (measure the uniform
	// superposition directly), the textbook formula otherwise.
	var iterations int
	if m > n/2 {
		iterations = 0
	} else {
		iterations = int(math.Floor(math.Pi / 4 * math.Sqrt(float64(n)/float64(m))))
		if iterations < 1 {
			iterations = 1
		}
	}

	rng := rand.New(rand.NewSource(int64(searchSpaceBits)*1013 + int64(m)))
	c, err := NewCircuitWithRand(searchSpaceBits, rng)
	if err != nil {
		return 0, CircuitTrace{}, err
	}

	for q := 0; q < searchSpaceBits; q++ {
		c.ApplyH(q)
	}

	var oracleQueries, depth int
	depth += searchSpaceBits // the initial H layer
	for i := 0; i < iterations; i++ {
		if err := ctx.Err(); err != nil {
			return 0, CircuitTrace{}, err
		}
		c.ApplyPhaseOracle(oracle)
		c.ApplyDiffusion()
		oracleQueries++
		depth += 2
	}

	result := c.MeasureAll()

	trace := CircuitTrace{
		QubitsUsed:            searchSpaceBits,
		GateOperations:        depth,
		OracleQueries:         oracleQueries,
		SimulatedCPUTimeMS:    time.Since(start).Milliseconds(),
		TheoreticalComplexity: "O(sqrt(N)) oracle queries on real quantum hardware for a single marked element, vs. O(N) for exhaustive classical search (Grover's algorithm's textbook asymptotic query complexity) -- a theoretical statement, NOT measured by this classical simulation, which pays O(N) PER iteration just to apply one simulated oracle query over the full amplitude vector",
		Label:                 SimulationLabel,
	}

	// Security review finding I1: Grover is a PROBABILISTIC algorithm --
	// its own success probability is never exactly 1 (worst case exactly
	// 0, as the M>N/2 overshoot above demonstrated before being fixed).
	// This classical simulation reports that honestly: the measured
	// result is verified against the real oracle before being returned
	// as a success, exactly as docs/QUANTUM_METHODOLOGY.md's "never claim
	// success you haven't verified" standard already applies to every
	// other experiment in this package. A real quantum computer running
	// Grover would face the exact same genuine chance of an unmarked
	// measurement -- this is not a simulation artifact to paper over.
	if !oracle(result) {
		return result, trace, fmt.Errorf("%w (measured %d)", ErrGroverMeasurementUnmarked, result)
	}
	return result, trace, nil
}

// ComplexityReport returns the PURE, theoretical expected operation
// counts for an exhaustive classical search (classicalExpectedOps = N)
// versus Grover's algorithm on real quantum hardware for a single
// marked element (quantumExpectedOps = ceil(pi/4 * sqrt(N))) over a
// search space of 2^searchSpaceBits elements.
//
// This performs NO simulation and calls no oracle -- it is a direct
// arithmetic calculation of known textbook asymptotic formulas, never
// derived from any Grover run's own measurements. Per the user's
// explicit "compare theoretical scaling without fabricating performance
// improvements" requirement, this is the only place in this package
// that reports a classical-vs-quantum comparison, and it is always
// theoretical, never a claim about this simulation's own (always
// classically-run, always slower-growing-worse) measured performance.
//
// Bounded to the same [0, MaxQubits] range Circuit itself enforces
// (security review finding M3): searchSpaceBits=63 previously computed
// `1 << 63` as a negative int64 (overflow), 64 and -1 both silently gave
// (0, 0), and none of these were ever realistic search-space sizes this
// package's own Grover could run anyway. Returns ErrQubitBoundExceeded
// outside that range rather than silently returning nonsense -- an
// added error return (a disclosed deviation from the plan's bare
// two-value signature).
func ComplexityReport(searchSpaceBits int) (classicalExpectedOps, quantumExpectedOps int, err error) {
	if searchSpaceBits < 0 || searchSpaceBits > MaxQubits {
		return 0, 0, fmt.Errorf("quantum: ComplexityReport: %w", ErrQubitBoundExceeded)
	}
	n := 1 << uint(searchSpaceBits)
	classicalExpectedOps = n
	quantumExpectedOps = int(math.Ceil(math.Pi / 4 * math.Sqrt(float64(n))))
	return classicalExpectedOps, quantumExpectedOps, nil
}
