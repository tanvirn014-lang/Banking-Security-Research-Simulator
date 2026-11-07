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

	iterations := int(math.Floor(math.Pi / 4 * math.Sqrt(float64(n)/float64(m))))
	if iterations < 1 {
		iterations = 1
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

	return result, CircuitTrace{
		QubitsUsed:            searchSpaceBits,
		CircuitDepth:          depth,
		OracleQueries:         oracleQueries,
		SimulatedCPUTimeMS:    time.Since(start).Milliseconds(),
		TheoreticalComplexity: "O(sqrt(N)) oracle queries on real quantum hardware for a single marked element, vs. O(N) for exhaustive classical search (Grover's algorithm's textbook asymptotic query complexity) -- a theoretical statement, NOT measured by this classical simulation, which pays O(N) PER iteration just to apply one simulated oracle query over the full amplitude vector",
		Label:                 SimulationLabel,
	}, nil
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
func ComplexityReport(searchSpaceBits int) (classicalExpectedOps, quantumExpectedOps int) {
	n := 1 << uint(searchSpaceBits)
	classicalExpectedOps = n
	quantumExpectedOps = int(math.Ceil(math.Pi / 4 * math.Sqrt(float64(n))))
	return classicalExpectedOps, quantumExpectedOps
}
