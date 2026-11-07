package quantum

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"
)

// ErrShorInputUnsupported is returned for any n outside the documented
// toy moduli {15, 21, 35} (docs/CRYPTOGRAPHY.md §5: internal/quantum
// only ever operates on small, fixed, documented toy inputs).
var ErrShorInputUnsupported = errors.New("quantum: Shor only supports the documented toy moduli {15, 21, 35}")

// ErrShorExhaustedAttempts is returned if every deterministically-tried
// candidate base exhausts shorMaxAttempts without yielding a nontrivial
// factor -- in practice this does not happen for {15, 21, 35} within the
// attempt budget, but Shor must report this honestly rather than loop
// forever or silently return a wrong answer.
var ErrShorExhaustedAttempts = errors.New("quantum: Shor exhausted its deterministic attempt budget without finding a nontrivial factor")

// shorSupportedModuli are the only inputs Shor accepts -- see
// docs/QUANTUM_METHODOLOGY.md for why only these three toy values.
var shorSupportedModuli = map[int]bool{15: true, 21: true, 35: true}

// shorMaxAttempts bounds how many candidate bases `a` Shor tries before
// giving up -- generous relative to {15,21,35}'s own typical 1-2 attempt
// requirement (deterministic choice of `a` and a 2*workBits+1-bit
// counting register together make failure rare for these toy moduli).
const shorMaxAttempts = 8

// Shor factors n (one of the documented toy moduli {15, 21, 35}) via a
// genuine simulation of the standard quantum order-finding algorithm:
// quantum phase estimation (QFT-based) applied to the modular
// multiplication unitary |y> -> |a*y mod n>, for a classically-chosen
// base `a` coprime to n. This is NOT a classical shortcut that calls a
// factoring routine directly -- the period r of a (mod n) is extracted
// from measuring a real simulated quantum circuit's counting register,
// exactly as the real algorithm does; only the final gcd-based factor
// extraction from r is classical post-processing, which is also true of
// the real algorithm.
//
// Reproducibility: per this project's deterministic-test-case
// requirement, the candidate base `a` is tried in a FIXED order
// (2, 3, 4, ...; never randomly chosen), and each (n, a) attempt seeds
// its own *rand.Rand deterministically from (n, a) rather than from
// wall-clock time -- so Shor(ctx, n) returns the exact same factors on
// every run for a given n, even though the underlying measurement
// process being simulated (Born-rule sampling) is genuinely
// probabilistic in general.
//
// See docs/QUANTUM_METHODOLOGY.md for what this experiment measures,
// what it does not, and why: in short, this demonstrates the ALGORITHM's
// logic correctly recovering a real modulus's factors at toy scale, and
// says nothing about this project's real cryptographic keys or about
// actual quantum hardware performance.
func Shor(ctx context.Context, n int) ([]int, CircuitTrace, error) {
	start := time.Now()
	if !shorSupportedModuli[n] {
		return nil, CircuitTrace{}, fmt.Errorf("%w: got %d", ErrShorInputUnsupported, n)
	}
	if err := ctx.Err(); err != nil {
		return nil, CircuitTrace{}, err
	}

	workBits := bitsFor(n)
	countBits := 2*workBits + 1
	totalQubits := workBits + countBits
	if totalQubits > MaxQubits {
		return nil, CircuitTrace{}, fmt.Errorf("quantum: Shor(%d) would need %d qubits, exceeding MaxQubits=%d", n, totalQubits, MaxQubits)
	}

	var oracleQueries, depth, attempts int
	for a := 2; a < n; a++ {
		if err := ctx.Err(); err != nil {
			return nil, CircuitTrace{}, err
		}
		if gcdInt(a, n) != 1 {
			continue
		}
		attempts++
		if attempts > shorMaxAttempts {
			break
		}

		rng := rand.New(rand.NewSource(int64(n)*1009 + int64(a)))
		r, queries, gateOps, err := quantumFindOrderCandidate(ctx, a, n, workBits, countBits, rng)
		if err != nil {
			return nil, CircuitTrace{}, err
		}
		oracleQueries += queries
		depth += gateOps
		if r == 0 || r%2 != 0 {
			continue // phase estimation didn't resolve a usable even period this attempt
		}

		half := modPow(a, r/2, n)
		factors := collectNontrivialFactorPair(gcdInt(half-1, n), gcdInt(half+1, n), n)
		if factors != nil {
			// Security review finding I4: Shor previously only checked
			// ctx BETWEEN whole attempts, so a deadline expiring mid
			// -attempt (each one is dozens of controlled-unitary
			// applications over a 2^19-amplitude state for n=35) was
			// ignored, and a "successful" result could be returned well
			// after the caller's own deadline. One last check here,
			// right before reporting success, closes that gap for the
			// attempt that actually found the factors (the loop inside
			// quantumFindOrderCandidate itself is also now checked --
			// see its own doc comment).
			if err := ctx.Err(); err != nil {
				return nil, CircuitTrace{}, err
			}
			return factors, CircuitTrace{
				QubitsUsed:            totalQubits,
				GateOperations:        depth,
				OracleQueries:         oracleQueries,
				SimulatedCPUTimeMS:    time.Since(start).Milliseconds(),
				TheoreticalComplexity: "O((log N)^3) elementary gate operations on real quantum hardware (Shor's algorithm's textbook asymptotic gate complexity) -- a theoretical statement, NOT measured by this classical simulation, whose own cost instead scales as O(2^qubits) in both time and memory",
				Label:                 SimulationLabel,
			}, nil
		}
	}

	return nil, CircuitTrace{
		QubitsUsed:         totalQubits,
		GateOperations:     depth,
		OracleQueries:      oracleQueries,
		SimulatedCPUTimeMS: time.Since(start).Milliseconds(),
		Label:              SimulationLabel,
	}, ErrShorExhaustedAttempts
}

// quantumFindOrderCandidate runs ONE attempt of the quantum phase
// estimation circuit for base a modulo n, and classically converts the
// measured phase into a candidate order r via continued-fraction
// convergents. Returns r=0 (not an error) if this attempt's measurement
// didn't yield any convergent denominator satisfying a^r ≡ 1 (mod n) --
// the caller then moves on to the next candidate base, exactly as the
// real algorithm retries with a different random base on failure.
//
// Checks ctx between each controlled-unitary application (security
// review finding I4): for n=35 this loop applies 13 permutation
// unitaries, each touching the full 2^19-amplitude state -- the
// expensive part of one attempt -- so a deadline expiring partway
// through was previously invisible until the whole attempt finished.
func quantumFindOrderCandidate(ctx context.Context, a, n, workBits, countBits int, rng *rand.Rand) (r, oracleQueries, gateOps int, err error) {
	totalQubits := workBits + countBits
	c, cerr := NewCircuitWithRand(totalQubits, rng)
	if cerr != nil {
		return 0, 0, 0, cerr
	}

	// Counting register occupies qubits [0, countBits); work register
	// occupies [countBits, countBits+workBits). Work register starts at
	// |1> (the standard choice for order-finding: a^0 * 1 = 1).
	c.ApplyX(countBits) // qubit countBits is bit 0 of the work register -> sets it to 1
	gateOps++

	countingQubits := make([]int, countBits)
	for j := 0; j < countBits; j++ {
		countingQubits[j] = j
		c.ApplyH(j)
		gateOps++
	}

	for j := 0; j < countBits; j++ {
		if err := ctx.Err(); err != nil {
			return 0, oracleQueries, gateOps, err
		}
		multiplier := modPow(a, 1<<uint(j), n)
		perm := controlledMulModPermutation(j, workBits, countBits, multiplier, n)
		c.ApplyPermutationUnitary(perm)
		oracleQueries++
		gateOps++
	}

	ApplyInverseQFT(c, countingQubits)
	gateOps += countBits // QFT's own elementary-gate count is tracked at this granularity, not gate-by-gate

	measured := c.MeasureAll()
	countingValue := measured & ((1 << uint(countBits)) - 1)

	for _, candidate := range continuedFractionDenominators(countingValue, 1<<uint(countBits), n) {
		if candidate > 0 && modPow(a, candidate, n) == 1 {
			return candidate, oracleQueries, gateOps, nil
		}
	}
	return 0, oracleQueries, gateOps, nil
}

// controlledMulModPermutation returns the basis-index permutation
// implementing |work> -> |work * multiplier mod n>, controlled on
// countQubit, with the work register located at bits
// [workOffset, workOffset+workBits) of the full circuit index. Indices
// whose work-register value is >= n (outside the meaningful [0,n)
// subspace -- never actually populated, since the work register starts
// at |1> < n and multiplication mod n always stays within [0,n)) map to
// themselves, which keeps the permutation well-defined and bijective
// over the FULL 2^(workBits) range ApplyPermutationUnitary requires,
// without ever needing to be exercised.
func controlledMulModPermutation(countQubit, workBits, workOffset, multiplier, n int) func(int) int {
	controlBit := 1 << countQubit
	workMask := (1 << uint(workBits)) - 1
	return func(x int) int {
		if x&controlBit == 0 {
			return x
		}
		work := (x >> uint(workOffset)) & workMask
		if work >= n {
			return x
		}
		newWork := (work * multiplier) % n
		return (x &^ (workMask << uint(workOffset))) | (newWork << uint(workOffset))
	}
}

// continuedFractionDenominators returns the successive convergent
// denominators of the continued-fraction expansion of numerator/denominator,
// stopping once a denominator exceeds maxDenom -- the standard classical
// post-processing step that turns a quantum phase-estimation measurement
// into a candidate period.
func continuedFractionDenominators(numerator, denominator, maxDenom int) []int {
	var out []int
	n, d := numerator, denominator
	hPrev, hPrevPrev := 1, 0
	kPrev, kPrevPrev := 0, 1
	for d != 0 {
		q := n / d
		n, d = d, n%d
		h := q*hPrev + hPrevPrev
		k := q*kPrev + kPrevPrev
		hPrevPrev, hPrev = hPrev, h
		kPrevPrev, kPrev = kPrev, k
		if k > maxDenom {
			break
		}
		if k > 0 {
			out = append(out, k)
		}
	}
	return out
}

// collectNontrivialFactorPair returns [f, n/f] for whichever of f1/f2 is
// a nontrivial factor of n (1 < f < n), or nil if neither is.
func collectNontrivialFactorPair(f1, f2, n int) []int {
	for _, f := range []int{f1, f2} {
		if f > 1 && f < n {
			return []int{f, n / f}
		}
	}
	return nil
}

// bitsFor returns ceil(log2(n)) for n > 0.
func bitsFor(n int) int {
	bits := 0
	for (1 << uint(bits)) < n {
		bits++
	}
	return bits
}

// gcdInt returns the greatest common divisor of a and b (both treated
// as non-negative; gcdInt(0, b) == b).
func gcdInt(a, b int) int {
	if a < 0 {
		a = -a
	}
	if b < 0 {
		b = -b
	}
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// modPow returns base^exp mod m via classical repeated squaring. This
// is ordinary classical arithmetic, used here only to (a) classically
// precompute each controlled oracle's multiplier a^(2^j) mod n -- the
// real algorithm's own classical pre-processing step, not a shortcut
// around the quantum part -- and (b) classically verify a candidate
// period in quantumFindOrderCandidate/Shor's post-processing.
func modPow(base, exp, m int) int {
	if m == 1 {
		return 0
	}
	result := 1
	base = base % m
	for exp > 0 {
		if exp&1 == 1 {
			result = (result * base) % m
		}
		exp >>= 1
		base = (base * base) % m
	}
	return result
}
