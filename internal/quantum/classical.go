package quantum

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ClassicalBaselineLabel is the disclosure every classical-cryptanalysis
// output in this file carries. Deliberately NOT SimulationLabel: these
// are genuine classical computations (trial division, baby-step
// giant-step), not simulations of anything -- labeling them as a
// "classical simulation of a quantum algorithm" would misdescribe them.
// They exist specifically so Shor/Grover's theoretical complexity claims
// have a real, measured classical baseline to be compared against (see
// docs/QUANTUM_METHODOLOGY.md).
const ClassicalBaselineLabel = "Classical cryptanalysis baseline (trial division / baby-step giant-step), included for direct comparison against this package's quantum-algorithm simulations. Uses deliberately small, insecure parameters. Not representative of real-world RSA/discrete-log hardness, and not run against this project's real cryptographic keys."

// ErrClassicalBoundExceeded is returned by RSAFactorTrialDivision/
// DiscreteLogBabyStepGiantStep above their documented bounds -- both
// algorithms are O(sqrt(n)), so an unbounded input could run for an
// impractically long time; bounded the same way Circuit bounds qubit
// count, never a silent slow-down with no explanation.
var ErrClassicalBoundExceeded = errors.New("quantum: classical cryptanalysis parameter bound exceeded")

// MaxRSAFactorModulus bounds RSAFactorTrialDivision's input: trial
// division is O(sqrt(n)), so this is generous for a toy/educational
// demonstration while staying well clear of "actually slow."
const MaxRSAFactorModulus = 1_000_000

// MaxDiscreteLogModulus bounds DiscreteLogBabyStepGiantStep's input:
// baby-step giant-step is O(sqrt(p)) in BOTH time and space (the
// baby-step hash table holds ~sqrt(p) entries).
const MaxDiscreteLogModulus = 1_000_000

// ClassicalTrace records what a classical cryptanalysis baseline
// actually did, mirroring CircuitTrace's separation of concerns for a
// REAL (non-simulated) algorithm:
//   - OperationCount is the actual number of elementary operations
//     performed (trial divisions attempted; baby-steps + giant-steps
//     computed) -- this IS the algorithm's real work, not a count of
//     "queries" against some other system.
//   - MeasuredCPUTimeMS is real, measured wall-clock time.
//   - Label is ClassicalBaselineLabel.
//
// Keeping OperationCount and MeasuredCPUTimeMS as two separate fields
// (rather than just reporting a duration) is the same "record oracle
// queries separately from actual CPU execution time" discipline
// CircuitTrace applies to Shor/Grover, extended to a baseline where
// there is no literal "oracle" -- OperationCount is this baseline's
// equivalent countable-step metric.
type ClassicalTrace struct {
	OperationCount    int
	MeasuredCPUTimeMS int64
	Label             string
}

// RSAFactorTrialDivision factors n by trial division -- testing each
// candidate divisor 2..floor(sqrt(n)) in order, the actual classical
// factoring algorithm it claims to be, not a shortcut around it.
// Returns the first nontrivial factor pair found (the smallest prime
// factor and its cofactor); for n with more than two prime factors,
// only that one split is reported (sufficient for this demo's toy RSA-
// modulus-shaped inputs, which are a product of exactly two primes).
func RSAFactorTrialDivision(ctx context.Context, n int) ([]int, ClassicalTrace, error) {
	start := time.Now()
	if n > MaxRSAFactorModulus {
		return nil, ClassicalTrace{}, fmt.Errorf("quantum: RSAFactorTrialDivision(%d): %w (max %d)", n, ErrClassicalBoundExceeded, MaxRSAFactorModulus)
	}
	if n < 4 {
		return nil, ClassicalTrace{}, fmt.Errorf("quantum: RSAFactorTrialDivision: n=%d is too small to have a nontrivial factor pair", n)
	}
	if err := ctx.Err(); err != nil {
		return nil, ClassicalTrace{}, err
	}

	operations := 0
	for d := 2; d*d <= n; d++ {
		if d%64 == 0 { // periodic cancellation check, not per-iteration (keeps the hot loop cheap)
			if err := ctx.Err(); err != nil {
				return nil, ClassicalTrace{}, err
			}
		}
		operations++
		if n%d == 0 {
			return []int{d, n / d}, ClassicalTrace{
				OperationCount:    operations,
				MeasuredCPUTimeMS: time.Since(start).Milliseconds(),
				Label:             ClassicalBaselineLabel,
			}, nil
		}
	}
	return nil, ClassicalTrace{
		OperationCount:    operations,
		MeasuredCPUTimeMS: time.Since(start).Milliseconds(),
		Label:             ClassicalBaselineLabel,
	}, fmt.Errorf("quantum: RSAFactorTrialDivision: %d is prime (or 1) -- no nontrivial factor exists", n)
}

// DiscreteLogBabyStepGiantStep finds the smallest x in [0, p-1) such
// that g^x ≡ h (mod p), via the standard baby-step giant-step algorithm:
// builds a hash table of baby steps {g^j mod p : j=0..m-1} (m=ceil(sqrt(p))),
// then searches giant steps h*(g^-m)^i mod p for i=0..m-1 against that
// table. Assumes p is prime and h actually has a discrete log base g
// within [0, p-1) (true whenever g generates the full group and h != 0);
// returns an error if no match is found within that range.
func DiscreteLogBabyStepGiantStep(ctx context.Context, g, h, p int) (int, ClassicalTrace, error) {
	start := time.Now()
	if p > MaxDiscreteLogModulus {
		return 0, ClassicalTrace{}, fmt.Errorf("quantum: DiscreteLogBabyStepGiantStep(p=%d): %w (max %d)", p, ErrClassicalBoundExceeded, MaxDiscreteLogModulus)
	}
	if err := ctx.Err(); err != nil {
		return 0, ClassicalTrace{}, err
	}

	m := 1
	for m*m < p {
		m++
	}

	operations := 0
	babySteps := make(map[int]int, m)
	cur := 1 % p
	for j := 0; j < m; j++ {
		operations++
		if _, exists := babySteps[cur]; !exists {
			babySteps[cur] = j
		}
		cur = (cur * g) % p
	}

	if err := ctx.Err(); err != nil {
		return 0, ClassicalTrace{}, err
	}

	// factor = g^(-m) mod p, via Fermat's little theorem (p assumed prime):
	// g^(p-1) ≡ 1 (mod p), so g^-1 ≡ g^(p-2) (mod p).
	gInv := modPow(g, p-2, p)
	factor := modPow(gInv, m, p)

	gamma := h % p
	if gamma < 0 {
		gamma += p
	}
	for i := 0; i < m; i++ {
		if i%64 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, ClassicalTrace{}, err
			}
		}
		operations++
		if j, ok := babySteps[gamma]; ok {
			x := i*m + j
			return x, ClassicalTrace{
				OperationCount:    operations,
				MeasuredCPUTimeMS: time.Since(start).Milliseconds(),
				Label:             ClassicalBaselineLabel,
			}, nil
		}
		gamma = (gamma * factor) % p
	}

	return 0, ClassicalTrace{
		OperationCount:    operations,
		MeasuredCPUTimeMS: time.Since(start).Milliseconds(),
		Label:             ClassicalBaselineLabel,
	}, fmt.Errorf("quantum: DiscreteLogBabyStepGiantStep: no x in [0,%d) satisfies %d^x ≡ %d (mod %d)", p-1, g, h, p)
}
