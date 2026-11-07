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

// ErrRSAInputTooSmall and ErrRSAInputIsPrime are sentinel errors for
// RSAFactorTrialDivision's two failure modes -- security review finding
// M7: previously neither case used a sentinel, so callers had no way to
// distinguish "n is too small to factor at all" from "n is prime" via
// errors.Is, and the prime-case message claimed to also cover n=1, which
// can never reach that branch (n<4 is rejected earlier).
var (
	ErrRSAInputTooSmall = errors.New("quantum: RSAFactorTrialDivision: input too small to have a nontrivial factor pair")
	ErrRSAInputIsPrime  = errors.New("quantum: RSAFactorTrialDivision: input is prime")
)

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
		return nil, ClassicalTrace{}, fmt.Errorf("%w: n=%d is too small to have a nontrivial factor pair", ErrRSAInputTooSmall, n)
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
	}, fmt.Errorf("%w: %d is prime -- no nontrivial factor exists", ErrRSAInputIsPrime, n)
}

// ErrDiscreteLogInvalidInput is returned for a modulus/base
// DiscreteLogBabyStepGiantStep cannot honestly operate on: p < 2 (no
// nontrivial group), or g ≡ 0 (mod p) (0 has no well-defined discrete
// log -- 0^x = 0 for every x >= 1, so it can never equal a nonzero h,
// and the algorithm's own modular-inverse step is undefined for it).
var ErrDiscreteLogInvalidInput = errors.New("quantum: DiscreteLogBabyStepGiantStep: invalid g or p")

// DiscreteLogBabyStepGiantStep finds the smallest x in [0, p-1) such
// that g^x ≡ h (mod p), via the standard baby-step giant-step algorithm:
// builds a hash table of baby steps {g^j mod p : j=0..m-1} (m=ceil(sqrt(p))),
// then searches giant steps h*(g^-m)^i mod p for i=0..m-1 against that
// table.
//
// Fixed per Milestone 9 security review finding I2 (four bugs in one):
//  1. g and h are both reduced into [0, p) up front (g was previously
//     used as-is, so a negative g incorrectly reported "no solution" and
//     a sufficiently large g could overflow int64 in cur*g).
//  2. g ≡ 0 (mod p) is rejected outright (ErrDiscreteLogInvalidInput) --
//     previously, modPow(0, p-2, p) = 0 made the "modular inverse" step
//     collapse every giant-step entry onto the same (wrong) value,
//     silently returning an incorrect x.
//  3. p < 2 is rejected outright (previously p=0 panicked with an
//     integer divide-by-zero in `1 % p`, and a negative p produced a
//     nonsensical error message rather than a clean rejection).
//  4. The candidate x this algorithm finds is now VERIFIED
//     (g^x ≡ h (mod p)) before being returned as a success -- the
//     g^-1 ≡ g^(p-2) (mod p) step is only valid when p is PRIME (Fermat's
//     little theorem); for a composite p it can silently produce a wrong
//     x. This function does not reject composite p outright (detecting
//     primality is its own cost this toy baseline doesn't need to pay),
//     but this final verification step means a wrong candidate is now
//     caught and reported as "no verified solution" rather than ever
//     returned as if it were correct.
func DiscreteLogBabyStepGiantStep(ctx context.Context, g, h, p int) (int, ClassicalTrace, error) {
	start := time.Now()
	if p > MaxDiscreteLogModulus {
		return 0, ClassicalTrace{}, fmt.Errorf("quantum: DiscreteLogBabyStepGiantStep(p=%d): %w (max %d)", p, ErrClassicalBoundExceeded, MaxDiscreteLogModulus)
	}
	if p < 2 {
		return 0, ClassicalTrace{}, fmt.Errorf("%w: p=%d must be >= 2", ErrDiscreteLogInvalidInput, p)
	}
	if err := ctx.Err(); err != nil {
		return 0, ClassicalTrace{}, err
	}

	g = reduceMod(g, p)
	hReduced := reduceMod(h, p)
	if g == 0 {
		return 0, ClassicalTrace{}, fmt.Errorf("%w: g ≡ 0 (mod %d) has no well-defined discrete log", ErrDiscreteLogInvalidInput, p)
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

	// factor = g^(-m) mod p, via Fermat's little theorem -- only exact
	// when p is prime; see this function's own doc comment on why the
	// candidate x this produces is verified below rather than trusted
	// outright.
	gInv := modPow(g, p-2, p)
	factor := modPow(gInv, m, p)

	gamma := hReduced
	for i := 0; i < m; i++ {
		if i%64 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, ClassicalTrace{}, err
			}
		}
		operations++
		if j, ok := babySteps[gamma]; ok {
			x := i*m + j
			if modPow(g, x, p) == hReduced {
				return x, ClassicalTrace{
					OperationCount:    operations,
					MeasuredCPUTimeMS: time.Since(start).Milliseconds(),
					Label:             ClassicalBaselineLabel,
				}, nil
			}
			// A candidate from the hash table that does NOT actually
			// satisfy g^x ≡ h (mod p): only possible when p is
			// composite (Fermat's little theorem doesn't hold), so the
			// "modular inverse" used to generate giant steps was wrong.
			// Keep searching rather than returning this wrong answer --
			// a different giant step may still land on a genuinely
			// correct baby-step match.
		}
		gamma = (gamma * factor) % p
	}

	return 0, ClassicalTrace{
		OperationCount:    operations,
		MeasuredCPUTimeMS: time.Since(start).Milliseconds(),
		Label:             ClassicalBaselineLabel,
	}, fmt.Errorf("quantum: DiscreteLogBabyStepGiantStep: no VERIFIED x in [0,%d) satisfies %d^x ≡ %d (mod %d)", p-1, g, hReduced, p)
}

// reduceMod returns v mod m in [0, m) -- Go's own % operator can return
// a negative result for a negative v, which this corrects.
func reduceMod(v, m int) int {
	r := v % m
	if r < 0 {
		r += m
	}
	return r
}
