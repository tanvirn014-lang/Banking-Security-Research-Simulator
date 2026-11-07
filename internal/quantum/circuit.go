// Package quantum is a classical state-vector simulator of elementary
// quantum gates, used to build toy-scale, genuinely-simulated
// implementations of Shor's and Grover's algorithms (internal/quantum's
// shor.go/grover.go) plus classical cryptanalysis baselines to compare
// against (classical.go).
//
// This package is structurally disconnected from internal/crypto: it
// never receives, touches, or attempts to factor/break any real key
// generated for this project's standard or PQC profiles (see
// docs/CRYPTOGRAPHY.md §5 and docs/QUANTUM_METHODOLOGY.md for the full,
// mandatory non-claims). TestNoImportsOutsideStdlib enforces this
// structurally: this package imports no other banksec-lab package.
package quantum

import (
	"errors"
	"math"
	"math/cmplx"
	"math/rand"
	"time"
)

// MaxQubits bounds Circuit's size: 2^20 complex128 amplitudes is ~16MiB,
// a reasonable upper bound for a classically-simulated toy circuit.
// Simulating one additional qubit doubles both the memory and the work
// of every gate, since gates operate on the full amplitude vector --
// this exponential classical cost is itself part of what
// docs/QUANTUM_METHODOLOGY.md documents as a limitation of the
// simulation (it is also the reason real quantum computers would, in
// principle, not pay this cost).
const MaxQubits = 20

// ErrQubitBoundExceeded is returned by NewCircuit/NewCircuitWithRand
// when asked for more than MaxQubits -- never a silent truncation.
//
// A plain errors.New sentinel, not internal/apperr.Error (the latter is
// how every other package in this project classifies errors for the
// CLI/protocol layer) -- this package imports no other banksec-lab
// package at all, per its own task instructions and
// TestNoImportsOutsideStdlib, since Milestone 9 is "independent of every
// other milestone except Milestone 1" and has no CLI/protocol wiring of
// its own yet.
var ErrQubitBoundExceeded = errors.New("quantum: qubit bound exceeded")

// Circuit is a classically-simulated register of NumQubits qubits,
// represented by its full complex amplitude vector (length
// 1<<NumQubits), indexed by the standard computational basis: bit q of
// an index selects qubit q's value (qubit 0 is the least-significant
// bit).
//
// Every Apply* method mutates State in place via genuine unitary
// (norm-preserving, reversible) linear algebra over the full amplitude
// vector -- never a shortcut that skips simulating superposition or
// entanglement. ApplyH/ApplyX/ApplyCNOT/ApplyControlledPhase are
// elementary one- or two-qubit gates, each a direct, standard matrix
// action. ApplyPermutationUnitary is a different kind of unitary: it
// lifts an arbitrary classically-computed bijection on basis indices
// directly to a unitary permutation matrix, without further decomposing
// it into elementary gates. This is standard practice for toy quantum
// algorithm simulators (used here for Shor's modular-exponentiation
// oracle and Grover's marking oracle) -- it is still a real unitary
// operating on genuinely superposed amplitudes, just not built up from
// 1-/2-qubit gates the way a real quantum compiler would. See
// docs/QUANTUM_METHODOLOGY.md for exactly which operations are
// elementary-gate-decomposed and which are oracle-level unitaries.
type Circuit struct {
	NumQubits int
	State     []complex128

	rng *rand.Rand
}

// NewCircuit creates a Circuit with NumQubits qubits, initialized to the
// all-zero basis state |00...0>, using a time-seeded random source for
// Measure/MeasureAll. For deterministic/reproducible measurement
// outcomes (required by this package's own deterministic test cases,
// and by Shor/Grover's reproducibility requirements), use
// NewCircuitWithRand with a seeded *rand.Rand instead.
func NewCircuit(numQubits int) (*Circuit, error) {
	return NewCircuitWithRand(numQubits, rand.New(rand.NewSource(time.Now().UnixNano())))
}

// NewCircuitWithRand is NewCircuit, but with an explicit, caller-owned
// *rand.Rand driving every probabilistic measurement outcome -- the
// deterministic alternative used by this package's own tests and by
// Shor/Grover, which need reproducible results given the same seed.
func NewCircuitWithRand(numQubits int, rng *rand.Rand) (*Circuit, error) {
	if numQubits < 0 || numQubits > MaxQubits {
		return nil, ErrQubitBoundExceeded
	}
	state := make([]complex128, 1<<numQubits)
	state[0] = complex(1, 0)
	return &Circuit{NumQubits: numQubits, State: state, rng: rng}, nil
}

// ApplyH applies a Hadamard gate to qubit, an elementary one-qubit gate
// putting a |0>/|1> basis state into equal superposition.
func (c *Circuit) ApplyH(qubit int) {
	bit := 1 << qubit
	invSqrt2 := complex(1/math.Sqrt2, 0)
	for i := 0; i < len(c.State); i++ {
		if i&bit != 0 {
			continue // handled as the partner of its i&^bit pair below
		}
		j := i | bit
		a, b := c.State[i], c.State[j]
		c.State[i] = invSqrt2 * (a + b)
		c.State[j] = invSqrt2 * (a - b)
	}
}

// ApplyX applies a Pauli-X (NOT) gate to qubit, an elementary one-qubit
// gate swapping the amplitudes of each basis pair differing only in
// qubit's bit.
func (c *Circuit) ApplyX(qubit int) {
	bit := 1 << qubit
	for i := 0; i < len(c.State); i++ {
		if i&bit != 0 {
			continue
		}
		j := i | bit
		c.State[i], c.State[j] = c.State[j], c.State[i]
	}
}

// ApplyCNOT applies a controlled-NOT gate: target is flipped exactly
// when control is 1. An elementary two-qubit gate; this is how
// ApplyCNOT entangles previously-independent qubits.
func (c *Circuit) ApplyCNOT(control, target int) {
	controlBit := 1 << control
	targetBit := 1 << target
	for i := 0; i < len(c.State); i++ {
		if i&controlBit == 0 || i&targetBit != 0 {
			continue
		}
		j := i | targetBit
		c.State[i], c.State[j] = c.State[j], c.State[i]
	}
}

// ApplyControlledPhase multiplies the amplitude of every basis state
// with BOTH control and target bits set to 1 by e^(i*theta), leaving
// every other amplitude unchanged. An elementary two-qubit gate
// (symmetric in its two arguments); internal/quantum's QFT is built
// from this plus ApplyH.
func (c *Circuit) ApplyControlledPhase(control, target int, theta float64) {
	controlBit := 1 << control
	targetBit := 1 << target
	phase := cmplx.Exp(complex(0, theta))
	for i := 0; i < len(c.State); i++ {
		if i&controlBit != 0 && i&targetBit != 0 {
			c.State[i] *= phase
		}
	}
}

// ApplyPermutationUnitary applies the unitary permutation matrix
// |x> -> |perm(x)> to the full state -- see Circuit's doc comment for
// why this is a legitimate (if not further gate-decomposed) unitary,
// and when this package uses it. perm MUST be a bijection on
// [0, 1<<NumQubits); ApplyPermutationUnitary panics if it detects a
// collision, since a non-bijective perm would not be unitary at all
// (this is a programmer-error assertion on an internal primitive, not
// user input validation -- every caller in this package is this
// package's own code).
func (c *Circuit) ApplyPermutationUnitary(perm func(x int) int) {
	n := len(c.State)
	next := make([]complex128, n)
	seen := make([]bool, n)
	for x := 0; x < n; x++ {
		px := perm(x)
		if px < 0 || px >= n {
			panic("quantum: ApplyPermutationUnitary: perm returned an out-of-range index")
		}
		if seen[px] {
			panic("quantum: ApplyPermutationUnitary: perm is not a bijection (collision)")
		}
		seen[px] = true
		next[px] = c.State[x]
	}
	c.State = next
}

// ApplyPhaseOracle multiplies the amplitude of every basis state x for
// which mark(x) is true by -1, leaving every other amplitude unchanged
// -- a genuine diagonal unitary (every diagonal entry is +1 or -1, so
// norm and reversibility are automatic). This is Grover's algorithm's
// marking oracle: an "oracle-level" unitary wrapping an arbitrary
// caller-supplied classical predicate, the same category as
// ApplyPermutationUnitary/Shor's modular-exponentiation oracle -- not
// further decomposed into elementary gates. See
// docs/QUANTUM_METHODOLOGY.md for why evaluating mark(x) once per basis
// state here is a classical simulation cost, not the "one query" a real
// quantum oracle call represents.
func (c *Circuit) ApplyPhaseOracle(mark func(x int) bool) {
	for i := range c.State {
		if mark(i) {
			c.State[i] = -c.State[i]
		}
	}
}

// ApplyDiffusion applies Grover's diffusion operator (reflection about
// the mean amplitude, equivalent to 2|s><s| - I where |s> is the
// uniform superposition over the full register) to the ENTIRE state --
// a fixed, well-known, standard Grover component, not an arbitrary
// oracle. Implemented directly via the mean-amplitude identity
// (2|s><s|psi> = 2*mean(psi)*|all-ones vector>, so the reflection is
// exactly "replace each amplitude with 2*mean - itself") rather than
// building it from ApplyH/ApplyX/ApplyControlledPhase -- mathematically
// exact for this operator, and the standard way toy Grover simulators
// implement it.
func (c *Circuit) ApplyDiffusion() {
	var sum complex128
	for _, a := range c.State {
		sum += a
	}
	mean := sum / complex(float64(len(c.State)), 0)
	twoMean := 2 * mean
	for i := range c.State {
		c.State[i] = twoMean - c.State[i]
	}
}

// Measure collapses qubit's superposition, sampling its outcome
// according to the Born rule (probability = |amplitude|^2, summed over
// every basis state consistent with each outcome), zeroes out every
// amplitude inconsistent with the sampled outcome, and renormalizes
// what remains. Returns the sampled outcome (0 or 1). This only
// collapses the one qubit named -- other qubits remain however
// entangled/superposed they were (see TestApplyCNOT_EntanglesQubits for
// the observable consequence: measuring one half of an entangled pair
// determines the other's later measurement).
func (c *Circuit) Measure(qubit int) int {
	bit := 1 << qubit
	var probOne float64
	for i, a := range c.State {
		if i&bit != 0 {
			probOne += real(a)*real(a) + imag(a)*imag(a)
		}
	}
	outcome := 0
	if c.rng.Float64() < probOne {
		outcome = 1
	}
	probOutcome := probOne
	if outcome == 0 {
		probOutcome = 1 - probOne
	}
	norm := complex(1/math.Sqrt(probOutcome), 0)
	for i := range c.State {
		if (i&bit != 0) == (outcome == 1) {
			c.State[i] *= norm
		} else {
			c.State[i] = 0
		}
	}
	return outcome
}

// MeasureAll collapses the ENTIRE register in one Born-rule sample over
// all 1<<NumQubits basis states, leaving State as the pure basis vector
// at the sampled outcome (amplitude 1 there, 0 elsewhere -- the global
// phase of that one surviving amplitude is discarded, which is correct:
// measurement collapse is only defined up to global phase). Returns the
// sampled outcome as a single integer (qubit q's value is bit q of the
// result). Used where Shor/Grover need one consistent, correlated
// readout of multiple qubits together, rather than qubit-by-qubit
// Measure calls that would each (correctly, but unhelpfully here)
// collapse and renormalize the shared state as they go.
func (c *Circuit) MeasureAll() int {
	r := c.rng.Float64()
	var cumulative float64
	outcome := len(c.State) - 1 // fallback for float rounding landing exactly at 1.0
	for i, a := range c.State {
		cumulative += real(a)*real(a) + imag(a)*imag(a)
		if r < cumulative {
			outcome = i
			break
		}
	}
	next := make([]complex128, len(c.State))
	next[outcome] = 1
	c.State = next
	return outcome
}
