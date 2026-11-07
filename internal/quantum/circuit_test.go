package quantum

import (
	"errors"
	"go/build"
	"math"
	"math/cmplx"
	"math/rand"
	"strings"
	"testing"
)

func TestNewCircuit_ExceedsBound_ReturnsError(t *testing.T) {
	if _, err := NewCircuit(21); !errors.Is(err, ErrQubitBoundExceeded) {
		t.Fatalf("expected ErrQubitBoundExceeded for 21 qubits, got %v", err)
	}
	if _, err := NewCircuit(20); err != nil {
		t.Fatalf("expected 20 qubits (the documented bound) to be accepted, got %v", err)
	}
}

func TestNewCircuit_InitializedToAllZeroState(t *testing.T) {
	c, err := NewCircuit(3)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	if len(c.State) != 1<<3 {
		t.Fatalf("expected a state vector of length 8, got %d", len(c.State))
	}
	if c.State[0] != complex(1, 0) {
		t.Fatalf("expected the |000> amplitude to start at 1, got %v", c.State[0])
	}
	for i := 1; i < len(c.State); i++ {
		if c.State[i] != 0 {
			t.Fatalf("expected every non-|000> amplitude to start at 0, state[%d]=%v", i, c.State[i])
		}
	}
}

func stateNorm(state []complex128) float64 {
	var sum float64
	for _, a := range state {
		sum += real(a)*real(a) + imag(a)*imag(a)
	}
	return math.Sqrt(sum)
}

func TestApplyH_ProducesEqualSuperposition(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	const trials = 2000
	ones := 0
	for i := 0; i < trials; i++ {
		c, err := NewCircuitWithRand(1, rng)
		if err != nil {
			t.Fatalf("NewCircuitWithRand: %v", err)
		}
		c.ApplyH(0)
		if c.Measure(0) == 1 {
			ones++
		}
	}
	frac := float64(ones) / float64(trials)
	if frac < 0.45 || frac > 0.55 {
		t.Fatalf("expected roughly 50%% ones over %d trials of H|0> then measure, got %.3f", trials, frac)
	}
}

func TestApplyH_PreservesNormalization(t *testing.T) {
	c, err := NewCircuit(2)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	c.ApplyH(0)
	c.ApplyH(1)
	if n := stateNorm(c.State); math.Abs(n-1) > 1e-9 {
		t.Fatalf("expected the state vector to remain normalized (norm 1) after ApplyH, got %v", n)
	}
}

func TestApplyX_FlipsBasisState(t *testing.T) {
	c, err := NewCircuit(2)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	c.ApplyX(0)
	// |00> -> |01> (qubit 0 flipped to 1): basis index 1 (bit 0 set).
	if cmplx.Abs(c.State[1]-1) > 1e-9 {
		t.Fatalf("expected ApplyX(0) on |00> to produce |01> (index 1) with amplitude 1, got state=%v", c.State)
	}
}

func TestApplyCNOT_EntanglesQubits(t *testing.T) {
	c, err := NewCircuit(2)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	c.ApplyH(0)
	c.ApplyCNOT(0, 1)
	// Expect a Bell-like state: amplitude 1/sqrt2 at |00> (index 0) and
	// |11> (index 3, both bits set), 0 elsewhere.
	want := complex(1/math.Sqrt2, 0)
	if cmplx.Abs(c.State[0]-want) > 1e-9 || cmplx.Abs(c.State[3]-want) > 1e-9 {
		t.Fatalf("expected a Bell state (amplitude 1/sqrt2 at indices 0 and 3), got state=%v", c.State)
	}
	if cmplx.Abs(c.State[1]) > 1e-9 || cmplx.Abs(c.State[2]) > 1e-9 {
		t.Fatalf("expected zero amplitude at indices 1 and 2, got state=%v", c.State)
	}

	rng := rand.New(rand.NewSource(1))
	const trials = 500
	for i := 0; i < trials; i++ {
		c2, _ := NewCircuitWithRand(2, rng)
		c2.ApplyH(0)
		c2.ApplyCNOT(0, 1)
		b0 := c2.Measure(0)
		b1 := c2.Measure(1)
		if b0 != b1 {
			t.Fatalf("expected the entangled qubits to always measure equal, got q0=%d q1=%d", b0, b1)
		}
	}
}

func TestApplyPermutationUnitary_PreservesNormalizationAndIsReversible(t *testing.T) {
	c, err := NewCircuit(3)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	c.ApplyH(0)
	c.ApplyH(1)
	c.ApplyH(2)
	before := append([]complex128(nil), c.State...)

	perm := func(x int) int { return x ^ 0b101 } // a simple involutive bijection on 3 qubits
	c.ApplyPermutationUnitary(perm)
	if n := stateNorm(c.State); math.Abs(n-1) > 1e-9 {
		t.Fatalf("expected normalization to be preserved after a permutation unitary, got %v", n)
	}
	c.ApplyPermutationUnitary(perm) // applying the same involution twice must restore the original state
	for i := range before {
		if cmplx.Abs(c.State[i]-before[i]) > 1e-9 {
			t.Fatalf("expected applying an involutive permutation twice to restore the original state at index %d: got %v want %v", i, c.State[i], before[i])
		}
	}
}

func TestApplyPermutationUnitary_NonBijectivePanics(t *testing.T) {
	c, err := NewCircuit(2)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected ApplyPermutationUnitary to panic on a non-bijective function")
		}
	}()
	c.ApplyPermutationUnitary(func(x int) int { return 0 }) // collides every input onto 0
}

func TestApplyControlledPhase_OnlyAffectsBothOnesSubspace(t *testing.T) {
	c, err := NewCircuit(2)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	c.ApplyX(0)
	c.ApplyX(1) // now in basis state |11> (index 3)
	c.ApplyControlledPhase(0, 1, math.Pi/2)
	if cmplx.Abs(c.State[3]-complex(0, 1)) > 1e-9 {
		t.Fatalf("expected a pi/2 controlled-phase on |11> to multiply its amplitude by i, got %v", c.State[3])
	}
}

func TestMeasureAll_CollapsesToConsistentBasisState(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	c, err := NewCircuitWithRand(3, rng)
	if err != nil {
		t.Fatalf("NewCircuitWithRand: %v", err)
	}
	c.ApplyH(0)
	c.ApplyH(1)
	c.ApplyH(2)
	outcome := c.MeasureAll()
	if outcome < 0 || outcome >= 8 {
		t.Fatalf("expected MeasureAll to return a value in [0,8), got %d", outcome)
	}
	// After collapse, the state must be a pure basis vector at outcome.
	for i, amp := range c.State {
		if i == outcome {
			if cmplx.Abs(amp-1) > 1e-9 {
				t.Fatalf("expected amplitude 1 at the measured outcome %d, got %v", outcome, amp)
			}
		} else if cmplx.Abs(amp) > 1e-9 {
			t.Fatalf("expected zero amplitude away from the measured outcome, state[%d]=%v", i, amp)
		}
	}
}

func TestApplyPhaseOracle_FlipsOnlyMarkedAmplitudes(t *testing.T) {
	c, err := NewCircuit(2)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	c.ApplyH(0)
	c.ApplyH(1)
	before := append([]complex128(nil), c.State...)

	marked := map[int]bool{2: true}
	c.ApplyPhaseOracle(func(x int) bool { return marked[x] })

	for i, amp := range c.State {
		want := before[i]
		if marked[i] {
			want = -want
		}
		if cmplx.Abs(amp-want) > 1e-9 {
			t.Fatalf("index %d: got %v want %v (marked=%v)", i, amp, want, marked[i])
		}
	}
	if n := stateNorm(c.State); math.Abs(n-1) > 1e-9 {
		t.Fatalf("expected ApplyPhaseOracle to preserve normalization, got %v", n)
	}
}

func TestApplyDiffusion_IsItsOwnInverse(t *testing.T) {
	c, err := NewCircuit(3)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	c.ApplyH(0)
	c.ApplyH(1)
	c.ApplyH(2)
	c.ApplyPhaseOracle(func(x int) bool { return x == 5 })
	before := append([]complex128(nil), c.State...)

	c.ApplyDiffusion()
	if n := stateNorm(c.State); math.Abs(n-1) > 1e-9 {
		t.Fatalf("expected ApplyDiffusion to preserve normalization, got %v", n)
	}
	c.ApplyDiffusion()
	for i := range before {
		if cmplx.Abs(c.State[i]-before[i]) > 1e-9 {
			t.Fatalf("expected ApplyDiffusion applied twice (a reflection is an involution) to restore the original state at index %d: got %v want %v", i, c.State[i], before[i])
		}
	}
}

func TestNoImportsOutsideStdlib(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("import package: %v", err)
	}
	for _, path := range pkg.Imports {
		if strings.HasPrefix(path, "banksec-lab/") {
			t.Fatalf("package quantum must not import any other banksec-lab package (CRYPTOGRAPHY.md §5: structurally disconnected from internal/crypto), found: %s", path)
		}
	}
}
