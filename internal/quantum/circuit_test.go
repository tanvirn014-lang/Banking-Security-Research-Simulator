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

// TestQubitBounds_PanicConsistently is the regression test for security
// review finding M2: before this, an out-of-range qubit index produced
// a DIFFERENT failure mode per method (some silently did nothing or
// returned 0, some panicked with Go's own "index out of range" or
// "negative shift amount"). Every Apply*/Measure method must now panic
// via the same validateQubit helper for any out-of-range index.
func TestQubitBounds_PanicConsistently(t *testing.T) {
	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("%s: expected a panic for an out-of-range qubit, got none", name)
			}
		}()
		f()
	}

	mustPanic("ApplyH(5) on 3 qubits", func() { c, _ := NewCircuit(3); c.ApplyH(5) })
	mustPanic("ApplyH(-1)", func() { c, _ := NewCircuit(3); c.ApplyH(-1) })
	mustPanic("ApplyX(3) on 3 qubits", func() { c, _ := NewCircuit(3); c.ApplyX(3) })
	mustPanic("ApplyCNOT(5,0) on 3 qubits", func() { c, _ := NewCircuit(3); c.ApplyCNOT(5, 0) })
	mustPanic("ApplyCNOT(0,5) on 3 qubits", func() { c, _ := NewCircuit(3); c.ApplyCNOT(0, 5) })
	mustPanic("ApplyCNOT(1,1) same qubit", func() { c, _ := NewCircuit(3); c.ApplyCNOT(1, 1) })
	mustPanic("ApplyControlledPhase(7,0,..) on 2 qubits", func() { c, _ := NewCircuit(2); c.ApplyControlledPhase(7, 0, 1) })
	mustPanic("Measure(5) on 3 qubits", func() { c, _ := NewCircuit(3); c.Measure(5) })
}

// TestMeasureAll_FallbackNeverReturnsZeroAmplitudeOutcome is the
// regression test for security review finding M4: MeasureAll's
// float-rounding fallback previously used the literal last index
// (len(State)-1) unconditionally, which can have exactly zero amplitude
// -- an outcome the state never actually had any chance of producing.
// Reproduces the reviewer's own probe: a state whose true probabilities
// sum to slightly less than 1 (float rounding), paired with an rng that
// always returns the maximum possible float64 just under 1, forces the
// fallback path; the last basis state here has zero amplitude, so the
// fallback must choose an earlier, genuinely nonzero-amplitude state
// instead.
func TestMeasureAll_FallbackNeverReturnsZeroAmplitudeOutcome(t *testing.T) {
	c, err := NewCircuitWithRand(2, rand.New(maxFloatSource{}))
	if err != nil {
		t.Fatalf("NewCircuitWithRand: %v", err)
	}
	// index 3 has amplitude exactly 0; indices 0,1 are slightly
	// under-normalized (as float rounding naturally produces).
	c.State = []complex128{
		complex(math.Sqrt(0.5), 0),
		complex(math.Sqrt(0.5-1e-15), 0),
		0,
		0,
	}
	outcome := c.MeasureAll()
	if outcome == 3 {
		t.Fatalf("expected the fallback to skip the zero-amplitude index 3, got outcome=%d", outcome)
	}
	if outcome != 0 && outcome != 1 {
		t.Fatalf("expected the fallback to land on a genuinely nonzero-amplitude index (0 or 1), got %d", outcome)
	}
}

// maxFloatSource is a rand.Source producing rand.Float64() == 1-2^-52,
// the largest float64 strictly less than 1 -- forcing MeasureAll's
// cumulative-probability loop to fall through without ever satisfying
// `r < cumulative` for a state whose true probabilities don't sum to
// exactly 1 in float64. NOT 1<<63-1: math/rand's Float64() retries
// forever if int64-to-float64 conversion rounds its result up to
// exactly 1 (which 1<<63-1 does, since 2^63-1 is too large for float64's
// 53-bit mantissa and rounds to 2^63) -- 1<<63-1<<11 is the nearest
// representable value below that rounds to something strictly less than
// 1 instead.
type maxFloatSource struct{}

func (maxFloatSource) Int63() int64 { return 1<<63 - 1<<11 }
func (maxFloatSource) Seed(int64)   {}

// TestNoImportsOutsideStdlib checks every file this package could ever
// build, not just this platform's non-test files. Security review
// finding M5: the original version of this test checked only
// pkg.Imports (non-test, current-GOOS files) -- a banned import from a
// _test.go file (internal or external) passed undetected, and so did
// one hidden behind a `//go:build linux` (or any other non-matching)
// tag when running on a different GOOS. UseAllFiles makes
// build.ImportDir include every build-tag variant regardless of the
// host GOOS/GOARCH, and TestImports/XTestImports cover _test.go files
// (both same-package and external _test packages).
func TestNoImportsOutsideStdlib(t *testing.T) {
	pkg, err := build.ImportDir(".", build.ImportMode(0))
	if err != nil {
		t.Fatalf("import package: %v", err)
	}
	ctx := build.Default
	ctx.UseAllFiles = true
	pkgAllFiles, err := ctx.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("import package (all build-tag variants): %v", err)
	}

	var allImports []string
	allImports = append(allImports, pkg.Imports...)
	allImports = append(allImports, pkg.TestImports...)
	allImports = append(allImports, pkg.XTestImports...)
	allImports = append(allImports, pkgAllFiles.Imports...)
	allImports = append(allImports, pkgAllFiles.TestImports...)
	allImports = append(allImports, pkgAllFiles.XTestImports...)

	for _, path := range allImports {
		if strings.HasPrefix(path, "banksec-lab/") {
			t.Fatalf("package quantum (including its tests, and every build-tag variant) must not import any other banksec-lab package (CRYPTOGRAPHY.md §5: structurally disconnected from internal/crypto), found: %s", path)
		}
	}
}
