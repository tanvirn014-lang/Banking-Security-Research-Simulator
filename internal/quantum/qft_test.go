package quantum

import (
	"math"
	"math/cmplx"
	"math/rand"
	"testing"
)

// dft computes the standard (unnormalized-by-sqrt-handled) quantum
// Fourier transform of amp directly via its textbook matrix definition,
// as an independent ground truth to check ApplyQFT against:
// out[k] = (1/sqrt(N)) * sum_x amp[x] * e^(2*pi*i*x*k/N).
func dft(amp []complex128) []complex128 {
	n := len(amp)
	out := make([]complex128, n)
	norm := 1 / math.Sqrt(float64(n))
	for k := 0; k < n; k++ {
		var sum complex128
		for x := 0; x < n; x++ {
			theta := 2 * math.Pi * float64(x) * float64(k) / float64(n)
			sum += amp[x] * cmplx.Exp(complex(0, theta))
		}
		out[k] = complex(norm, 0) * sum
	}
	return out
}

// TestApplyQFT_MatchesTextbookDFTMatrix_AcrossQubitCounts broadens the
// single hand-picked 3-qubit case below to n=1..8 with a seeded-random
// starting state each time, plus a non-contiguous, permuted sub-register
// case -- security review finding M8 noted the original version of this
// file covered only one fixed 3-qubit state (independently re-verified
// correct by the reviewer's own n=1..9 probe, but not committed as
// regression coverage).
func TestApplyQFT_MatchesTextbookDFTMatrix_AcrossQubitCounts(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	randomState := func(n int) []complex128 {
		s := make([]complex128, 1<<n)
		var sumSq float64
		for i := range s {
			s[i] = complex(rng.NormFloat64(), rng.NormFloat64())
			sumSq += real(s[i])*real(s[i]) + imag(s[i])*imag(s[i])
		}
		norm := math.Sqrt(sumSq)
		for i := range s {
			s[i] /= complex(norm, 0)
		}
		return s
	}

	for n := 1; n <= 8; n++ {
		c, err := NewCircuit(n)
		if err != nil {
			t.Fatalf("NewCircuit(%d): %v", n, err)
		}
		qubits := make([]int, n)
		for i := range qubits {
			qubits[i] = i
		}

		c.State = randomState(n)
		want := dft(c.State)
		ApplyQFT(c, qubits)
		for i := range want {
			if cmplx.Abs(c.State[i]-want[i]) > 1e-6 {
				t.Fatalf("n=%d: ApplyQFT disagrees with the reference DFT at index %d: got %v want %v", n, i, c.State[i], want[i])
			}
		}
	}

	// A non-contiguous, permuted sub-register within a larger circuit --
	// confirms ApplyQFT's bit-index handling isn't accidentally relying
	// on qubits being contiguous or in ascending order.
	c, err := NewCircuit(6)
	if err != nil {
		t.Fatalf("NewCircuit(6): %v", err)
	}
	c.State = randomState(6)
	qubits := []int{4, 1, 5}
	// Build the expected result via the same sub-register DFT definition
	// as refSubDFT in the review's own probe: transform only the named
	// qubits' value, leaving the rest of the index untouched.
	want := subRegisterDFT(c.State, qubits, 1)
	ApplyQFT(c, qubits)
	for i := range want {
		if cmplx.Abs(c.State[i]-want[i]) > 1e-6 {
			t.Fatalf("non-contiguous sub-register {4,1,5}: ApplyQFT disagrees with the reference DFT at index %d: got %v want %v", i, c.State[i], want[i])
		}
	}
}

// subRegisterDFT computes the reference DFT (sign=+1 forward, -1
// inverse) restricted to the named qubits of state, leaving every other
// qubit's value as a spectator -- an independent ground truth for
// ApplyQFT/ApplyInverseQFT on a non-contiguous, non-ascending qubit
// list, not derived from this package's own ApplyQFT implementation.
func subRegisterDFT(state []complex128, qubits []int, sign float64) []complex128 {
	k := len(qubits)
	kDim := 1 << k
	var subMask int
	for _, q := range qubits {
		subMask |= 1 << q
	}
	embed := func(rest, v int) int {
		idx := rest
		for b, q := range qubits {
			if v&(1<<b) != 0 {
				idx |= 1 << q
			}
		}
		return idx
	}
	out := make([]complex128, len(state))
	for idx := range state {
		if idx&subMask != 0 {
			continue // handled as part of its rest-bits group below
		}
		for y := 0; y < kDim; y++ {
			var sum complex128
			for x := 0; x < kDim; x++ {
				theta := sign * 2 * math.Pi * float64(x*y) / float64(kDim)
				sum += state[embed(idx, x)] * cmplx.Exp(complex(0, theta))
			}
			out[embed(idx, y)] = sum / complex(math.Sqrt(float64(kDim)), 0)
		}
	}
	return out
}

func TestApplyQFT_MatchesTextbookDFTMatrix(t *testing.T) {
	c, err := NewCircuit(3)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	// An arbitrary (non-uniform, non-trivial) starting amplitude vector,
	// renormalized to a valid quantum state.
	raw := []complex128{1, 2, 0, -1, 0.5, 0, 1, -2}
	var sumSq float64
	for _, a := range raw {
		sumSq += real(a)*real(a) + imag(a)*imag(a)
	}
	norm := math.Sqrt(sumSq)
	for i := range raw {
		c.State[i] = raw[i] / complex(norm, 0)
	}
	want := dft(c.State)

	ApplyQFT(c, []int{0, 1, 2})

	for i := range want {
		if cmplx.Abs(c.State[i]-want[i]) > 1e-6 {
			t.Fatalf("ApplyQFT output disagrees with the textbook DFT matrix at index %d: got %v want %v", i, c.State[i], want[i])
		}
	}
}

func TestApplyInverseQFT_UndoesApplyQFT(t *testing.T) {
	c, err := NewCircuit(3)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	c.ApplyH(0)
	c.ApplyX(1)
	c.ApplyH(2)
	before := append([]complex128(nil), c.State...)

	qubits := []int{0, 1, 2}
	ApplyQFT(c, qubits)
	ApplyInverseQFT(c, qubits)

	for i := range before {
		if cmplx.Abs(c.State[i]-before[i]) > 1e-6 {
			t.Fatalf("InverseQFT(QFT(state)) != state at index %d: got %v want %v", i, c.State[i], before[i])
		}
	}
}

func TestApplyQFT_PreservesNormalization(t *testing.T) {
	c, err := NewCircuit(4)
	if err != nil {
		t.Fatalf("NewCircuit: %v", err)
	}
	c.ApplyH(0)
	c.ApplyH(2)
	ApplyQFT(c, []int{0, 1, 2, 3})
	if n := stateNorm(c.State); math.Abs(n-1) > 1e-9 {
		t.Fatalf("expected QFT to preserve normalization, got %v", n)
	}
}
