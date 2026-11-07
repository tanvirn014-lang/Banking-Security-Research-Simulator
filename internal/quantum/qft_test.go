package quantum

import (
	"math"
	"math/cmplx"
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
