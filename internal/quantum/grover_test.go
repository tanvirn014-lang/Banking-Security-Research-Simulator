package quantum

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestGrover_FindsMarkedElement(t *testing.T) {
	const bits = 4 // N=16
	const target = 11
	result, trace, err := Grover(context.Background(), bits, func(x int) bool { return x == target })
	if err != nil {
		t.Fatalf("Grover: %v", err)
	}
	if result != target {
		t.Fatalf("expected Grover to find the single marked element %d, got %d", target, result)
	}
	if trace.OracleQueries <= 0 {
		t.Fatalf("expected a positive OracleQueries count, got %d", trace.OracleQueries)
	}

	// Determinism: a second run must agree.
	result2, _, err := Grover(context.Background(), bits, func(x int) bool { return x == target })
	if err != nil {
		t.Fatalf("Grover second run: %v", err)
	}
	if result2 != target {
		t.Fatalf("expected Grover to be deterministic, got %d then %d", result, result2)
	}
}

func TestGrover_FindsOneOfMultipleMarkedElements(t *testing.T) {
	const bits = 4
	marked := map[int]bool{3: true, 12: true}
	result, _, err := Grover(context.Background(), bits, func(x int) bool { return marked[x] })
	if err != nil {
		t.Fatalf("Grover: %v", err)
	}
	if !marked[result] {
		t.Fatalf("expected Grover to find one of the marked elements %v, got %d", marked, result)
	}
}

func TestGrover_NoMarkedElementsReturnsError(t *testing.T) {
	const bits = 3
	if _, _, err := Grover(context.Background(), bits, func(x int) bool { return false }); err == nil {
		t.Fatalf("expected an error when the oracle marks nothing (no target to amplify toward)")
	}
}

func TestGrover_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Grover(ctx, 4, func(x int) bool { return x == 0 }); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected an already-cancelled context to be reported, got %v", err)
	}
}

func TestGrover_ExceedsQubitBoundReturnsError(t *testing.T) {
	if _, _, err := Grover(context.Background(), MaxQubits+1, func(x int) bool { return x == 0 }); !errors.Is(err, ErrQubitBoundExceeded) {
		t.Fatalf("expected ErrQubitBoundExceeded, got %v", err)
	}
}

func TestGrover_OutputCarriesSimulationLabel(t *testing.T) {
	_, trace, err := Grover(context.Background(), 4, func(x int) bool { return x == 5 })
	if err != nil {
		t.Fatalf("Grover: %v", err)
	}
	if trace.Label != SimulationLabel {
		t.Fatalf("expected trace.Label to carry the mandatory SimulationLabel, got %q", trace.Label)
	}
	if !strings.Contains(trace.TheoreticalComplexity, "sqrt") {
		t.Fatalf("expected TheoreticalComplexity to describe the sqrt(N) scaling, got %q", trace.TheoreticalComplexity)
	}
}

// TestComplexityReport_QuadraticSpeedupRatio asserts against
// INDEPENDENTLY, hand-computed literal expected values -- not by
// re-deriving the implementation's own formula in the test (security
// review finding M8: the original version of this test rebuilt
// wantQuantum via the exact same math.Ceil(math.Pi/4*math.Sqrt(...))
// expression the implementation itself uses, so it could only ever
// confirm "the code agrees with itself," never catch a real formula
// bug). For bits=16, N=65536=256^2, so sqrt(N)=256 exactly:
// pi/4*256 = 201.061929... -> ceil = 202 (verified by hand/calculator,
// not computed by this test).
func TestComplexityReport_QuadraticSpeedupRatio(t *testing.T) {
	const bits = 16 // N = 65536 = 256^2
	const wantClassical = 65536
	const wantQuantum = 202 // ceil(pi/4 * 256), computed independently of this package's own code

	classical, quantum, err := ComplexityReport(bits)
	if err != nil {
		t.Fatalf("ComplexityReport: %v", err)
	}
	if classical != wantClassical {
		t.Fatalf("expected classicalExpectedOps=%d, got %d", wantClassical, classical)
	}
	if quantum != wantQuantum {
		t.Fatalf("expected quantumExpectedOps=%d, got %d", wantQuantum, quantum)
	}
	// The whole point being demonstrated: quadratic, not exponential,
	// speedup. 65536/202 = 324.4..., a large but QUADRATIC-scale
	// improvement (not, say, an exponential 65536/16), and nowhere near
	// a fabricated larger number.
	ratio := float64(classical) / float64(quantum)
	if ratio < 300 || ratio > 350 {
		t.Fatalf("expected a quadratic-scale ratio around 324 (65536/202), got %.1f", ratio)
	}
}

func TestComplexityReport_RejectsOutOfRangeInput(t *testing.T) {
	if _, _, err := ComplexityReport(-1); !errors.Is(err, ErrQubitBoundExceeded) {
		t.Fatalf("expected ErrQubitBoundExceeded for -1, got %v", err)
	}
	if _, _, err := ComplexityReport(MaxQubits + 1); !errors.Is(err, ErrQubitBoundExceeded) {
		t.Fatalf("expected ErrQubitBoundExceeded for MaxQubits+1, got %v", err)
	}
	if _, _, err := ComplexityReport(63); !errors.Is(err, ErrQubitBoundExceeded) {
		t.Fatalf("expected ErrQubitBoundExceeded for 63 (would overflow 1<<63 as a negative int), got %v", err)
	}
}
