package quantum

import (
	"context"
	"errors"
	"math"
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

func TestComplexityReport_QuadraticSpeedupRatio(t *testing.T) {
	const bits = 16 // N = 65536
	classical, quantum := ComplexityReport(bits)
	n := 1 << bits
	if classical != n {
		t.Fatalf("expected classicalExpectedOps == N == %d, got %d", n, classical)
	}
	wantQuantum := int(math.Ceil(math.Pi / 4 * math.Sqrt(float64(n))))
	if quantum != wantQuantum {
		t.Fatalf("expected quantumExpectedOps == ceil(pi/4*sqrt(N)) == %d, got %d", wantQuantum, quantum)
	}
	// The whole point being demonstrated: quadratic, not exponential,
	// speedup -- the ratio should track (4/pi)*sqrt(N) (Grover's own
	// pi/4 prefactor against an exact sqrt(N) iteration count), not some
	// fabricated larger improvement.
	ratio := float64(classical) / float64(quantum)
	wantRatio := (4 / math.Pi) * math.Sqrt(float64(n))
	if math.Abs(ratio-wantRatio) > 2 {
		t.Fatalf("expected the classical/quantum ratio to track (4/pi)*sqrt(N)=%.1f, got %.1f", wantRatio, ratio)
	}
}
