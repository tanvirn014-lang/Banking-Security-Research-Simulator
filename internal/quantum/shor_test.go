package quantum

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
)

func assertFactorsMultiplyToN(t *testing.T, factors []int, n int) {
	t.Helper()
	if len(factors) != 2 {
		t.Fatalf("expected exactly 2 factors for n=%d, got %v", n, factors)
	}
	if factors[0]*factors[1] != n {
		t.Fatalf("expected factors to multiply to %d, got %v (product %d)", n, factors, factors[0]*factors[1])
	}
	for _, f := range factors {
		if f <= 1 || f >= n {
			t.Fatalf("expected a NONTRIVIAL factor (1 < f < n), got %d among %v for n=%d", f, factors, n)
		}
	}
}

func sortedCopy(factors []int) []int {
	out := append([]int(nil), factors...)
	sort.Ints(out)
	return out
}

func TestShor_Factors15(t *testing.T) {
	factors, trace, err := Shor(context.Background(), 15)
	if err != nil {
		t.Fatalf("Shor(15): %v", err)
	}
	assertFactorsMultiplyToN(t, factors, 15)
	if want := []int{3, 5}; !equalInts(sortedCopy(factors), want) {
		t.Fatalf("expected factors {3,5} for n=15, got %v", factors)
	}
	if trace.OracleQueries <= 0 {
		t.Fatalf("expected a positive OracleQueries count, got %d", trace.OracleQueries)
	}

	// Determinism: a second, independent run must agree exactly.
	factors2, _, err := Shor(context.Background(), 15)
	if err != nil {
		t.Fatalf("Shor(15) second run: %v", err)
	}
	if !equalInts(sortedCopy(factors), sortedCopy(factors2)) {
		t.Fatalf("expected Shor(15) to be deterministic across runs, got %v then %v", factors, factors2)
	}
}

func TestShor_Factors21(t *testing.T) {
	factors, _, err := Shor(context.Background(), 21)
	if err != nil {
		t.Fatalf("Shor(21): %v", err)
	}
	assertFactorsMultiplyToN(t, factors, 21)
	if want := []int{3, 7}; !equalInts(sortedCopy(factors), want) {
		t.Fatalf("expected factors {3,7} for n=21, got %v", factors)
	}
}

func TestShor_Factors35(t *testing.T) {
	factors, _, err := Shor(context.Background(), 35)
	if err != nil {
		t.Fatalf("Shor(35): %v", err)
	}
	assertFactorsMultiplyToN(t, factors, 35)
	if want := []int{5, 7}; !equalInts(sortedCopy(factors), want) {
		t.Fatalf("expected factors {5,7} for n=35, got %v", factors)
	}
}

func TestShor_UnsupportedModulusReturnsError(t *testing.T) {
	if _, _, err := Shor(context.Background(), 100); !errors.Is(err, ErrShorInputUnsupported) {
		t.Fatalf("expected ErrShorInputUnsupported for an undocumented modulus, got %v", err)
	}
}

func TestShor_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Shor(ctx, 15); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected an already-cancelled context to be reported, got %v", err)
	}
}

func TestShor_OutputCarriesSimulationLabel(t *testing.T) {
	_, trace, err := Shor(context.Background(), 15)
	if err != nil {
		t.Fatalf("Shor(15): %v", err)
	}
	if trace.Label != SimulationLabel {
		t.Fatalf("expected trace.Label to carry the mandatory SimulationLabel, got %q", trace.Label)
	}
	if !strings.Contains(trace.TheoreticalComplexity, "O(") {
		t.Fatalf("expected TheoreticalComplexity to state an asymptotic complexity, got %q", trace.TheoreticalComplexity)
	}
}

func TestShor_QubitCountWithinBound(t *testing.T) {
	for _, n := range []int{15, 21, 35} {
		_, trace, err := Shor(context.Background(), n)
		if err != nil {
			t.Fatalf("Shor(%d): %v", n, err)
		}
		if trace.QubitsUsed <= 0 || trace.QubitsUsed > MaxQubits {
			t.Fatalf("expected QubitsUsed for n=%d to be in (0, %d], got %d", n, MaxQubits, trace.QubitsUsed)
		}
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
