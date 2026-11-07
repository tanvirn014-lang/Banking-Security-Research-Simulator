package quantum

import (
	"context"
	"errors"
	"testing"
)

func TestRSAFactorTrialDivision_FactorsKnownComposite(t *testing.T) {
	// The classic RSA textbook toy example: 3233 = 61 * 53.
	factors, trace, err := RSAFactorTrialDivision(context.Background(), 3233)
	if err != nil {
		t.Fatalf("RSAFactorTrialDivision(3233): %v", err)
	}
	if len(factors) != 2 || factors[0]*factors[1] != 3233 {
		t.Fatalf("expected two factors multiplying to 3233, got %v", factors)
	}
	got := sortedCopy(factors)
	if want := []int{53, 61}; !equalInts(got, want) {
		t.Fatalf("expected factors {53,61}, got %v", got)
	}
	if trace.OperationCount <= 0 {
		t.Fatalf("expected a positive OperationCount, got %d", trace.OperationCount)
	}
	if trace.Label != ClassicalBaselineLabel {
		t.Fatalf("expected trace.Label to be ClassicalBaselineLabel, got %q", trace.Label)
	}
}

func TestRSAFactorTrialDivision_PrimeInputReturnsError(t *testing.T) {
	if _, _, err := RSAFactorTrialDivision(context.Background(), 97); err == nil {
		t.Fatalf("expected an error factoring a prime (no nontrivial factor exists)")
	}
}

func TestRSAFactorTrialDivision_ExceedsBoundReturnsError(t *testing.T) {
	if _, _, err := RSAFactorTrialDivision(context.Background(), MaxRSAFactorModulus+1); !errors.Is(err, ErrClassicalBoundExceeded) {
		t.Fatalf("expected ErrClassicalBoundExceeded, got %v", err)
	}
}

func TestRSAFactorTrialDivision_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := RSAFactorTrialDivision(ctx, 3233); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected an already-cancelled context to be reported, got %v", err)
	}
}

func TestRSAFactorTrialDivision_Deterministic(t *testing.T) {
	f1, _, err := RSAFactorTrialDivision(context.Background(), 3233)
	if err != nil {
		t.Fatalf("RSAFactorTrialDivision: %v", err)
	}
	f2, _, err := RSAFactorTrialDivision(context.Background(), 3233)
	if err != nil {
		t.Fatalf("RSAFactorTrialDivision: %v", err)
	}
	if !equalInts(f1, f2) {
		t.Fatalf("expected deterministic output, got %v then %v", f1, f2)
	}
}

func TestDiscreteLogBabyStepGiantStep_FindsCorrectExponent(t *testing.T) {
	// p=23 is prime, g=5 generates a subgroup of Z/23Z*; h is chosen as
	// an actual power of g so a solution is guaranteed to exist.
	const g, p = 5, 23
	const knownX = 7
	h := modPow(g, knownX, p)

	x, trace, err := DiscreteLogBabyStepGiantStep(context.Background(), g, h, p)
	if err != nil {
		t.Fatalf("DiscreteLogBabyStepGiantStep: %v", err)
	}
	if got := modPow(g, x, p); got != h {
		t.Fatalf("expected g^x ≡ h (mod p): g=%d x=%d p=%d gives %d, want %d", g, x, p, got, h)
	}
	if trace.OperationCount <= 0 {
		t.Fatalf("expected a positive OperationCount, got %d", trace.OperationCount)
	}
	if trace.Label != ClassicalBaselineLabel {
		t.Fatalf("expected trace.Label to be ClassicalBaselineLabel, got %q", trace.Label)
	}
}

func TestDiscreteLogBabyStepGiantStep_NoSolutionReturnsError(t *testing.T) {
	// h=0 is never a power of g for prime p (g^x is always nonzero mod p).
	if _, _, err := DiscreteLogBabyStepGiantStep(context.Background(), 5, 0, 23); err == nil {
		t.Fatalf("expected an error when h has no discrete log w.r.t. g")
	}
}

func TestDiscreteLogBabyStepGiantStep_ExceedsBoundReturnsError(t *testing.T) {
	if _, _, err := DiscreteLogBabyStepGiantStep(context.Background(), 2, 1, MaxDiscreteLogModulus+1); !errors.Is(err, ErrClassicalBoundExceeded) {
		t.Fatalf("expected ErrClassicalBoundExceeded, got %v", err)
	}
}

func TestDiscreteLogBabyStepGiantStep_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := DiscreteLogBabyStepGiantStep(ctx, 5, 8, 23); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected an already-cancelled context to be reported, got %v", err)
	}
}

func TestDiscreteLogBabyStepGiantStep_Deterministic(t *testing.T) {
	x1, _, err := DiscreteLogBabyStepGiantStep(context.Background(), 5, modPow(5, 11, 23), 23)
	if err != nil {
		t.Fatalf("DiscreteLogBabyStepGiantStep: %v", err)
	}
	x2, _, err := DiscreteLogBabyStepGiantStep(context.Background(), 5, modPow(5, 11, 23), 23)
	if err != nil {
		t.Fatalf("DiscreteLogBabyStepGiantStep: %v", err)
	}
	if x1 != x2 {
		t.Fatalf("expected deterministic output, got %d then %d", x1, x2)
	}
}
