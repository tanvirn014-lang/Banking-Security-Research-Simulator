package quantum

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestGrover_NeverReturnsUnmarkedElementWithNilError is the regression
// test for Milestone 9 review finding I1: when more than half the
// search space is marked (M > N/2), floor(pi/4*sqrt(N/M)) collapses to
// 0 and was forced up to 1 iteration regardless -- an overshoot that can
// drive the success probability to exactly 0, while Grover still
// returned that (unmarked) result with err=nil, contradicting
// QUANTUM_METHODOLOGY.md's "correct implementation of Grover's ...
// logic" claim. If Grover reports no error, the returned index MUST be
// genuinely marked by the oracle -- never a silently wrong answer.
func TestGrover_NeverReturnsUnmarkedElementWithNilError(t *testing.T) {
	cases := []struct {
		bits   int
		marked func(x int) bool
	}{
		{2, func(x int) bool { return x != 3 }},   // N=4, M=3
		{3, func(x int) bool { return x%2 == 0 }}, // N=8, M=4
		{4, func(x int) bool { return x < 12 }},   // N=16, M=12
	}
	for _, tc := range cases {
		result, _, err := Grover(context.Background(), tc.bits, tc.marked)
		if err != nil {
			continue // an honest "didn't find a marked element" error is acceptable
		}
		if !tc.marked(result) {
			t.Fatalf("bits=%d: Grover returned UNMARKED element %d with err=nil -- a silently wrong answer", tc.bits, result)
		}
	}
}

// TestGrover_PreScanRespectsContextCancellation is the regression test
// for finding I3: Grover's classical pre-scan of all 2^bits oracle
// inputs (to determine M) never checked ctx AFTER it started, so a
// deadline expiring mid-scan was ignored until the full 2^bits calls
// finished (the reviewer's own probe: over a million oracle calls made
// after the deadline had already expired). The oracle here cancels ctx
// itself after a fixed number of calls -- a deterministic way to
// simulate "the context expires partway through the scan" with no
// wall-clock race, so this test's pass/fail does not depend on machine
// speed.
func TestGrover_PreScanRespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls int
	oracle := func(x int) bool {
		calls++
		if calls == 100 {
			cancel()
		}
		return x == 12345
	}

	_, _, err := Grover(ctx, 20, oracle) // unfixed, a full pre-scan is 2^20 = 1,048,576 calls
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls > 10000 {
		t.Fatalf("expected the pre-scan to bail soon after ctx was cancelled mid-scan (at call 100), got %d calls before stopping -- well on its way to the full %d", calls, 1<<20)
	}
}

// TestShor_RespectsContextExpiringMidAttempt is the regression test for
// finding I4: Shor only checked ctx between whole attempts (each
// ~dozens of controlled-unitary applications over a 2^19-amplitude
// state for n=35), so a deadline expiring mid-attempt was ignored and a
// "successful" result could be returned well after the caller's
// deadline.
func TestShor_RespectsContextExpiringMidAttempt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	_, _, err := Shor(ctx, 35)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded once the deadline expired mid-attempt, got %v", err)
	}
}

// TestDiscreteLogBabyStepGiantStep_RejectsGZeroModP is the regression
// test for finding I2's first bug: g ≡ 0 (mod p) silently returned a
// WRONG answer (x=4 for g=0,h=5,p=7, even though 0^4 mod 7 = 0, not 5),
// because gInv = modPow(0, p-2, p) = 0 collapses every giant step onto
// the same baby-step entry.
func TestDiscreteLogBabyStepGiantStep_RejectsGZeroModP(t *testing.T) {
	if _, _, err := DiscreteLogBabyStepGiantStep(context.Background(), 0, 5, 7); err == nil {
		t.Fatalf("expected an error for g=0 (mod p), which has no well-defined discrete log, got a result with nil error")
	}
	if _, _, err := DiscreteLogBabyStepGiantStep(context.Background(), 7, 3, 7); err == nil {
		// g=7 reduces to 0 mod p=7 -- same bug via a different g.
		t.Fatalf("expected an error for g=7 (≡0 mod 7), got a result with nil error")
	}
}

// TestDiscreteLogBabyStepGiantStep_RejectsCompositeModulusWrongAnswers
// is the regression test for finding I2's second bug: the Fermat
// -little-theorem-based modular inverse (g^(p-2) mod p) is only valid
// for PRIME p; for composite p it can silently produce a WRONG x. The
// fix must at minimum verify g^x ≡ h (mod p) before returning success,
// so a wrong candidate is caught rather than returned.
func TestDiscreteLogBabyStepGiantStep_RejectsCompositeModulusWrongAnswers(t *testing.T) {
	// p=21 (composite, =3*7), g=2, h=11: review found this returns x=9
	// with nil error, but 2^9 mod 21 = 8, not 11.
	x, _, err := DiscreteLogBabyStepGiantStep(context.Background(), 2, 11, 21)
	if err == nil && modPow(2, x, 21) != 11%21 {
		t.Fatalf("expected either an error or a VERIFIED answer for composite p=21, got x=%d (2^%d mod 21 = %d, want 11) with nil error", x, x, modPow(2, x, 21))
	}
}

// TestDiscreteLogBabyStepGiantStep_ReducesNegativeAndHugeG is the
// regression test for finding I2's third bug: g was never reduced mod p
// before use, so a negative g (e.g. g=-2, p=23, equivalent to g=21)
// incorrectly reported "no solution" even though one exists, and a huge
// g could overflow int64 in cur*g.
func TestDiscreteLogBabyStepGiantStep_ReducesNegativeAndHugeG(t *testing.T) {
	const p = 23
	want := modPow(21, 5, p) // a real power of g≡21 (mod 23)
	x, _, err := DiscreteLogBabyStepGiantStep(context.Background(), -2, want, p)
	if err != nil {
		t.Fatalf("expected g=-2 (≡21 mod 23) to be reduced and solved like g=21, got error: %v", err)
	}
	if modPow(-2, x, p) != want && modPow(21, x, p) != want {
		t.Fatalf("expected a verified solution, got x=%d", x)
	}
}

// TestDiscreteLogBabyStepGiantStep_RejectsInvalidModulus is the
// regression test for finding I2's fourth bug: p=0 panicked with
// "integer divide by zero", and a negative p produced a nonsensical
// error message rather than a clear rejection.
func TestDiscreteLogBabyStepGiantStep_RejectsInvalidModulus(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("expected a clean error for p=0, got a panic: %v", r)
		}
	}()
	if _, _, err := DiscreteLogBabyStepGiantStep(context.Background(), 2, 1, 0); err == nil {
		t.Fatalf("expected an error for p=0, got nil")
	}
	if _, _, err := DiscreteLogBabyStepGiantStep(context.Background(), 2, 1, -7); err == nil {
		t.Fatalf("expected an error for a negative modulus, got nil")
	}
	if _, _, err := DiscreteLogBabyStepGiantStep(context.Background(), 2, 1, 1); err == nil {
		t.Fatalf("expected an error for p=1 (trivial group), got nil")
	}
}
