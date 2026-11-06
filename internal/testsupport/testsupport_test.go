package testsupport

import (
	"testing"
	"time"
)

func TestTempSQLitePath_Unique(t *testing.T) {
	p1 := TempSQLitePath(t)
	p2 := TempSQLitePath(t)

	if p1 == p2 {
		t.Fatalf("expected two calls to TempSQLitePath to return different paths, both were %q", p1)
	}
}

func TestFixedClock_Stable(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := FixedClock(start)

	first := clock()
	time.Sleep(10 * time.Millisecond)
	second := clock()

	if !first.Equal(second) {
		t.Fatalf("expected FixedClock to return a stable instant, got %v then %v", first, second)
	}
	if !first.Equal(start) {
		t.Fatalf("expected FixedClock to return the given start time, got %v", first)
	}
}
