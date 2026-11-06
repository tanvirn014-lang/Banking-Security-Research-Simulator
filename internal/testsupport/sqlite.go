// Package testsupport holds small helpers shared across this project's
// tests, so later packages don't each re-derive the same SQLite-fixture
// and deterministic-clock patterns.
package testsupport

import (
	"path/filepath"
	"testing"
	"time"
)

// TempSQLitePath returns a fresh, unique SQLite file path under t's
// temporary directory. The file and its directory are removed automatically
// when the test completes.
func TempSQLitePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.db")
}

// FixedClock returns a clock function that always reports start,
// regardless of real elapsed time — for deterministic/reproducibility tests.
func FixedClock(start time.Time) func() time.Time {
	return func() time.Time { return start }
}
