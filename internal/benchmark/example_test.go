package benchmark

import (
	"bytes"
	"context"
	"fmt"

	"banksec-lab/internal/config"
	"banksec-lab/internal/harness"
)

// ExampleRunComparative_ledgerTamper is a meaningful, runnable benchmark
// example: the ledger-tamper attack (Milestone 8), 5 repetitions per
// mode, vulnerable vs. hardened. Reproduce it directly with:
//
//	go test ./internal/benchmark/... -run ExampleRunComparative_ledgerTamper -v
//
// It demonstrates the full pipeline this package provides -- comparative
// execution, summary statistics, and JSON/CSV export -- against a real,
// registered attack, not a synthetic/mocked one. The printed
// SuccessRate/N/Errors values are a genuine prediction this example
// actually verifies, not a hardcoded string: ledger-tamper's own Verify
// defines Success as "the tamper went UNDETECTED" (the attacker's
// perspective), so hardened (which runs the balance-invariant-violation
// detection rule) must show 0% and vulnerable (no detection rules
// configured) must show 100%, deterministically, every run -- and
// Errors must be 0 for both (a security review, finding M10, noted an
// earlier version of this example printed the `reps` CONSTANT as `n`
// rather than Summary's own N, and never checked RunErr at all, so a
// hardened 0% caused by every run silently erroring would have looked
// identical to a hardened 0% caused by genuine detection).
func ExampleRunComparative_ledgerTamper() {
	vulnerableProfile, err := config.Load("../../configs/vulnerable.json")
	if err != nil {
		fmt.Println("load vulnerable profile:", err)
		return
	}
	hardenedProfile, err := config.Load("../../configs/hardened.json")
	if err != nil {
		fmt.Println("load hardened profile:", err)
		return
	}

	runner := harness.NewRunner()

	const reps = 5
	const seed = 1
	raw, err := RunComparative(context.Background(), runner, harness.NewLedgerTamperScenario, vulnerableProfile, hardenedProfile, reps, seed)
	if err != nil {
		fmt.Println("RunComparative:", err)
		return
	}

	summaries := Summarize(raw)
	for _, s := range summaries {
		fmt.Printf("%s/%s: SuccessRate=%.0f%% (n=%d, errors=%d)\n", s.ScenarioID, s.Mode, s.SuccessRate*100, s.N, s.Errors)
	}

	// Export both formats to confirm the pipeline runs end-to-end. Only
	// non-emptiness is printed, not an exact byte count: both formats
	// embed each run's real wall-clock Timestamp, whose formatted
	// length (RFC3339Nano trims trailing zero fractional-second digits)
	// varies run to run -- an exact byte count would make this example
	// flaky for reasons having nothing to do with correctness.
	var jsonBuf, csvBuf bytes.Buffer
	if err := ExportJSON(&jsonBuf, raw, summaries); err != nil {
		fmt.Println("ExportJSON:", err)
		return
	}
	if err := ExportCSV(&csvBuf, raw, summaries); err != nil {
		fmt.Println("ExportCSV:", err)
		return
	}
	fmt.Printf("exported %d raw runs as JSON (non-empty: %v) and CSV (non-empty: %v)\n", len(raw), jsonBuf.Len() > 0, csvBuf.Len() > 0)

	// Output:
	// ledger-tamper/vulnerable: SuccessRate=100% (n=5, errors=0)
	// ledger-tamper/hardened: SuccessRate=0% (n=5, errors=0)
	// exported 10 raw runs as JSON (non-empty: true) and CSV (non-empty: true)
}
