# BankSec Lab — Benchmark Examples and Reproduction Commands

`internal/benchmark` has no CLI wiring yet (out of this milestone's own
scope — `docs/TASK_BREAKDOWN.md`'s Milestone 11 names only
`internal/benchmark/*.go` files, and `cmd/banksec`'s CLI today only
drives ordinary banking operations). Every example below is reproduced
through `go test`, exactly as this project's TDD-driven development has
exercised every milestone before any CLI integration existed.

## 1. A single, real comparative experiment (committed, runnable example)

`internal/benchmark/example_test.go`'s `ExampleRunComparative_ledgerTamper`
is a genuine, idiomatic Go [testable
example](https://go.dev/blog/examples): it runs the Milestone 8
ledger-tamper attack 5 times under each of the vulnerable and hardened
profiles, computes summary statistics, exports both JSON and CSV, and
*verifies* its own printed output against Go's own `// Output:` comment
mechanism — not a static description of what the code is supposed to
do, but a real assertion that fails the build if the behavior ever
changes.

**Reproduce it:**

```bash
go test ./internal/benchmark/... -run ExampleRunComparative_ledgerTamper -v
```

Expected output (the exact text Go's test runner checks):

```
ledger-tamper/vulnerable: SuccessRate=100% (n=5, errors=0)
ledger-tamper/hardened: SuccessRate=0% (n=5, errors=0)
exported 10 raw runs as JSON (non-empty: true) and CSV (non-empty: true)
```

This is a genuine, falsifiable prediction the example actually checks,
not a hardcoded string chosen to match whatever the code happened to
print: `NewLedgerTamperScenario`'s own `Verify` defines success as "the
tamper went UNDETECTED" (the attacker's perspective). Under `hardened`
(`balance-invariant-violation` registered), every one of the 5
repetitions must be caught — `SuccessRate=0%`. Under `vulnerable` (no
detection rules configured), nothing is watching — `SuccessRate=100%`.
Any future change that broke this property (e.g. a Detection Engine
regression, or a scenario change) would make this example's actual
output disagree with `// Output:` and fail `go test`.

## 2. The full benchmark test suite (every task's own tests)

```bash
go test ./internal/benchmark/... -v
```

Runs every test for Tasks 46-49 plus the `RunSuite` addendum: comparative
orchestration (`TestRunComparative_*`), summary statistics including the
"never fabricate a missing metric" tests
(`TestSummarize_AbsentMetricNeverFabricatedAsZero`), JSON/CSV export
including the "absent metric is an empty cell, not zero" test
(`TestExportCSV_AbsentMetricIsEmptyCellNotZero`), the seeded
-reproducibility test (`TestBenchmark_SameSeed_IdenticalNonTimingFields`),
and the full-suite runner (`TestRunSuite_CoversEveryRegisteredScenario`).

## 3. A full attack-suite run against every registered Milestone 8 scenario

This is not a committed test (running all 11 registered scenarios
comparatively, 30 reps each under `BENCHMARK_METHODOLOGY.md §2`'s
documented default, would make the package's own fast unit-test suite
slow) — it is a worked example showing how `RunSuite` is meant to be
used for a real benchmarking session. `internal/benchmark` is an
internal package, so this file MUST live somewhere inside this module
(a security review, finding M11, confirmed running it from an external
scratch directory fails with `use of internal package ... not allowed`)
-- e.g. `cmd/benchmark_example/main.go`:

```go
package main

import (
	"context"
	"fmt"
	"os"
	"sort"

	"banksec-lab/internal/benchmark"
	"banksec-lab/internal/config"
	"banksec-lab/internal/harness"
)

func main() {
	vulnerable, err := config.Load("configs/vulnerable.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, "load vulnerable profile:", err)
		os.Exit(1)
	}
	hardened, err := config.Load("configs/hardened.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, "load hardened profile:", err)
		os.Exit(1)
	}

	reg := harness.NewRegistry()
	if err := harness.RegisterAllScenarios(reg); err != nil {
		fmt.Fprintln(os.Stderr, "register scenarios:", err)
		os.Exit(1)
	}

	const reps = 30 // BENCHMARK_METHODOLOGY.md §2's documented default
	const seed = 1
	results, err := benchmark.RunSuite(context.Background(), harness.NewRunner(), reg, vulnerable, hardened, reps, seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "RunSuite:", err)
		os.Exit(1)
	}

	// results is a map, so its own iteration order is NOT deterministic
	// (security review finding M11) -- collect and sort scenario IDs
	// explicitly before producing any ordered output.
	ids := make([]string, 0, len(results))
	for id := range results {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var allRaw benchmark.RawResults
	for _, id := range ids {
		allRaw = append(allRaw, results[id]...)
	}
	summaries := benchmark.Summarize(allRaw)
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].ScenarioID != summaries[j].ScenarioID {
			return summaries[i].ScenarioID < summaries[j].ScenarioID
		}
		return summaries[i].Mode < summaries[j].Mode
	})

	jsonFile, err := os.Create("benchmark_results.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create JSON file:", err)
		os.Exit(1)
	}
	defer jsonFile.Close()
	if err := benchmark.ExportJSON(jsonFile, allRaw, summaries); err != nil {
		fmt.Fprintln(os.Stderr, "ExportJSON:", err)
		os.Exit(1)
	}

	csvFile, err := os.Create("benchmark_results.csv")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create CSV file:", err)
		os.Exit(1)
	}
	defer csvFile.Close()
	if err := benchmark.ExportCSV(csvFile, allRaw, summaries); err != nil {
		fmt.Fprintln(os.Stderr, "ExportCSV:", err)
		os.Exit(1)
	}

	for _, s := range summaries {
		fmt.Printf("%-30s %-12s n=%-3d errors=%-3d success_rate=%.1f%%\n", s.ScenarioID, s.Mode, s.N, s.Errors, s.SuccessRate*100)
	}
}
```

**Reproduce it** (run from the repository root, so the relative
`configs/*.json` paths resolve):

```bash
go run ./cmd/benchmark_example
```

This produces `benchmark_results.json` and `benchmark_results.csv` in
the current directory — both independently analyzable: the JSON can be
loaded by any `jq`/Python/JS tooling, and the CSV opens directly in a
spreadsheet (two sections, raw runs then summary statistics, separated
by a blank line — see `ExportCSV`'s own doc comment, including why a
single default `csv.Reader` cannot parse the WHOLE combined stream in
one pass).

**What to expect, honestly:** several Milestone 8 scenarios will show
`success_rate=0%` under BOTH modes (e.g. `key-revocation`, which per its
own doc comment must always reject a revoked key regardless of profile —
"success" there never varies by mode, since it's verifying a security
property, not demonstrating a mode-dependent attack). Others
(`crypto-toy-rsa-factor-forge`, `crypto-ecb-pattern-leakage`) are gated
to the weak-educational crypto profile and will report `success_rate=0%`
with `errors=0` (applicable=false, cleanly) against `vulnerable.json`/
`hardened.json`'s own `crypto_profile: "standard"` setting — this is
documented, expected behavior (`docs/ATTACK_COVERAGE.md`), not a
benchmarking bug. A real benchmarking session should read each
scenario's own doc comment before interpreting its summary, and should
always check `errors` alongside `success_rate` -- a scenario reporting
`errors > 0` for some runs had its own infrastructure problems that
`success_rate` (computed over only the completed runs) will not surface
on its own.
