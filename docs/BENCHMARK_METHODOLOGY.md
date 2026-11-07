# BankSec Lab — Benchmark Methodology

**Status:** Implemented (Milestone 11; see `internal/benchmark`),
reviewed against the actual code during Milestone 13's documentation
pass. Scope remains **v1 (minimal)** as originally planned — fuller
methodology (hardware fingerprinting, noise modeling, outlier rejection)
is still explicitly deferred, not omitted by oversight (see §5). Several
implementation details below were refined during development beyond
what this document originally specified, each noted inline as "as
implemented."

## 1. Principles (binding, from source spec §11.1)

- Preserve raw, per-run results — never discard them in favor of only a
  summary.
- Record software version, configuration, and seed with every run.
- Include failed and inconclusive runs in the raw output, not just
  successes.
- Define success criteria *before* running the experiment (in the attack
  scenario's registration, per `ATTACK_SURFACES.md`).
- Never hardcode a benchmark outcome. Every metric is a measurement of an
  actual execution.

## 2. Comparative run procedure

1. Prepare a synthetic dataset and experiment configuration (fixed seed).
2. Initialize storage to a defined starting state under **vulnerable**
   `SecurityProfile`.
3. Run the registered scenario; collect the raw result (§3).
4. Re-initialize storage to the *same* defined starting state (same seed),
   now under **hardened** `SecurityProfile`.
5. Run the same scenario; collect the raw result.
6. Repeat steps 2-5 for N repetitions (N configurable per experiment,
   documented default: 30).
7. Preserve every raw run. Compute summary statistics (§4) from the full
   set, never from a subset chosen after seeing results.
8. Export raw results and summary to JSON and CSV.

"Defined starting state" means: the ledger and keystore are
re-initialized from the same fixture/seed before each mode's run, so the
only difference between the two runs is the active `SecurityProfile` —
never an incidental difference in starting data.

**As implemented** (`internal/benchmark.RunComparative`): "re-initialize
storage" means building a brand-new `harness.Environment` per run (never
reusing one across runs or modes), and "a fresh Scenario instance per
run" (not just fresh storage) turned out to matter too — a security
review during development (finding C1, Critical) found that reusing one
`harness.Scenario` VALUE across repetitions let a Scenario's own closure
state (several Milestone 8 scenarios track state like "did Exec reach
its attack step yet" in a closure variable) leak between runs, so a run
whose infrastructure failed could silently inherit a prior unrelated
run's "succeeded" state. `RunComparative` now takes a
`newScenario func() harness.Scenario` constructor, called fresh for
every single run (not once per rep) — see
`internal/benchmark/runner.go`'s own doc comment for the full
explanation. `RunComparative` also rejects `vulnerable.Name ==
hardened.Name` outright (a second review finding, I3): two profiles
sharing a `Name` would make the exported `target_configuration` field
identical for both, silently erasing which one actually ran.

## 3. Metrics recorded per run

From source spec §11, recorded when applicable to the scenario (an
inapplicable metric is recorded as explicitly absent/null, never
fabricated). **As implemented**, the exact field names (matching
`internal/harness.Result`'s own JSON-exported shape, via
`internal/benchmark/export.go`'s `rawRunJSON`) are:

`run_id`, `timestamp`, `attack_id`, `target_configuration`
(vulnerable/hardened — **as implemented**, sourced from
`RunComparative`'s own `"vulnerable"`/`"hardened"` labels, not from
`harness.Result` directly; see §2's C1/I3 note above for why), `success`
(evidence-based, from the harness oracle, never assumed),
`execution_time_ms`, `time_to_compromise_ms`, `data_leaked_bytes`,
`records_compromised`, `detection_latency_ms`, `attempts`,
`computational_cost`, `memory_usage_bytes`, `seed`, and `run_error` (a
field not in the original plan — see §7's known-limitations update for
why it was added).

`detection_latency_ms` specifically = `detection_event.timestamp -
attack_event.timestamp`, sourced from the Detection Engine's own emitted
events (`ARCHITECTURE.md` §4.3) — never estimated or assumed.

**Not every metric is populated by every scenario, or by any scenario at
all, as of this writing:** `time_to_compromise_ms` and
`memory_usage_bytes` are defined in the schema but never set by any
currently-registered Milestone 8 scenario (confirmed by direct
inspection across every `internal/harness/scenario_*.go` file — see
`ATTACK_SURFACES.md` §10's full data-leak/impact matrix for exactly
which scenario populates which field). This is not a bug: a
benchmark consumer should expect `nil`/absent for these two fields on
every current scenario, not assume they are simply "usually 0."

## 4. v1 summary statistics

Over the N raw runs per (scenario, mode) pair: **mean, median, standard
deviation** (population stddev, dividing by N — v1 treats the N runs as
the complete population, not a sample estimating a larger one) for each
numeric metric, plus **success rate** (fraction of runs where `success
== true`). No outlier rejection, no confidence intervals, no
hardware-normalization in v1.

**Refined during development, beyond the original plan** (security
review findings I2/I3): a run whose own `harness.Runner.Run` call
errored (`run_error` populated) has no meaningful `success`/metric
values at all — it's an infrastructure failure, not an attack outcome.
An earlier implementation folded such a run's (mostly zero-valued)
`Result` straight into the mean/success-rate, silently biasing the
statistics. **As implemented**, `Summary` adds two fields beyond the
original plan: `n` (total runs in the group, including errored ones) and
`errors` (how many of those errored); `success_rate` and every
mean/median/stddev are computed over the `n - errors` *completed* runs
only. A metric present in zero completed runs for a group is omitted
entirely from the summary (never recorded as a fabricated `0`) — a
companion `sample_size` map records, per metric, exactly how many
completed runs' worth of data each aggregate actually covers, so "this
mean covers all N runs" vs. "this mean covers only 3 of them" is never
ambiguous.

## 4.5 Full attack-suite execution (added during Milestone 11, not in the original plan)

`internal/benchmark.RunSuite(ctx, runner, registry, vulnerable, hardened,
reps, seed)` runs §2's comparative procedure once per `Scenario`
currently registered (`registry.All()`), keyed by each scenario's own
ID, using the same `reps`/`seed`/profile pair across the whole attack
surface — see `docs/BENCHMARK_EXAMPLES.md` for a runnable example against
every registered Milestone 8 scenario. If one scenario's `RunComparative`
call fails outright (not an individual run failing — that is already
preserved as `run_error` — but something that stops the WHOLE comparative
run, such as a context cancellation), `RunSuite` still returns whatever
it collected for that scenario before the failure, alongside the error,
rather than discarding it.

## 5. Explicitly deferred (not built in v1)

- Hardware/software environment fingerprinting (CPU model, OS, Go version
  pinned per run) — deferred until a specific experiment's conclusions
  depend on cross-machine comparability.
- Noise-source documentation and warm-up-run discarding — deferred until a
  specific metric shows measurement noise that misleads a conclusion.
- Outlier rejection / robust statistics — deferred for the same reason.

This is a deliberate YAGNI scoping decision from brainstorming, not an
oversight: building this machinery before any real experiment has
demonstrated a need for it would be speculative work. If a future
experiment's results are visibly noisy or non-comparable, extend this
document with the specific technique needed, with its own rationale.

## 6. Output format

**As implemented** (`internal/benchmark.ExportJSON`/`ExportCSV`), raw
and summary are **not** two separate files — they are written together
in ONE call, so it is structurally impossible to export one without the
other (enforcing §1's "always shipped alongside, never instead of"
principle by construction rather than by convention):

- **JSON** (`ExportJSON`): one document, `{"raw": [...], "summary":
  [...]}`. Each raw record has every field in §3 (JSON `null` for an
  inapplicable/absent metric — `encoding/json`'s native behavior for a
  nil pointer, never a fabricated `0`).
- **CSV** (`ExportCSV`): one stream, two blocks separated by a blank
  line — raw rows first, then summary rows. A standard `csv.Reader`
  cannot parse the combined stream in a single pass (the two blocks have
  different column counts) — split on the blank line first, then parse
  each block with its own `csv.Reader` (see
  `internal/benchmark/export_test.go`'s own round-trip test for the
  pattern). An absent metric is an **empty cell**, never the text `"0"`
  or `"null"` (CSV has no native null). A `run_error` value is sanitized
  to a single physical line (embedded newlines escaped) before writing,
  so a multi-line error message can never be mistaken for the
  raw/summary section boundary.

## 7. Known limitations (honest)

- A default of 30 repetitions is a starting point, not a statistically
  derived power calculation; if a scenario's variance is high, the plan
  should allow raising N per-experiment rather than trusting a universal
  default.
- Without hardware fingerprinting (§5), results from two different
  development machines are not safely comparable to each other — only
  runs within the same machine/session should be compared until that
  limitation is addressed.
- **`run_error`** (a field not in the original source-spec metric list,
  §3) exists because real runs sometimes fail for infrastructure reasons
  unrelated to the attack itself (e.g. a `harness.Scenario` with a `nil`
  `Verify`, or a context deadline expiring mid-run) — §1's own "include
  failed and inconclusive runs in the raw output" principle requires
  recording this, not silently dropping the row or pretending it
  succeeded.
- **No CLI wiring** (`cmd/banksec` has no `benchmark` subcommand): every
  example in `docs/BENCHMARK_EXAMPLES.md` is a `go test`/`go run`
  invocation, not a shipped CLI command. Consistent with
  `docs/TASK_BREAKDOWN.md`'s own scoping of Milestone 11 (new packages
  only, no CLI integration named).
