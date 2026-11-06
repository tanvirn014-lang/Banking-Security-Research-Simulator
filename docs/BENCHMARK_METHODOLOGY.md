# BankSec Lab — Benchmark Methodology

**Status:** Approved design, pre-implementation. Scope: **v1 (minimal)**,
per brainstorming decision — fuller methodology (hardware fingerprinting,
noise modeling, outlier rejection) is explicitly deferred, not omitted by
oversight (see §5).

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

## 3. Metrics recorded per run

From source spec §11, recorded when applicable to the scenario (an
inapplicable metric is recorded as explicitly absent/null, never
fabricated):

`attack_id`, `target_configuration` (vulnerable/hardened),
`attack_type`, `success` (evidence-based, from the harness oracle, never
assumed), `execution_time_ms`, `time_to_compromise`,
`data_leaked_bytes`, `records_compromised`, `detection_latency`,
`attempts`, `computational_cost`, `memory_usage`, `seed`.

`detection_latency` specifically = `detection_event.timestamp -
attack_event.timestamp`, sourced from the Detection Engine's own emitted
events (`ARCHITECTURE.md` §4.3) — never estimated or assumed.

## 4. v1 summary statistics

Over the N raw runs per (scenario, mode) pair: **mean, median, standard
deviation** for each numeric metric, plus **success rate** (fraction of
runs where `success == true`). No outlier rejection, no confidence
intervals, no hardware-normalization in v1.

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

- **Raw results:** one JSON object per run, newline-delimited or as a JSON
  array, containing every field in §3 (nulls for inapplicable fields) plus
  a `run_id` and `timestamp`.
- **CSV:** flattened equivalent of the same raw records, one row per run,
  for spreadsheet-based analysis.
- **Summary:** a separate JSON/CSV pair containing the §4 aggregates per
  (scenario, mode) pair, generated from — and always shipped alongside,
  never instead of — the raw records.

## 7. Known limitations (honest)

- A default of 30 repetitions is a starting point, not a statistically
  derived power calculation; if a scenario's variance is high, the plan
  should allow raising N per-experiment rather than trusting a universal
  default.
- Without hardware fingerprinting (§5), results from two different
  development machines are not safely comparable to each other — only
  runs within the same machine/session should be compared until that
  limitation is addressed.
