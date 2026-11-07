# BankSec Lab

BankSec Lab is a local, synthetic banking-security research simulator: a
minimal double-entry banking backend, a real (if simplified) wire
protocol, three cryptographic profiles (an intentionally weak
educational one, a real "standard" one, and a real post-quantum one),
and a library of registered attack scenarios that drive the system
exactly as a real attacker or protocol client would — adjudicated by a
read-only oracle that never trusts an attack's own claim of success.
Everything in this repository operates on fabricated accounts,
fabricated keys, and fabricated data; **no asset here is ever real money,
a real identity, or a real credential** (see `docs/THREAT_MODEL.md` §1).

This README documents the system **as it is actually implemented**, not
as it was originally planned — every command below was run against this
repository during its own documentation pass; see
`docs/MILESTONE_12_VERIFICATION_REPORT.md` for the full independent
verification evidence (301/301 tests passing, 0 data races, a live
binary walkthrough).

## Table of contents

- [Installation](#installation)
- [Build](#build)
- [Test](#test)
- [Running the simulator](#running-the-simulator)
- [Running individual attacks](#running-individual-attacks)
- [Running the full attack suite](#running-the-full-attack-suite)
- [Running benchmarks](#running-benchmarks)
- [Vulnerable and hardened configurations](#vulnerable-and-hardened-configurations)
- [Result interpretation](#result-interpretation)
- [Attack-surface and data-leak matrices](#attack-surface-and-data-leak-matrices)
- [Adding a new attack](#adding-a-new-attack)
- [Adding a cryptographic algorithm](#adding-a-cryptographic-algorithm)
- [Quantum-inspired simulations](#quantum-inspired-simulations)
- [AI-agent experiments](#ai-agent-experiments)
- [Known limitations](#known-limitations)
- [Project documentation map](#project-documentation-map)

## Installation

**Go version:** this project requires **Go 1.27.3** or later (pinned in
`go.mod`; it uses the standard library's `crypto/mldsa` and
`crypto/mlkem` packages, which are not available in older Go versions).
Check your version with:

```bash
go version
```

**Dependencies:** this project has exactly **one** direct third-party
dependency, `modernc.org/sqlite` (a pure-Go SQLite driver — no cgo, no
system SQLite library needed), used by `internal/ledger`,
`internal/audit`, and `internal/keystore` for their persistent storage.
Everything else — all signatures, encryption, MACs, and key encapsulation
— comes from the Go standard library; **no other cryptography library is
used anywhere in this project** (see `docs/CRYPTOGRAPHY.md` §1.3 for why
the originally-planned `cloudflare/circl` fallback for post-quantum
signatures turned out unnecessary). Every other entry in `go.mod` is a
transitive dependency of `modernc.org/sqlite` itself.

Clone the repository and fetch dependencies:

```bash
git clone <this-repository-url>
cd <repository-directory>
go mod download
```

## Build

```bash
go build ./...
```

Builds every package. The only `main` package in this repository is
`cmd/banksec`; to produce a named binary:

```bash
go build -o banksec ./cmd/banksec     # banksec.exe on Windows
```

## Test

```bash
gofmt -l .                  # formatting check; empty output = clean
go vet ./...                # static analysis
go test -count=1 ./...      # full test suite
go test -race -count=1 ./...  # same, with the race detector
```

`go test -race` requires a C compiler available on your `PATH` (the race
detector's runtime is not pure Go, regardless of this project's own
pure-Go SQLite driver). On Windows, this typically means installing a
mingw-w64 GCC toolchain and setting `CC` to its path; on Linux/macOS, a
system `gcc`/`clang` is normally already present.

As of this writing, the full suite passes **301 tests across all 17
packages**, with **0 failures and 0 data races** under both commands —
see `docs/MILESTONE_12_VERIFICATION_REPORT.md` for the complete,
independently-reproduced evidence (exact commands, exact output, a live
binary walkthrough).

## Running the simulator

`cmd/banksec` is a CLI that wires a full client-to-backend-to-vault
stack (protocol client, backend, ledger, keystore, audit, Detection
Engine) in a single process and sends one banking operation per
invocation. **It always runs under `configs/hardened.json`** — there is
no `--profile` flag to select a different configuration (see
[Known limitations](#known-limitations)). Persistent storage lives in a
`data/` directory created next to wherever you run the binary.

```bash
go build -o banksec ./cmd/banksec

./banksec create-account -owner=alice
# account=acct-<hex>

./banksec create-account -owner=bob
# account=acct-<hex>

./banksec deposit -account=<alice's account> -amount=1000 -as=alice
./banksec balance  -account=<alice's account> -as=alice
# balance=1000

./banksec transfer -from=<alice's account> -to=<bob's account> -amount=300 -as=alice
./banksec withdraw -account=<alice's account> -amount=200 -as=alice
./banksec balance  -account=<alice's account> -as=alice
# balance=500

./banksec history  -account=<alice's account> -as=alice
# history=[{"TxID":"tx-...","Amount":1000,...},{"TxID":"tx-...","Amount":-300,...},{"TxID":"tx-...","Amount":-200,...}]
```

Supported operations (`-owner`, `-account`, `-from`, `-to`, `-amount`,
`-as` flags, as applicable per operation — see `cmd/banksec/cli.go`'s
`paramsForOp`): `create-account`, `deposit`, `withdraw`, `transfer`,
`balance`, `history`.

Authorization is enforced server-side under the hardened profile: an
actor (`-as`) acting on an account they don't own is rejected —

```bash
./banksec withdraw -account=<alice's account> -amount=50 -as=bob
# unauthorized: unauthorized   (exit status 2)
```

The `data/` directory is `.gitignore`d; delete it to start from a
genuinely fresh state.

## Running individual attacks

Every attack is a registered `harness.Scenario` with its own test(s) in
`internal/harness`. Run one directly by test name:

```bash
go test -v ./internal/harness/... -run TestScenario_LedgerTamper_DetectedHardened_UndetectedVulnerable
```

This runs the `ledger-tamper` attack under both `configs/hardened.json`
(subtest `hardened`, expected to be detected) and `configs/vulnerable.json`
(subtest `vulnerable`, expected to go undetected) — the standard pattern
every differential attack test in this project follows. See
`docs/ATTACK_SURFACES.md` §9 for the full list of 11 registered attack
IDs and their test names, and `docs/ATTACK_COVERAGE.md` for exactly what
each one does and why.

To drive an attack programmatically (as `internal/benchmark` and
`internal/agent` both do) rather than through a test:

```go
env, _ := harness.NewLocalEnvironment(profile)   // profile loaded via config.Load
defer env.Close()
runner := harness.NewRunner()
result, err := runner.Run(ctx, harness.NewLedgerTamperScenario(), env, seed)
// result.Success, result.DetectionLatencyMS, result.Attempts, ...
```

## Running the full attack suite

To discover every registered scenario and confirm there are no ID
collisions:

```bash
go test -v ./internal/harness/... -run TestRegisterAllScenarios_NoCollisionsAllCategoriesPresent
```

To actually *run* every registered scenario in one comparative pass
(vulnerable vs. hardened, with summary statistics and JSON/CSV export),
use `internal/benchmark.RunSuite` — see
[Running benchmarks](#running-benchmarks) and
`docs/BENCHMARK_EXAMPLES.md` §3 for a complete, runnable program that
does exactly this against all 11 registered scenarios.

## Running benchmarks

A committed, runnable, self-verifying example (a real Go
[testable example](https://go.dev/blog/examples), not just a code
snippet):

```bash
go test ./internal/benchmark/... -run ExampleRunComparative_ledgerTamper -v
```

Runs the `ledger-tamper` attack 5 times under each profile, computes
summary statistics, and exports both JSON and CSV — its expected output
is checked by Go's own test runner, so it fails the build if the
underlying behavior ever regresses. For a full attack-suite benchmark
(every registered scenario, 30 repetitions each, exported to
`benchmark_results.json`/`.csv`), see the complete worked example in
`docs/BENCHMARK_EXAMPLES.md` §3. Full methodology — what's measured, how
summary statistics are computed, and what's explicitly out of scope for
this v1 — is in `docs/BENCHMARK_METHODOLOGY.md`.

There is no `cmd/banksec benchmark` subcommand; benchmarks are run
through Go test/code, not the CLI (see
[Known limitations](#known-limitations)).

## Vulnerable and hardened configurations

Two committed profiles, `configs/vulnerable.json` and
`configs/hardened.json`, differing only in which protections are active
— never in starting data (`internal/config.SecurityProfile`):

| Setting | `vulnerable.json` | `hardened.json` |
|---|---|---|
| `protocol_auth_enforced` | `false` | `true` |
| `authz_enforced` | `false` | `true` |
| `atomicity_enforced` | `false` | `true` |
| `keystore_encrypted_at_rest` | `false` | `true` |
| `audit_hash_chained` | `false` | `true` |
| `detection_rules` | `[]` (none) | `["balance-invariant-violation", "audit-chain-violation"]` |
| `crypto_profile` / `min_accepted_crypto_profile` | `standard` / `standard` | `standard` / `standard` |

Every registered attack scenario (except `key-revocation`, which must
hold in *every* mode by design, and the two cryptographic scenarios,
which fork on a separate `weak-educational`/`standard` axis instead — see
`docs/ATTACK_SURFACES.md` §9) succeeds under `vulnerable.json` and is
blocked or detected under `hardened.json`. A `SecurityProfile` is loaded
once per CLI invocation or benchmark run and is immutable for that run's
duration — there is no runtime API to flip modes mid-session
(`docs/ARCHITECTURE.md` §5).

## Result interpretation

Every attack run produces one `harness.Result` (the common schema every
other package reuses — `internal/benchmark` wraps it, never redefines
it):

| Field | Meaning |
|---|---|
| `AttackID` / `AttackType` | the scenario's own ID / category |
| `TargetConfiguration` | which `SecurityProfile.Name` ran (`"vulnerable"`/`"hardened"`) |
| `Success` | **evidence-based only** — from the Oracle, never from the attack's own `Exec` return value ("never trust Exec's own claim" is enforced structurally by `harness.Runner`, not just by convention) |
| `ExecutionTimeMS` | real wall-clock duration of the run |
| `Attempts` | how many internal attempts the scenario's own `StopCond` allowed before stopping |
| `TimeToCompromiseMS`, `DataLeakedBytes`, `RecordsCompromised`, `DetectionLatencyMS`, `ComputationalCost`, `MemoryUsageBytes` | **optional, scenario-specific** impact/detection measurements — `nil` when inapplicable to that scenario, *never* fabricated as `0`. See [the data-leak matrix](#attack-surface-and-data-leak-matrices) for exactly which scenario populates which field; `TimeToCompromiseMS` and `MemoryUsageBytes` are defined in the schema but not populated by any currently-registered scenario |
| `Seed` | the reproducibility seed this run used |

A `nil` optional field is not a missing measurement to be alarmed about
— it means that metric does not apply to that particular attack (e.g. an
integrity-violation attack like `ledger-tamper` has no
`DataLeakedBytes`, since nothing was exfiltrated). When aggregating many
runs (`internal/benchmark.Summarize`), an absent metric is excluded from
that metric's mean/median/stddev entirely, and `SampleSize`/`N`/`Errors`
tell you exactly how many runs each aggregate actually covers — never
guess from the mean alone.

## Attack-surface and data-leak matrices

The full, verified-against-the-actual-registry tables — every registered
scenario ID, its target component, its vulnerable/hardened outcome, and
which impact field (if any) each one populates — are in
`docs/ATTACK_SURFACES.md` §9 and §10. In brief: **11 scenarios are
implemented and verified** across application, protocol, ledger,
key-management, and cryptographic categories; **2 are explicitly
unsupported** with documented technical reasons (small-parameter
Diffie-Hellman discrete-log — no key-exchange primitive exists in this
codebase at all; static-IV reuse detection — ECB mode has no IV concept
to reuse). See `docs/ATTACK_COVERAGE.md` for the full implementation
rationale behind each one.

## Adding a new attack

1. Create `internal/harness/scenario_<yourcategory>.go` (or add to an
   existing one in the same category) with a `NewXxxScenario() Scenario`
   constructor function — **a constructor, not a bare `Scenario` value**:
   `harness.Registry.Register` takes `func() Scenario` specifically so
   every lookup gets independent closure state (a security review found
   that sharing one `Scenario` value across repeated runs lets its own
   closure variables leak between them — see `internal/harness/registry.go`'s
   doc comment).
2. Fill in `ID` (a unique string), `Category`, `TargetComponent`,
   `Exec` (drives the real target — `env.Client` for protocol-reachable
   attacks, `env.Priv` for the insider/compromised-host bypass used by
   ledger/key-management attacks — never a hardcoded result), and
   `Verify` (inspects the **Oracle**, never `Exec`'s own return value, to
   decide success and gather `Evidence`). `Prereqs`/`StopCond`/`Timeout`
   are optional.
3. Register it in `internal/harness/registry_scenarios.go`'s
   `RegisterAllScenarios`.
4. Write a test proving BOTH the attack-succeeds path (typically under
   `configs/vulnerable.json`) and the attack-fails/detected path
   (typically under `configs/hardened.json`) — see any existing
   `scenario_*_test.go` for the pattern. A `Scenario` whose `Exec`/
   `Verify` just returns a hardcoded value, with no test proving it
   actually exercises the target component, is not acceptable (see
   `docs/ATTACK_COVERAGE.md`'s own "Implemented & Verified" criteria).
5. Update `docs/ATTACK_COVERAGE.md` and `docs/ATTACK_SURFACES.md` §9/§10
   to list the new scenario.

## Adding a cryptographic algorithm

See `docs/CRYPTOGRAPHY.md` §6 for the full guide. In short:
`internal/crypto.Engine` (five methods: `Encrypt`, `Decrypt`, `Sign`,
`Verify`, `MAC`, each dispatched on a `domain.CryptoProfileName`) is the
only seam every other package goes through — add a new primitive to an
existing profile's own file and its `switch profile` branch, or wire a
whole new profile into every method explicitly (`ErrProfileNotImplemented`
catches anything left unwired). The binding rule is non-negotiable: no
cryptographic primitive is ever hand-rolled from scratch; real
cryptography is Go standard library only, and an intentionally weak
construction must be proven weak by a real test, never just asserted in
a comment.

## Quantum-inspired simulations

`internal/quantum` is a from-scratch classical state-vector simulator —
genuine unitary gate operations over complex amplitudes, not a
hardcoded demo — implementing Shor's and Grover's algorithms at toy
scale, plus two classical cryptanalysis baselines (trial-division RSA
factoring, baby-step-giant-step discrete log) to compare their
theoretical complexity against. **It is structurally disconnected from
`internal/crypto`** (enforced by a test that checks it imports no other
package in this module at all) and never touches this project's real
keys.

```bash
go test -v ./internal/quantum/... -run TestShor_Factors15      # genuinely factors 15 = 3×5 via simulated quantum phase estimation
go test -v ./internal/quantum/... -run TestGrover_FindsMarkedElement
```

**The single most important limitation to understand:** this is a
classical simulation, and classically simulating `n` qubits costs
`O(2^n)` in both time and memory — the *opposite* of the speedup a real
quantum computer is theorized to provide. No quantum speedup is
demonstrated or claimed anywhere in this package; every output carries a
mandatory label saying exactly that. Grover's algorithm is also
genuinely probabilistic here (an honestly-reported, real chance of
returning "no marked element found," not a bug). Full research
methodology, including a dedicated "what cannot be concluded" section,
is in `docs/QUANTUM_METHODOLOGY.md` — read it before citing any result
from this package.

## AI-agent experiments

`internal/agent` is an offline-first, deterministic attack-selection
framework — explicitly **not** presented as an advanced AI agent (it is
a rule-based policy, not a learning one) — that drives the same
Registry/Runner/Environment/Oracle interfaces any other caller uses, with
no new capability and a hard step budget (no unbounded execution). A
`Policy` interface is the one seam a future LLM-backed policy could
plug into without any change to the bounded-execution guarantees — see
`docs/AGENT_LLM_INTEGRATION.md` for exactly what that would and would
not change.

```bash
go test -v ./internal/agent/... -run TestControlledExperiment_BaselineAgentAgainstRealScenarios
```

This is a genuine controlled experiment, not a smoke test: the same
deterministic-policy-driven agent against real `ledger-tamper`/
`audit-tamper` scenarios reports 0 successful compromises under
hardened (both detected) and 2 under vulnerable (both undetected) — a
falsifiable prediction the test actually checks.

## Known limitations

Disclosed honestly, independently re-confirmed against the actual code
during Milestone 13's documentation pass (not copied from an earlier
document without checking):

- **No Diffie-Hellman / key-exchange primitive anywhere in
  `internal/crypto`** — `Engine` has no key-exchange method, and the
  "standard" profile's own originally-planned X25519 key agreement was
  never implemented. First flagged in Milestone 4's security review,
  repeated in every review since; still an open design question. See
  `docs/CRYPTOGRAPHY.md` §1.2.
- **Static-IV reuse detection is unsupported** — not a missed
  implementation step but a genuine inconsistency in the original design
  (ECB mode, which is what the weak-educational profile actually uses,
  has no IV/nonce concept to reuse at all).
- **No production code path calls `keystore.Store.Generate`** — every
  key-related attack scenario uses a test-fixture helper
  (`Environment.GenerateTestKey`) instead, since nothing in
  `cmd/banksec`/`internal/backend`/`internal/protocol` actually sources
  key material from the keystore yet (ledgered since Milestone 5).
- **`cmd/banksec` has no `--profile` flag** — it always runs under
  `configs/hardened.json`; the vulnerable profile can only be exercised
  through tests and library code, never the shipped binary.
- **No CLI subcommand for `internal/agent` or `internal/benchmark`** —
  both are fully functional and tested, driven entirely through Go code
  (consistent with their own milestones' scoping, which named only new
  packages, not CLI integration).
- **`RolePrivilegedOperator` is defined but never functionally used** —
  `internal/domain` defines two principal roles, but only
  `RoleAccountOwner`-vs-`RoleAccountOwner` authorization (an owner acting
  on an account they don't own) is actually checked anywhere; the
  originally-planned "operator acting across accounts" threat class has
  no operator-only operation to even target. See `docs/THREAT_MODEL.md`
  §5.
- **Only one transport exists: `net.Pipe`** — the originally-planned
  "optional loopback-TCP mode," for experiments needing real network
  timing, was never implemented. See `docs/ARCHITECTURE.md` §1.
- Benchmark v1 deliberately has no hardware fingerprinting, no noise
  modeling, and no outlier rejection — a documented YAGNI scoping
  decision, not an oversight (`docs/BENCHMARK_METHODOLOGY.md` §5).

## Project documentation map

| Document | Covers |
|---|---|
| `docs/ARCHITECTURE.md` | package layout, component responsibilities, communication design, security-mode isolation |
| `docs/THREAT_MODEL.md` | assets, trust boundaries, threat categories, authorization model |
| `docs/ATTACK_SURFACES.md` | per-category attack design, plus the as-implemented attack-surface and data-leak matrices (§9-10) |
| `docs/ATTACK_COVERAGE.md` | implementation/verification status of every registered attack scenario |
| `docs/CRYPTOGRAPHY.md` | the three crypto profiles, what's actually implemented vs. originally planned, how to add a new algorithm |
| `docs/BENCHMARK_METHODOLOGY.md` | comparative run procedure, metrics, summary statistics, output format |
| `docs/BENCHMARK_EXAMPLES.md` | runnable benchmark examples and their exact reproduction commands |
| `docs/QUANTUM_METHODOLOGY.md` | what each quantum-inspired experiment measures, and what cannot be concluded from any of them |
| `docs/AGENT_LLM_INTEGRATION.md` | how a future LLM-backed policy could integrate without compromising isolation |
| `docs/MILESTONE_12_VERIFICATION_REPORT.md` | independent, evidence-based verification of the whole system |
| `CONVENTIONS.md` | coding conventions used throughout this codebase |
