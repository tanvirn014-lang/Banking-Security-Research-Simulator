# BankSec Lab — Implementation Plan (Milestone Roadmap)

**Status:** Draft, awaiting approval. Supersedes the narrower, 5-plan
incremental roadmap sketched in
`docs/superpowers/plans/2026-11-07-foundation-core-banking.md` ("Plan 1 of
5"). That file's **Tasks 1-2 are already implemented and committed**
(worktree branch `worktree-foundation-core-banking`, commits
`269812c..8d06364`) and are retained below as Milestone 1, Tasks F1-F2 —
nothing is redone or discarded.

**Companion documents:** [TASK_BREAKDOWN.md](TASK_BREAKDOWN.md) (the actual
task cards — this file is the index), [DEPENDENCY_GRAPH.md](DEPENDENCY_GRAPH.md),
[TEST_STRATEGY.md](TEST_STRATEGY.md). Source design:
[ARCHITECTURE.md](ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md),
[ATTACK_SURFACES.md](ATTACK_SURFACES.md), [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md),
[BENCHMARK_METHODOLOGY.md](BENCHMARK_METHODOLOGY.md),
[COMPONENT_INTERFACES.md](COMPONENT_INTERFACES.md).

## One documented deviation from COMPONENT_INTERFACES.md

This roadmap introduces a new foundation package, **`internal/domain`**,
holding the shared value types (`AccountID`, `Money`, `TransactionID`,
`PrincipalID`, `Role`, `CryptoProfileName`, `DetectionRuleID`) that
`COMPONENT_INTERFACES.md` had scattered across `internal/ledger` and
`internal/backend`. Reason: `internal/audit`'s `Event.Actor` field was
typed as a bare `string` specifically to avoid an import cycle with
`internal/backend` (documented in that file). A shared `internal/domain`
package removes the need for that workaround — every package importing
`domain` instead of each other. This is a strict improvement with no
behavior change; `COMPONENT_INTERFACES.md`'s signatures otherwise stand,
read with `ledger.X`/`backend.X` mentally replaced by `domain.X` for the
seven shared types.

## Milestones at a glance

| # | Milestone | Tasks | Status | Depends on |
|---|---|---|---|---|
| 1 | Project foundation | F1-F6 | F1-F2 done, F3-F6 pending | — |
| 2 | Core transaction system | T1-T6 | pending | M1 |
| 3 | Security architecture | S1-S4 | pending | M2 |
| 4 | Cryptographic system | C1-C5 | pending | M1 (C1-C4); M3 (C5) |
| 5 | Key management | K1-K4 | pending | M2, M4 |
| 6 | Audit system | A1-A4 | pending | M2 |
| 7 | Attack framework | H1-H4 | pending | M2 only — the framework reads/writes ledger/keystore/audit interfaces, not security-mode behavior; runs in parallel with M3-M6 (see `DEPENDENCY_GRAPH.md`) |
| 8 | Attack implementations | I1-I5 | pending | M7 plus one of M3/M4/M5/M6 each, per scenario (see `DEPENDENCY_GRAPH.md`'s diagram for the exact per-task mapping) |
| 9 | Quantum-inspired simulations | Q1-Q3 | pending | M1 only (fully independent otherwise) |
| 10 | AI-agent experiments | G1-G4 | pending | M7, M8 |
| 11 | Benchmarking | B1-B4 | pending | M7 (schema), M8 |
| 12 | Integration and validation | V1-V4 | pending | everything above except M9/M10/M13 |
| 13 | Documentation and publication | P1-P3 | pending | M12 |

Full task cards (objective, files, interfaces, instructions, acceptance
criteria, tests) are in [TASK_BREAKDOWN.md](TASK_BREAKDOWN.md). This file
stays an index deliberately — a 56-task plan documented twice would drift.

## Milestone narratives

### Milestone 1 — Project foundation
Go module, CLI skeleton, config-driven `SecurityProfile` (both **done**),
plus the shared domain-type package, error-handling and logging
conventions, and a shared test-support package so Milestones 2+ don't each
reinvent SQLite-fixture/temp-dir boilerplate.

### Milestone 2 — Core transaction system
Builds the plain, correct mechanism first: ledger, (basic) keystore,
(basic) audit, backend business logic, (basic) protocol, CLI. "Basic"
means: correct, but without the vulnerable/hardened behavioral fork yet —
authorization is simply always enforced, protocol has no replay/tamper
enforcement logic yet, keystore is plaintext. Milestone 3 adds the fork.
This sequencing is a deliberate, different approach from the earlier
5-plan roadmap (which built each component's full vulnerable+hardened
behavior in one pass) — it isolates "does the mechanism work" from "does
the security differentiation work" as two separate, separately reviewable
slices.

### Milestone 3 — Security architecture
Layers `SecurityProfile`-driven differentiation onto Milestone 2's
components: authorization enforcement toggle + input validation
(backend), replay/tamper/downgrade enforcement (protocol), ledger
concurrency safety (the logical-race-without-a-data-race design — see
`TASK_BREAKDOWN.md` Task S3 and `TEST_STRATEGY.md`'s Review Focus).
Encrypted-at-rest key storage is **not** part of this milestone — it
belongs to Milestone 5, where the spec's own milestone list places it.

### Milestone 4 — Cryptographic system
Standard profile (Task C1, reuses the design already proven out in the
earlier 5-plan roadmap's Task 3), then the weak-educational profile
(toy RSA/DH, ECB, static IV — needed as a real task now, since this
roadmap builds the whole system rather than stopping at foundation), then
PQC (ML-KEM via stdlib, ML-DSA via `cloudflare/circl`), then wiring real
profile selection into the protocol's auth-tag/signature logic.

### Milestone 5 — Key management
Extends Milestone 2's basic keystore with encrypted-at-rest wrapping
(vulnerable = plaintext, hardened = AES-GCM-wrapped via Milestone 4's
Engine), rotation/revocation enforcement, and access auditing.

### Milestone 6 — Audit system
Extends Milestone 2's basic audit stream with hash-chaining and tamper
detection (hardened mode), richer querying, JSON/CSV export, and the
Detection Engine (rule-based subscriber producing the detection events
that `detection_latency` is measured from). Depends only on Milestone 2 —
runs in parallel with Milestones 4 and 5 (see `DEPENDENCY_GRAPH.md`).

### Milestone 7 — Attack framework
The generic harness: `Scenario`, `Oracle` (read-only verification),
`PrivilegedAccess` (read-write insider-simulation channel, with a
structural test proving it is unreachable from the CLI/protocol), and the
`Runner`. Framework only — no concrete attacks yet. Needs only Milestone
2's store interfaces (not security-mode differentiation itself), so it
can be built in parallel with Milestones 3-6 — only Milestone 8's
individual scenario tasks need those milestones' differentiation to
exist.

### Milestone 8 — Attack implementations
One task per `ATTACK_SURFACES.md` category (application, protocol,
database/ledger, key-management, cryptographic), each depending on
whichever earlier milestone built its target. These five tasks touch
disjoint files and have no interdependencies on each other — a clean
parallelization opportunity once Milestone 7 lands.

### Milestone 9 — Quantum-inspired simulations
Fully independent of every other milestone except Milestone 1 (it imports
nothing from `internal/crypto`, `internal/backend`, or any other
component — enforced by an import-graph test, consistent with
`CRYPTOGRAPHY.md` §5's non-claim). Can be built any time in parallel with
Milestones 2-8.

### Milestone 10 — AI-agent experiments
A deterministic, **reactive-but-not-learning** policy (the spec's "Action
selection" / "Adaptive execution" bullets mean the agent reacts to its
current `Observation`, not that it trains or improves over time — see the
infeasibility note below). Needs Milestone 7's harness and at least some
of Milestone 8's registered scenarios to have actions worth choosing
between.

### Milestone 11 — Benchmarking
The common result schema is **not a new task** — it is Milestone 7, Task
H3's `harness.Result` struct, reused and aggregated here. This satisfies
the stated rule ("do not implement benchmarks before the common result
schema exists") without a redundant schema-defining task. Benchmarking
adds comparative-run orchestration, JSON/CSV export, and summary
statistics on top of it.

### Milestone 12 — Integration and validation
No new packages — this milestone is entirely test-writing and
whole-project verification: end-to-end tests, the aggregated
vulnerable-vs-hardened differential suite, a full `-race` pass, benchmark
reproducibility, and a clean build.

### Milestone 13 — Documentation and publication
README and technical documentation consolidation, a scripted reproducible
example, then repository cleanup. **GitHub publication is explicitly not
an automatic step** — see Infeasibility/Substitution Notes.

## Infeasibility / substitution notes

Per your instruction not to silently drop difficult requirements:

- **GitHub publication (M13, P3):** publishing a repository is a
  side-effectful action visible outside this machine. The task prepares
  everything needed (clean history, README, LICENSE placeholder) but the
  actual `git remote add` + `git push` + repository creation step requires
  your explicit go-ahead at execution time — it is not something this plan
  auto-executes, consistent with how this project has handled every other
  git operation so far.
- **ML-KEM / ML-DSA exact library versions (M4, C3-C4):** `crypto/mlkem`'s
  API and `cloudflare/circl`'s tagged version must be verified against the
  Go toolchain actually installed (currently `go1.27.3`, confirmed present)
  at the time Tasks C3-C4 are implemented, not frozen in this document —
  already noted in `CRYPTOGRAPHY.md` §6 and carried forward here.
  Substitute if `crypto/mlkem` is absent from the installed toolchain:
  vendor `cloudflare/circl`'s ML-KEM implementation instead, for both KEM
  and signatures, under one dependency rather than two.
- **AI-agent "Adaptive execution" (M10):** interpreted as the agent
  reacting to its live `Observation` within a bounded step budget, **not**
  as a learning/trainable agent — the brainstorming decision was a
  deterministic, offline, reproducible agent (`ARCHITECTURE.md`'s
  AI-agent discussion). A learning agent is out of scope for this plan
  and would need its own brainstorming pass if wanted later.
- **Quantum simulations as real quantum execution:** not feasible on
  classical hardware and not attempted — `internal/quantum` is a genuine
  state-vector *simulator*, bounded to ~20 qubits, labeled as such on
  every output surface. This was already resolved in brainstorming
  (`CRYPTOGRAPHY.md` §5) and is carried forward unchanged.
- **Every verification-strategy item the request listed** (gofmt, vet,
  test, race, build, integration, security, benchmark reproducibility,
  JSON/CSV validation) is feasible and is mapped onto milestones in
  `TEST_STRATEGY.md` — no substitutions needed there.
