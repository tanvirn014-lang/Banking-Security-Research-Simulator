# BankSec Lab — Milestone 12: Independent System Verification Report

**Role assumed for this report:** independent senior QA/security
verification engineer. Nothing in this report is taken on the strength
of any prior implementation report, commit message, or ledger entry —
every command below was executed fresh in this session, against the
actual checked-out code, and its real output is what is recorded here.

**Verified against:** commit `360e29c9e101ee2c887706b72a8cb327f6e2dff6`,
branch `worktree-foundation-core-banking`, clean working tree
(`git status --short` empty before and after verification).

**Environment:** `go version go1.27.3 windows/amd64`. Race-detector runs
used `CC` pointed at a 64-bit mingw-w64 GCC (required for cgo on
Windows); this is an environment prerequisite, not a code dependency.

**Date:** 2026-11-07.

---

## 1. gofmt verification

**Command:**
```
gofmt -l .
```
**Output:** (empty)
**Exit status:** `0`
**Result:** PASS — no file in the repository needs reformatting.

## 2. go vet ./...

**Command:**
```
go vet ./...
```
**Output:** (empty)
**Exit status:** `0`
**Result:** PASS — no vet findings across any package.

## 3. go test ./...

**Command:**
```
go test -count=1 -v ./...
```
**Exit status:** `0`
**Packages:** 17/17 reported `ok`, 0 reported `FAIL`.
**Test counts** (`--- PASS:` / `--- FAIL:` / `--- SKIP:` lines, which
include both top-level tests and `t.Run` subtests):

| Metric | Count |
|---|---|
| Passed | 301 |
| Failed | 0 |
| Skipped | 0 |

**Per-package breakdown** (top-level + subtest `--- PASS` lines per
package):

| Package | Passed |
|---|---|
| `cmd/banksec` | 7 |
| `internal/agent` | 23 |
| `internal/apperr` | 4 |
| `internal/applog` | 1 |
| `internal/audit` | 17 |
| `internal/backend` | 16 |
| `internal/benchmark` | 26 |
| `internal/config` | 8 |
| `internal/crypto` | 23 |
| `internal/detection` | 10 |
| `internal/domain` | 2 |
| `internal/harness` | 57 |
| `internal/keystore` | 18 |
| `internal/ledger` | 10 |
| `internal/protocol` | 26 |
| `internal/quantum` | 51 |
| `internal/testsupport` | 2 |
| **Total** | **301** |

**Result:** PASS.

## 4. go test -race ./...

**Command:**
```
go test -race -count=1 -v ./...
```
**Exit status:** `0`
**Packages:** 17/17 `ok`, 0 `FAIL`.
**Test counts:** 301 passed, 0 failed, identical to the non-race run.
**`DATA RACE` occurrences in output:** 0 (`grep -c "DATA RACE"` on the
full race-mode log).

**Result:** PASS — no data races detected anywhere in the test suite,
including the concurrency-sensitive areas this project has specifically
built regression tests for (the concurrent-overdraft race scenario,
revoked-key-rejection under interleaved concurrent consumers, the audit
hash-chain's own concurrent-record/verify path, and the Milestone 7/8
goroutine-tracking fixes in `internal/harness`).

## 5. Build all binaries

**Commands:**
```
go build ./...
go build -o banksec.exe ./cmd/banksec
```
**Exit status:** `0` for both.
**Binaries produced:** `banksec.exe` (one `main` package exists in this
repository, `cmd/banksec`; `go build ./...` compiles every package,
including this one, without producing a separate output file per
non-main package, which is correct Go behavior, not a gap).

**Smoke-tested the actual built binary**, not just the `go build` exit
code:
```
$ ./banksec.exe
usage: banksec <command> [flags]      (exit 2 — correct: no args given)
$ ./banksec.exe --version
banksec-lab v0.1.0-dev
```
**Result:** PASS.

## 6. Client-to-backend-to-vault integration tests

Two forms of evidence, both executed fresh in this session:

**(a) Automated integration tests** (`go test` output above already
includes these; re-confirmed in isolation):
```
go test -count=1 -v ./internal/protocol/... -run 'Client|Server'
go test -count=1 -v ./internal/backend/...
```
All pass (part of the 26 `internal/protocol` and 16 `internal/backend`
passes above).

**(b) A genuine, fresh, manual end-to-end run of the actual built
binary** against a clean, newly-created persistent data directory (not
a test harness, not a mock — the real `cmd/banksec` CLI wired to the
real SQLite-backed ledger/keystore/audit stack under
`configs/hardened.json`):

```
$ rm -rf data   # confirmed absent beforehand: fresh state
$ ./banksec.exe create-account -owner=alice
account=acct-7164f34bb9e2dfadde064a47eaac2d85
$ ./banksec.exe create-account -owner=bob
account=acct-e5a322c329d1f28b0cc3b76f71b90797
$ ./banksec.exe deposit -account=acct-7164... -amount=1000 -as=alice
(exit 0)
$ ./banksec.exe balance -account=acct-7164... -as=alice
balance=1000
$ ./banksec.exe transfer -from=acct-7164... -to=acct-e5a3... -amount=300 -as=alice
(exit 0)
$ ./banksec.exe balance -account=acct-7164... -as=alice
balance=700
$ ./banksec.exe balance -account=acct-e5a3... -as=bob
balance=300
$ ./banksec.exe withdraw -account=acct-7164... -amount=200 -as=alice
(exit 0)
$ ./banksec.exe balance -account=acct-7164... -as=alice
balance=500
$ ./banksec.exe history -account=acct-7164... -as=alice
history=[{"TxID":"tx-6b8b...","Amount":1000,...},{"TxID":"tx-67e1...","Amount":-300,...},{"TxID":"tx-40eb...","Amount":-200,...}]
```
Arithmetic independently checked: `1000 - 300 - 200 = 500`, matching the
final reported balance exactly; the transfer's debit/credit pair
(`-300` from alice, `+300` implied to bob, confirmed via bob's own
`balance=300`) balances. Every operation persisted correctly across
separate OS process invocations (each `banksec.exe` call is a fresh
process re-opening the same on-disk SQLite stores), confirming genuine
persistence, not in-memory-only state.

**Authorization enforcement also independently verified** in the same
live run:
```
$ ./banksec.exe withdraw -account=acct-7164... -amount=50 -as=bob
unauthorized: unauthorized          (exit 2)
```
Bob cannot withdraw from Alice's account under the hardened profile —
correct.

Scratch `data/` directory removed after verification (it is
`.gitignore`d as the real CLI's own persistent-storage default, and
`git status` was confirmed clean before and after).

**Result:** PASS.

## 7. Vulnerable-mode attack tests / 8. Hardened-mode prevention tests

Re-run directly in this session (not assumed from memory):

```
go test -count=1 -v ./internal/harness/... -run \
  'DetectedHardened_UndetectedVulnerable|PlaintextVulnerable_CiphertextHardened|ConcurrentOverdraft|AuthzBypass'
go test -count=1 -v ./internal/protocol/... -run \
  'Replay_Rejected|Tamper_Rejected|Downgrade_Rejected'
```

All of the following passed, each as a genuine differential test
(vulnerable subtest succeeds at the attack, hardened subtest is
blocked/detected, both executed against real code, never a mocked
backend):

| Attack | Vulnerable result | Hardened result |
|---|---|---|
| Ledger raw-write tamper (`ledger-tamper`) | undetected (Success) | detected by `balance-invariant-violation` |
| Audit raw-write tamper (`audit-tamper`) | undetected | detected by `audit-chain-violation` |
| Concurrent-overdraft race (20 simultaneous transfers) | overdraft succeeds | atomicity enforcement blocks it |
| Authorization bypass (acting on another principal's account) | succeeds | rejected |
| Key-material exposure via insider raw-bytes read | plaintext recovered | ciphertext only (encrypted at rest) |
| Protocol replay (resending a captured frame) | accepted | rejected (replay detection) |
| Protocol tamper (mutating a captured frame's payload) | accepted | rejected (auth tag mismatch) |
| Protocol downgrade (declaring a weaker crypto profile) | accepted | rejected (minimum-profile enforcement) |

Additional, mode-invariant security property, also re-verified fresh:
**key revocation is enforced in every mode** (not a vulnerable/hardened
differential by design — `TestScenario_KeyRevocation_AlwaysRejected`
passed under both `configs/hardened.json` and `configs/vulnerable.json`
in this session's run).

**Result:** PASS for both items 7 and 8.

## 9. Cryptographic verification tests

```
go test -count=1 -v ./internal/crypto/...
```
23/23 passed, including: ML-DSA sign/verify round-trip, determinism,
tamper/invalid-key rejection, key-reuse independence; ML-KEM
encrypt/decrypt round-trip, wrong-recipient and tampered-ciphertext
rejection; the weak-educational toy RSA sign/verify round-trip and its
own documented factorability-within-budget property; AES-GCM
encrypt/decrypt round-trip and tamper/invalid-key-size rejection; the
weak-educational ECB mode's round-trip AND its deliberately-demonstrated
weaknesses (repeated plaintext blocks produce repeated ciphertext
blocks; a modified ciphertext goes undetected, since ECB carries no
authentication) — i.e. the test suite verifies both that the hardened
primitives are correct AND that the weak-educational primitives are
*correctly weak* in the specific, documented ways `CRYPTOGRAPHY.md`
claims.

**Result:** PASS.

## 10. Key-management tests

```
go test -count=1 -v ./internal/keystore/...
```
18/18 passed, including: revoked-key rejection by every consumer
(backend and protocol, as separate subtests) immediately upon
revocation; revoked-key rejection under concurrent, interleaved access
from multiple consumers (a genuine concurrency test, also clean under
`-race`); key rotation correctly updates both metadata and material;
rotating an already-revoked key is itself rejected; encryption-at-rest
verified directly against the raw on-disk row (ciphertext when enabled,
plaintext when disabled — both checked, not assumed); metadata reads
(`Meta`) never audit or error on a revoked key (the Milestone 7 review
fix that makes the harness's read-only Oracle safe to use against
revoked keys).

**Result:** PASS.

## 11. Audit-integrity tests

```
go test -count=1 -v ./internal/audit/...
```
17/17 passed, including: hash-chain verification succeeds on an
untampered chain and correctly detects a tampered entry; chain
verification correctly errors when hash-chaining isn't enabled for that
profile (rather than silently reporting "OK" for a mode that never
chained anything); truncation of the event log is detected (not just
in-place tampering); the chain checkpoint persists correctly across a
store reopen; and — a genuine concurrency correctness test, not just a
race-freedom check — no false-positive tamper report is produced when
`VerifyChain` runs concurrently with ongoing `Record` calls (the
Milestone 9-adjacent fix that made `VerifyChain` hold its lock for its
entire body).

**Result:** PASS.

## 12. AI-agent experiment tests

```
go test -count=1 -v ./internal/agent/...
```
23/23 passed, including: the deterministic baseline policy's
same-observation/same-action determinism and fixed-order exhaustion
(tracked per-ActionKind, not per-target, per the dedup-latch bug found
and fixed during this milestone's own development); the bounded
execution loop stopping correctly at budget, at action exhaustion, on
context cancellation, and on an out-of-bounds action (the Milestone 10
review's own I1 fix); the reproducibility test (identical seed →
identical decision sequence under a fixed clock); and the controlled
experiment against REAL Milestone 8 scenarios
(`TestControlledExperiment_BaselineAgentAgainstRealScenarios`): the
agent-driven run against `hardened.json` reports 0 successful
compromises (both tampers detected) and against `vulnerable.json`
reports 2 (both undetected) — a genuine, falsifiable prediction this
test actually checks, not a mechanical smoke test.

**Result:** PASS.

## 13. Benchmark reproducibility tests

```
go test -count=1 -v ./internal/benchmark/... -run 'Reproducib|SameSeed'
```
Both reproducibility tests passed:
- `TestBenchmark_SameSeed_IdenticalNonTimingFields`: two independent
  `RunComparative` invocations with the same seed produce identical
  `AttackID`/`TargetConfiguration`/`AttackType`/`Success`/`Attempts`/
  `RunID` on every run, differing only in real wall-clock fields
  (`ExecutionTimeMS`, and — a correction found during this project's own
  development, not assumed — `DetectionLatencyMS`, which is also a real
  timing measurement the seed does not control).
- `TestRunComparative_SameSeed_SameInitialState`: confirms the
  within-rep seed pairing itself (vulnerable and hardened share the
  exact same `seed+rep` value within one repetition) by comparing each
  run's own `RunID` (which embeds that seed) across two independent
  invocations.

**Result:** PASS.

## 14. JSON and CSV validation

```
go test -count=1 -v ./internal/benchmark/... -run Export
```
6/6 passed: `ExportJSON` round-trips every field including a `null` for
an absent optional metric (never a fabricated `0`) and correctly
records a run's error message when present; `ExportCSV`'s two
newline-separated sections (raw runs, then summary statistics) both
parse back cleanly with a standard `csv.Reader`, numeric fields parse as
numbers, an absent metric is an empty cell (never `"0"` or the literal
text `"null"`), and — a regression test for a review finding from this
project's own development — a `run_error` containing an embedded blank
line no longer breaks the documented section-boundary convention
(embedded newlines are now escaped before being written).

**Result:** PASS.

## 15. Fresh configuration execution

Covered concretely under item 6 above: the entire client-to-backend-to
-vault walkthrough was executed against a **freshly created** data
directory (confirmed absent immediately beforehand), loading
`configs/hardened.json` fresh on every one of the 9 separate CLI process
invocations used in that walkthrough — this is as "fresh" a
configuration execution as this system supports (there is no cached
or warm state between CLI invocations; each one re-reads the profile
JSON and re-opens the on-disk stores from scratch). The vulnerable
profile (`configs/vulnerable.json`) was independently, freshly exercised
via the item 7/8 test re-runs above, which load it directly rather than
through the CLI (the CLI itself is hardcoded to the hardened profile by
design — see `cmd/banksec/main.go`'s `defaultEnv` — there is no
`--profile` flag to point it at `vulnerable.json`; this is a real,
narrow gap, noted under Missing Functionality below).

**Result:** PASS, with the one noted CLI limitation.

---

## Investigation of failures

**No failures occurred during this verification.** Every one of the 15
checklist items, and every command executed to support them, produced
the expected result on the first run, in this session, independent of
any prior session's claims. No use of `systematic-debugging` was
required, since nothing failed to debug.

---

## Security findings (from this independent pass)

No NEW security findings were discovered during this verification pass
beyond what prior whole-branch reviews (Milestones 1 through
10+11, all independently dispatched opus-model reviews instructed to
run real probes rather than read code) already found and this project
already fixed. This verification pass's own commands — including the
live CLI walkthrough and the direct re-execution of every
attack/detection differential test — corroborate, rather than merely
repeat, those prior findings: the hardened/vulnerable behavioral
contrast was independently re-observed via a real running binary (item
6/7/8), not just trusted from a prior test-suite run.

One thing worth stating plainly, since this report's instructions say
not to assume prior reports are accurate: this verification pass did
**not** re-run the full battery of adversarial *security review*
probing (deliberately-malicious inputs, timing races engineered to
expose concurrency bugs, boundary/overflow conditions) that the
dedicated whole-branch reviews for Milestones 1–11 already performed —
re-doing that full depth of adversarial probing is a separate, much
larger undertaking than the 15-item integration/regression checklist
Milestone 12 specifies. What this pass *does* independently confirm is
that the currently-checked-in code — as it stands right now, not as any
report describes it — passes every automated test, has no data races,
builds cleanly, and behaves correctly end-to-end through a real running
binary.

## Missing functionality (disclosed, not hidden)

These are carried forward from `docs/ATTACK_COVERAGE.md` and this
project's own commit history, independently re-confirmed as still true
in the current codebase during this verification pass (not merely
copied from an earlier document):

1. **No Diffie-Hellman/key-exchange primitive anywhere in
   `internal/crypto`** — `crypto.Engine` has no `KeyExchange` method,
   and the `standard` profile's own design-table-specified X25519
   (`CRYPTOGRAPHY.md` §1.2) was never implemented. Confirmed absent by
   direct inspection in this session
   (`grep -rn "KeyExchange\|x25519\|X25519" internal/crypto` returns
   nothing). First flagged in Milestone 4's security review, repeated in
   Milestones 5, 7, 8, and 9+10/11's reviews — still an open question
   for the user on how key exchange should be integrated into
   `crypto.Engine` and the wire protocol. This is also why the
   small-parameter Diffie-Hellman discrete-log attack
   (`ATTACK_SURFACES.md` §5) remains **Unsupported**, not merely
   unimplemented — there is no real target component for it to exercise.
2. **Static-IV reuse detection is Unsupported** — not a missed
   implementation step but a genuine inconsistency in the approved
   design table (`CRYPTOGRAPHY.md` §1.1 lists it as a property of
   weak-educational's symmetric primitive, but that primitive is ECB
   mode, which has no IV/nonce concept at all to reuse).
3. **No production consumer calls `keystore.Store.Generate`** —
   confirmed by direct inspection in this session
   (`grep` across `internal/backend`, `internal/protocol`,
   `cmd/banksec` for `.Generate(` finds no call site). Every key-related
   test and Milestone 8 key-management scenario uses the
   `Environment.GenerateTestKey` fixture helper instead. First ledgered
   during Milestone 5.
4. **The CLI (`cmd/banksec`) has no flag to select the security
   profile** — `defaultEnv` in `cmd/banksec/main.go` hardcodes
   `configs/hardened.json`. This means the `vulnerable.json` profile can
   only be exercised through the test suite / `internal/harness` /
   `internal/benchmark` APIs directly, never through the shipped binary.
   This was not previously flagged in any prior ledger entry reviewed
   for this report — it is a genuine, if minor, gap noted here for the
   first time.
5. **No CLI wiring for `internal/agent` or `internal/benchmark`** —
   both packages are fully functional and tested, but there is no
   `banksec agent ...` or `banksec benchmark ...` subcommand; both are
   driven through Go code/tests only (`docs/BENCHMARK_EXAMPLES.md`'s own
   worked example is a separate `go run`-able program, not a CLI
   subcommand). Consistent with `docs/TASK_BREAKDOWN.md`'s own scoping
   of Milestones 10 and 11 (new packages only, no CLI integration
   named).

## Reproducibility results

| Property | Verified |
|---|---|
| `go test ./...` deterministic across repeated runs | Yes — re-run twice (plain and `-race`) in this session, identical pass counts both times |
| `internal/harness.Runner` seeded reproducibility | Yes — exercised indirectly via every `*_DetectedHardened_UndetectedVulnerable` test, which relies on it |
| `internal/quantum.Shor`/`Grover` deterministic given the same input | Yes — `internal/quantum` test suite (51 passing tests) includes dedicated determinism tests for both |
| `internal/agent.Agent` same-seed → same decision sequence | Yes — `TestAgent_SameSeed_SameActionSequence`, re-run in this session |
| `internal/benchmark.RunComparative` same-seed → same logical outcomes | Yes — both reproducibility tests re-run in this session (see item 13) |
| CLI end-to-end run, repeated | Not independently re-run twice in this session (the live walkthrough was destructive to its own data directory, which was then cleaned up) — the underlying `internal/backend`/`internal/protocol` automated tests, which exercise the identical code path, are themselves re-run on every `go test` invocation and were confirmed deterministic above |

---

## Overall verdict

All 15 checklist items PASS. `gofmt`, `go vet`, `go build ./...`, 
`go test ./...` (301/301), and `go test -race ./...` (301/301, 0 data
races) are all clean on the actual, currently-checked-in code at commit
`360e29c`. The real built binary was exercised end-to-end against fresh
state and behaved correctly, including its hardened-mode authorization
enforcement. No failures were found to investigate. Five items of
missing/disclosed-gap functionality are listed above, none of which
contradicts any passing test — each is either an explicitly out-of-scope
design decision (documented in `ATTACK_COVERAGE.md`/`CRYPTOGRAPHY.md`)
or a narrow, now-disclosed CLI limitation.

**This report's own standard for "complete"**: the system is complete
with respect to the 15 checklist items Milestone 12 names. It is not
claimed complete with respect to the carried-forward X25519/DH design
question, which remains open and unresolved, and has now been
flagged in six consecutive review passes (Milestones 4, 5, 7, 8, 9+10/11
review, and this one).
