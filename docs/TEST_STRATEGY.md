# BankSec Lab — Test Strategy

**Status:** Draft, awaiting approval. Companion to
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) and
[TASK_BREAKDOWN.md](TASK_BREAKDOWN.md). Elaborates
`BankSec_Lab_System_Specification.md` §14 for this specific task
breakdown.

## Discipline: TDD on every task

Every task in `TASK_BREAKDOWN.md` follows: write the test(s) first, run
and confirm RED, implement the minimum to turn it GREEN, refactor only if
the task's own instructions call for it, run full verification, commit.
No task is "done" without a RED/GREEN record in its implementer's report
(this is how `subagent-driven-development`'s task reviewer checks TDD
compliance; `executing-plans` users confirm the same for themselves).

## Project-wide verification suite

Run after **every** task, not just at milestone boundaries:

```bash
gofmt -l .                 # must print nothing
go vet ./...
go test ./...
go test -race ./...
go build ./...
```

Additional, milestone-scoped verification (not run on every task — only
where the milestone's own tasks say to):

- **Integration testing:** full-stack tests that wire real
  ledger/keystore/audit/backend/protocol/CLI together (first appears at
  Task T6, deepens at S4, V1).
- **Security testing:** the vulnerable-vs-hardened differential suite —
  same scenario, both profiles, asserting the documented behavioral
  difference (first appears at S4, one per M8 attack task, aggregated at
  V2).
- **Benchmark reproducibility:** same seed -> same raw results, bit-for-bit
  on the non-timing fields (B4, re-checked at V4).
- **JSON/CSV validation:** exported files parse back into the documented
  schema and round-trip their numeric fields without precision loss (A3,
  B3, re-checked at V4).

## Test levels (maps to spec §14)

| Level | Where it lives | First appears |
|---|---|---|
| Unit | every task's own `_test.go` | F3 onward |
| Integration | cross-package wiring tests | T6 |
| Security-behavior | vulnerable vs. hardened differential | S4 |
| Attack-harness | prerequisites, stopping conditions, outcome classification | H4 |
| Benchmark | measurements from real executions, raw-result preservation | B4 |
| Concurrency/race | `go test -race`, targeted concurrent-access tests | S3, V3 |
| Reproducibility | deterministic scenarios, fixed seeds, same-input-same-output | Q2/Q3 (circuit determinism), G4 (agent), B4 (benchmark) |

## Review Focus (project-wide)

Five failure modes the milestone breakdown implies but that no single
task's own tests are guaranteed to exercise, listed most-likely-to-bite
first. Each gets an owning task below, consistent with how
`TASK_BREAKDOWN.md`'s per-task "Acceptance criteria" are written.

1. **Logical race vs. data race (Task S3):** vulnerable mode must produce
   a real, detectable business-logic race (TOCTOU lost-update/overdraft)
   while remaining completely clean under `go test -race` — a vulnerable
   mode that races at the Go-memory level (not just the business-logic
   level) is a bug in the test harness itself, not a feature of the
   simulator, and would make the mandated `go test -race ./...` fail even
   where it shouldn't.
2. **The `PrivilegedAccess` backdoor leaking into a real attack surface
   (Task H2):** this interface exists specifically to simulate an
   insider/compromised host for M8's I3/I4 scenarios. A structural test
   must prove it is never reachable through the CLI or the protocol
   server in any build configuration — not just "nobody calls it today,"
   but "nothing compiles a path to it" from those two entrypoints.
3. **Crypto-profile downgrade silently accepted in hardened mode (Task
   C5):** once three real profiles exist (C1-C4), the protocol's
   `MinAcceptedCryptoProfile` enforcement (built against a single
   placeholder profile in S2) must be re-verified against all three —
   a regression here would quietly reopen the downgrade attack surface
   that I2 depends on being closed in hardened mode.
4. **Revoked or rotated keys still usable by a long-lived caller (Task
   K2):** a component that fetched key material before a `Revoke`/`Rotate`
   call and caches it would make the key-management attack scenario (I4)
   meaningless — no task currently asserts that *all* consumers
   (`internal/backend`, `internal/protocol`) re-fetch rather than cache,
   so K2 adds that assertion explicitly rather than assuming it.
5. **Audit hash-chain verification never actually running in hardened
   mode's normal operation (Task A4):** it is easy to build `VerifyChain`
   (A1) and a Detection Engine (A4) as library code that nothing calls
   automatically. A4's acceptance criteria require an end-to-end test
   proving the Detection Engine actually subscribes and evaluates during
   normal backend operation, not just that `VerifyChain` works when
   invoked directly from a test.

## What "done" means for a milestone

A milestone is not complete when its tasks' individual tests pass — it is
complete when:
- every task in it has a clean task review (per whichever execution
  method — `subagent-driven-development` or `executing-plans` — is
  chosen),
- the project-wide verification suite is clean at the milestone's final
  commit,
- and, for milestones 2-8, the relevant row of `ATTACK_SURFACES.md`'s
  feasibility table is either satisfied or explicitly re-flagged in this
  document if something changed.
