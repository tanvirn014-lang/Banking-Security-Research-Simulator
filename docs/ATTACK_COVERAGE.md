# BankSec Lab — Attack Coverage Matrix

**Status:** Milestone 8 (Attack Scenarios) complete for the five groups
below. Source of truth for what each attack targets, its prerequisites,
and its feasibility class (F/S/L/T) is `docs/ATTACK_SURFACES.md` — this
document only tracks implementation/verification status against that
spec, and does not restate it.

An attack is marked **Implemented & Verified** only when:
1. It is a registered `harness.Scenario` (see
   `internal/harness/registry_scenarios.go`'s `RegisterAllScenarios`) —
   not merely a function that exists.
2. Its `Exec` genuinely drives the real target component (`env.Client`,
   `env.Priv`, or `internal/crypto` directly) — no hardcoded result.
3. Its `Verify` genuinely inspects real system state (the `Oracle`, or,
   for the two scenarios where the Oracle cannot help — see §4 and §5
   below — a captured, independently-recomputed comparison), never
   trusting `Exec`'s own return value.
4. It has a passing automated test exercising both the attack-succeeds
   and attack-fails paths (or, where the spec itself says a control must
   hold in every mode — key revocation — both configurations asserting
   the control holds).

Having an `Exec`/`Verify` pair that compiles is **not** sufficient on its
own for this status — see "Do not mark an attack as complete merely
because its interface exists" in the task instructions this milestone
was built against.

## 1. Application-level scenarios (`internal/harness/scenario_application.go`)

| Attack | Status | Scenario ID | Test |
|---|---|---|---|
| Concurrent-overdraft race | **Implemented & Verified** | `application-concurrent-overdraft` | `TestScenario_ConcurrentOverdraft_SucceedsVulnerable_FailsHardened` |
| Authorization bypass | **Implemented & Verified** | `application-authz-bypass` | `TestScenario_AuthzBypass_SucceedsVulnerable_FailsHardened` |

Both drive the real `internal/backend` through real protocol traffic
(`env.Client`) and are adjudicated via `Oracle.LedgerSnapshot` (real
ledger entries, not the protocol `Response`'s own unauthenticated `OK`
field). The overdraft scenario required building genuine concurrency at
the backend layer: a single `protocol.Client` serializes its own `Send`
calls and the `protocol.Server` processes one connection's frames
strictly sequentially, so `Environment.NewClientConnection` (new in this
milestone) opens separate connections per concurrent request — without
it, "concurrent" requests through one client would never actually race.
Verified race-clean under `go test -race` (3 repeated runs).

## 2. Protocol-level scenarios (`internal/harness/scenario_protocol.go`)

| Attack | Status | Scenario ID | Test |
|---|---|---|---|
| Replay | **Implemented & Verified** | `protocol-replay` | `TestScenario_Replay_SucceedsVulnerable_FailsHardened` |
| Tamper | **Implemented & Verified** | `protocol-tamper` | `TestScenario_Tamper_SucceedsVulnerable_FailsHardened` |
| Downgrade | **Implemented & Verified** | `protocol-downgrade` | `TestScenario_Downgrade_SucceedsVulnerable_FailsHardened` |

`protocol.Client`'s only method was `Send` — no way to resend a raw
captured frame, mutate one, or declare an off-profile frame. This
milestone added `protocol.AttackClient` (`LastSentFrame`, `BuildFrame`,
`SendRawFrame`) to `internal/protocol` itself, validated directly at the
protocol-package level before being used here. All three scenarios
target `"deposit"` (not `"create-account"`): a deposit lands in ledger
entries, so its real-world effect is observable via
`Oracle.LedgerSnapshot` — again, never the unauthenticated `Response.OK`.

## 3. Database and ledger scenarios (`internal/harness/scenario_ledger.go`)

| Attack | Status | Scenario ID | Test |
|---|---|---|---|
| Ledger tamper | **Implemented & Verified** | `ledger-tamper` | `TestScenario_LedgerTamper_DetectedHardened_UndetectedVulnerable` |
| Audit tamper | **Implemented & Verified** | `audit-tamper` | `TestScenario_AuditTamper_DetectedHardened_UndetectedVulnerable` |

Both use `PrivilegedAccess` (the insider/compromised-host bypass) to
write directly to storage, then are adjudicated by whether the already
-running Detection Engine actually flagged it — via
`Oracle.AuditEventsSince` for a `"detection"`-type event, with
`DetectionLatencyMS` populated from its timestamp. The audit-tamper
scenario surfaced a real gap while this task was being scoped: nothing
previously re-verified the audit hash chain as a Detection Engine rule
(Milestone 6 shipped only the balance-invariant rule), despite
`ATTACK_SURFACES.md` §3 explicitly calling for "hash-chain
re-verification... by the Detection Engine." A second rule,
`audit-chain-violation`, was added to `internal/detection` for this
task and wired in the same profile-gated way as the existing one.

**Structural requirement** (`ATTACK_SURFACES.md` §3): `PrivilegedAccess`
must be unreachable from the CLI or protocol server in every build
configuration. Verified by `internal/protocol/no_privileged_access_test.go`
(`TestProtocol_NoOpRoutesToPrivilegedAccess`, Milestone 7) plus
`internal/harness`'s `newPrivilegedAccess` being unexported, so no
Scenario can construct one pointed anywhere but the Environment that
made it (Milestone 7's own security review, finding C1).

## 4. Key-management scenarios (`internal/harness/scenario_keystore.go`)

| Attack | Status | Scenario ID | Test |
|---|---|---|---|
| Key-material exposure | **Implemented & Verified** | `key-exposure` | `TestScenario_KeyExposure_PlaintextVulnerable_CiphertextHardened` |
| Key rotation/revocation | **Implemented & Verified** (not a hardened/vulnerable differential — see below) | `key-revocation` | `TestScenario_KeyRevocation_AlwaysRejected` |

Key exposure's `Verify` is the one scenario in this milestone that
cannot use the `Oracle` at all: `Oracle.KeySnapshot` deliberately never
returns key material (doing so would make a "read-only" channel a
privileged one in disguise — see `oracle.go`'s own doc comment), so the
comparison is between what `Exec` captured via `env.Priv.RawKeyBytes`
and the test's own independently-known plaintext. This does not weaken
"never trust `Exec`'s own claim": `Exec` makes no success claim here at
all, only gathers data; `Verify` alone decides.

Key revocation deliberately breaks the hardened-vs-vulnerable pattern
every other scenario in this milestone follows: revocation must reject a
revoked key in *every* mode, so its test asserts `Success=false` under
both `configs/hardened.json` and `configs/vulnerable.json` — matching
`ATTACK_SURFACES.md` §4's own framing ("scenario *verifies* that a
revoked key is rejected", not an attack expected to differ by mode).

**Gap found while scoping this group:** nothing in production
(`cmd/banksec`, `internal/backend`, `internal/protocol`) actually calls
`keystore.Store.Generate` — a gap already ledgered in Milestone 5 (Task
23: "no production consumer sources protocol/backend key material from
the keystore yet"). There is therefore no protocol-level operation a
Scenario could use to create a test key, the way every other scenario
creates its fixtures through `env.Client`. Three `Environment` fixture
helpers (`GenerateTestKey`, `RevokeTestKey`, `GetTestKey`) were added,
explicitly documented as test/scenario-fixture setup standing in for
that missing production wiring — not new attack capability.

## 5. Cryptographic scenarios (`internal/harness/scenario_crypto.go`)

`ATTACK_SURFACES.md` §5 — "the original engineering specification," per
this milestone's own instructions — names **four** techniques. This
milestone's own `TASK_BREAKDOWN.md` draft only ever planned the first.

| Attack | Status | Scenario ID / Test | Technical reason |
|---|---|---|---|
| Toy RSA brute-force factor + forge signature | **Implemented & Verified** | `crypto-toy-rsa-factor-forge` / `TestScenario_ToyRSAFactorAndForge_SucceedsWithinBudget`, `TestScenario_ToyRSAFactorAndForge_InfeasibleUnderStandardProfile` | — |
| ECB-mode pattern detection | **Implemented & Verified** | `crypto-ecb-pattern-leakage` / `TestScenario_ECBPatternLeakage_WeakLeaksStandardDoesNot` | — |
| Small-parameter Diffie-Hellman discrete-log | **Implemented & Verified** | `crypto-dh-discrete-log` / `TestScenario_DiffieHellmanDiscreteLog_SucceedsWithinBudget`, `TestScenario_DiffieHellmanDiscreteLog_InfeasibleUnderStandardProfile` | Recovers a discrete logarithm in a deliberately small, fixed, documented toy DH group (`crypto.ToyDHPublicParams`) chosen to fit `internal/quantum`'s existing baby-step-giant-step budget — not a break of Diffie-Hellman in general, not a statement about real-world DH group sizes, and not a quantum result (the classical BSGS baseline only, no `quantum.Shor`/circuit code). Closes the long-standing X25519/DH gap noted earlier in this document. |
| Static-IV reuse detection | **Unsupported** | — | `CRYPTOGRAPHY.md` §1.1's design table lists "IV handling: static/reused IV" as a property of weak-educational's symmetric primitive, separate from "Symmetric: AES in ECB mode" — but ECB mode has no IV/nonce concept at all, so there is nothing to reuse. This is an inconsistency in the approved design table itself (the two rows describe incompatible constructions), not a missed implementation step. Already noted as a deferred scope gap in Milestone 4's security review. |

All three implemented scenarios target `internal/crypto` directly — no
`env.Client`/`env.Priv`/`Oracle` involvement — since they are passive
mathematical cryptanalysis, not actions against a running system
("Detection: N/A... a passive mathematical attack, not an observable
system event," `ATTACK_SURFACES.md` §5). The weak-educational-vs-
standard axis these three scenarios fork on is orthogonal to the
hardened-vs-vulnerable `SecurityProfile` axis every other scenario in
this milestone uses, and is expressed as a `config.SecurityProfile`
literal in the test file rather than a new `configs/*.json` file, since
it is not a deployment mode.

## Summary

| Status | Count |
|---|---|
| Implemented & Verified | 12 |
| Partially implemented | 0 |
| Unsupported | 1 (static-IV reuse) |

All 12 implemented scenarios are registered via
`harness.RegisterAllScenarios` (`internal/harness/registry_scenarios.go`),
verified to register with no ID collisions and to report the correct
per-category counts
(`TestRegisterAllScenarios_NoCollisionsAllCategoriesPresent`).

**Carried-forward open items, not this milestone's job to resolve**
(flagged in earlier milestones' security reviews, still pending a user
decision): no production consumer sources protocol/backend key material
from the keystore yet (Milestone 5, Task 23).
