# BankSec Lab — Attack Surfaces and Feasibility Matrix

**Status:** Approved design, pre-implementation

Every scenario below is bounded to the local simulator (per
`THREAT_MODEL.md` §6) and must declare, at registration time: prerequisites,
permitted actions, expected observations, success/failure criteria, and
stopping conditions (spec §5.8). The Attack Harness determines outcomes via
the oracle channel (`ARCHITECTURE.md` §4.2) — never from the attack path's
own claims.

**Feasibility classes** used below:
- **F** — Fully implementable with real, measured behavior.
- **S** — Requires a simplified educational model (explicitly labeled as
  such, not a claim of full real-world fidelity).
- **L** — Requires an external library (named explicitly).
- **T** — Theoretical/simulated only; must be labeled as such in all output
  and documentation, never presented as equivalent to real execution.

## 1. Application-level scenarios

| Attribute | Detail |
|---|---|
| Target | `internal/backend` |
| Prerequisites | at least two accounts with funded balances |
| Execution | concurrent transfer/withdrawal requests via protocol client, racing against the backend's transaction handling |
| Expected impact | overdraft beyond account balance, or lost-update on concurrent transfers, in vulnerable mode (missing per-account locking/serializable isolation) |
| Detection | Detection Engine rule: balance invariant violation (ledger sum check) |
| Metrics | `success`, `attempts`, `records_compromised`, `execution_time_ms` |
| Tests | Go `-race` concurrency test issuing N parallel transfer requests, asserting invariant holds in hardened mode and is measurably violated in vulnerable mode |
| Feasibility | **F** |

Authorization-bypass variant: a principal attempts an operator-only action
or acts on an account it does not own. Same feasibility (**F**).

## 2. Protocol-level scenarios

| Attribute | Detail |
|---|---|
| Target | `internal/protocol` |
| Prerequisites | a captured/observed legitimate request (the harness, acting as a passive observer on its own attack-path connection, may capture its own prior legitimate traffic — it does not need to "sniff" another session, since there is no multi-tenant traffic in this simulator) |
| Execution | re-send a captured frame (replay), mutate a frame field without updating the auth tag (tamper), or declare a weaker crypto profile than the server's configured minimum (downgrade) |
| Expected impact | replayed transaction re-applied (vulnerable mode: no sequence-number check); tampered frame accepted (vulnerable mode: no/weak auth tag verification); downgrade accepted (vulnerable mode: server does not enforce minimum profile) |
| Detection | protocol server rejects (hardened mode) and emits an audit event; Detection Engine flags repeated rejections |
| Metrics | `success`, `attempts`, `execution_time_ms`, `detection_latency` |
| Tests | scenario tests asserting hardened-mode rejection and vulnerable-mode acceptance for each of replay/tamper/downgrade, independently |
| Feasibility | **F** — contingent on the real wire protocol defined in `ARCHITECTURE.md` §4.1; without it this category would be **T** (there would be nothing genuine to replay) |

## 3. Database and ledger scenarios

| Attribute | Detail |
|---|---|
| Target | `internal/ledger` (and `internal/audit` for log-tampering variant) |
| Prerequisites | direct storage access via `PrivilegedAccess` (`COMPONENT_INTERFACES.md`, `internal/harness`; see `THREAT_MODEL.md` §7) — simulates an insider/compromised-host threat, not a remote attacker |
| Execution | directly mutate ledger rows or audit rows, bypassing `internal/backend` |
| Expected impact | ledger invariant violated (entries no longer sum to zero) or audit chain broken, undetected by the running system in vulnerable mode |
| Detection | hardened mode: periodic/triggered invariant re-check (ledger) and hash-chain re-verification (audit) by the Detection Engine |
| Metrics | `success`, `records_compromised`, `detection_latency` |
| Tests | tamper via `PrivilegedAccess.RawLedgerWrite`/`RawAuditWrite`, assert hardened mode's Detection Engine flags it within N audit-check cycles; assert vulnerable mode does not |
| Feasibility | **F** |

**Structural requirement:** `PrivilegedAccess` must be unreachable from the
CLI or protocol server in every build configuration — verify with an
integration test that attempts to reach it via the protocol and expects
rejection.

## 4. Key-management scenarios

| Attribute | Detail |
|---|---|
| Target | `internal/keystore` |
| Prerequisites | an existing test key in the keystore |
| Execution | read raw key bytes via `PrivilegedAccess.RawKeyBytes` (simulating insider access): plaintext-at-rest in vulnerable mode vs. still-wrapped ciphertext in hardened mode (the unlock/decrypt path is not available through `PrivilegedAccess`) |
| Expected impact | key material recovered in vulnerable mode; recovery fails/is detected in hardened mode |
| Detection | keystore access events are audited regardless of mode; Detection Engine flags access outside a declared rotation/usage window |
| Metrics | `success`, `attempts`, `data_leaked_bytes` (key material bytes exposed) |
| Tests | assert plaintext recovery succeeds in vulnerable mode and fails (or requires unlock credential not available to the attack path) in hardened mode |
| Feasibility | **F** |

Key rotation/revocation: scenario verifies that a revoked key is rejected
by `internal/crypto` for new operations — **F**.

## 5. Cryptographic scenarios

| Attribute | Detail |
|---|---|
| Target | `internal/crypto` |
| Prerequisites | weak-educational profile active |
| Execution | classical cryptanalysis against toy constructs: brute-force factoring of a small RSA modulus, discrete-log via brute force on a small-parameter DH group, ECB-mode pattern detection, static-IV reuse detection |
| Expected impact | key/plaintext recovered under weak-educational profile within a bounded time budget; infeasible under standard/PQC profile within the same budget |
| Detection | N/A for the cryptanalysis itself (it's a passive mathematical attack, not an observable system event) — detection applies only if the harness also attempts to *use* a recovered key against the protocol/backend, which then follows the protocol/key-management detection paths above |
| Metrics | `execution_time_ms`, `attempts`, `computational_cost` |
| Tests | assert recovery succeeds under weak profile within a defined bound (e.g., < 1,000,000 trial divisions for toy RSA) and does not succeed under standard/PQC profile within the same bound |
| Feasibility | **F**, explicitly bounded to tiny parameter sizes (documented in `CRYPTOGRAPHY.md` §2) — never implies anything about real-world key-size security margins |

## 6. AI-agent scenarios

| Attribute | Detail |
|---|---|
| Target | `internal/harness` (via `internal/agent`'s bounded action set) |
| Prerequisites | a registered scenario (one of §1-§5 above) made available as an agent action |
| Execution | deterministic policy selects actions from `Observation` -> bounded `Action` enum, within a step budget, attempting to reach a defined objective (e.g., cause a detectable ledger-invariant violation) |
| Expected impact | same as whichever underlying scenario(s) the agent selects, plus a decision/action log showing the agent's path |
| Detection | identical to the underlying scenario's detection mechanism |
| Metrics | `attempts`, `execution_time_ms`, plus the agent's own step count and decision trace |
| Tests | deterministic policy produces the same action sequence given the same seed/observation sequence (reproducibility test) |
| Feasibility | **F** — the agent is a scripted/rule-based client of the harness, not a new attack mechanism of its own |

## 7. Quantum-algorithm scenarios

| Attribute | Detail |
|---|---|
| Target | `internal/quantum` (standalone — never the real `internal/crypto` keys) |
| Prerequisites | none (self-contained demo) |
| Execution | genuine state-vector simulation (complex amplitudes, unitary gates) of Shor's algorithm factoring a toy modulus (e.g., 15, 21, 35) and Grover's algorithm searching an unstructured space up to the qubit bound (~16-20 qubits) |
| Expected impact | correct factorization / correct search result, demonstrating the algorithm's logic at toy scale |
| Detection | N/A — this is an offline demonstration, not an attack against a running system |
| Metrics | `execution_time_ms`, `memory_usage`, qubit count, circuit depth |
| Tests | assert correct factorization/search result for fixed small inputs; assert the simulator raises an explicit, documented error (not a silent wrong answer) above the qubit bound |
| Feasibility | **T**, explicitly and permanently — every output surface (CLI, exported results, documentation) must label this as a classical simulation of quantum algorithm logic, never as execution on quantum hardware, and never as a demonstrated attack against this system's real cryptographic keys (per `CRYPTOGRAPHY.md` §5) |

## 8. Summary feasibility table

| Category | Class | External library required |
|---|---|---|
| Application-level | F | none |
| Protocol-level | F | none |
| Database/ledger | F | none |
| Key-management | F | none |
| Cryptographic (weak-educational) | F | none (math/big) |
| Cryptographic (standard) | F | none (stdlib) |
| Cryptographic (PQC: ML-KEM) | F | stdlib `crypto/mlkem` (verify version at implementation time) |
| Cryptographic (PQC: ML-DSA) | L | `cloudflare/circl` |
| AI-agent | F | none |
| Quantum (Shor/Grover) | T | none (custom state-vector sim, math/cmplx) |
