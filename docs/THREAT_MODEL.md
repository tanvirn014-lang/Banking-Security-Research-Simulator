# BankSec Lab — Threat Model

**Status:** Approved design, pre-implementation
**Scope:** This document describes threats *within* the local synthetic
simulator only. It is not a threat model for a real banking system, and no
finding here implies anything about real-world banking security beyond the
educational analogy being demonstrated.

## 1. Assets

| Asset | Nature | Where it lives |
|---|---|---|
| Synthetic account/ledger data | Fabricated, never real financial data | `internal/ledger` (SQLite) |
| Synthetic cryptographic keys | Generated test keys, never production keys | `internal/keystore` (separate store) |
| Audit/event log | Record of simulated activity | `internal/audit` |
| Benchmark results | Experimental measurements | exported JSON/CSV |

No asset in this system is ever real money, a real identity, or a real
credential. This is a structural (data-policy) guarantee, not merely a
convention — see Non-Goals in the source spec §2.2.

## 2. Trust boundaries

```
Researcher (trusted operator)
   |
   v
CLI  --[protocol, real wire format]-->  Backend  --[Go calls]-->  Ledger/Keystore/Crypto/Audit
   ^                                        ^
   |                                        |
Attack Harness --[protocol, attack path: application/protocol scenarios]--+
   |
   +--[Oracle, read-only Go interface]--> Ledger/Keystore/Audit (verification, all scenarios)
   |
   +--[PrivilegedAccess, read-write Go interface]--> Ledger/Keystore/Audit (attack path: db/ledger + key-mgmt scenarios only)
```

- **Protocol boundary** (CLI/Harness-as-attacker <-> Backend): the only
  boundary treated as adversarial for application-level and protocol-level
  scenarios. Both legitimate and attack traffic cross here, which is
  exactly where protocol-level attacks (§8.2 of the spec) are meaningful.
- **Oracle boundary** (Harness <-> Ledger/Keystore/Audit, read-only): used
  by every scenario to adjudicate outcomes. It is never an attack surface
  and never reachable from the CLI or protocol clients.
- **PrivilegedAccess boundary** (Harness <-> Ledger/Keystore/Audit,
  read-write): used only by database/ledger and key-management scenario
  categories as their actual attack path, simulating an insider/
  compromised-host threat that bypasses the Backend entirely. This is
  intentional and documented, not an accidental hole — and it is a
  distinct interface from Oracle, so a scenario that uses it is never
  mistaken for one verifying through read-only ground truth.
- **Internal boundary** (Backend <-> Ledger/Keystore/Crypto/Audit): trusted
  Go calls, not modeled as adversarial.

## 3. Threat categories and their trust-boundary mapping

| Category | Crosses | Representative threat |
|---|---|---|
| Application-level | protocol boundary | authorization bypass, business-logic/race-condition exploitation (concurrent withdrawal overdraft) |
| Protocol-level | protocol boundary | replay, tampering, missing/weak auth tag, crypto-profile downgrade |
| Database/ledger | internal boundary (simulated insider access) | direct ledger tampering, ledger-integrity-invariant violation, audit-log tampering |
| Key-management | internal boundary + protocol boundary | weak key storage (plaintext at rest), key access without authorization, lifecycle failures (no rotation/revocation enforcement) |
| Cryptographic | protocol + internal | weak-educational profile exploited (toy RSA factoring, ECB pattern leakage, static IV reuse), compared against standard/PQC profiles |
| AI-agent | protocol boundary (as a scripted client) | agent discovers and exploits the same vulnerabilities above within its bounded action set |

## 4. Audit integrity

- **Vulnerable mode:** audit log is a plain append-only table; no integrity
  protection. A direct-storage tamper can alter or delete past entries
  undetected by the system itself (detectable only by an external
  oracle-level comparison in the test harness, not by the running system).
- **Hardened mode:** audit entries are hash-chained (each entry's hash
  covers its content plus the previous entry's hash), so any tamper breaks
  the chain and is detectable by the Detection Engine re-verifying the
  chain. This does not claim cryptographic non-repudiation against a
  fully-compromised host — only that in-band tampering via the normal
  storage path is detectable.

## 5. Authorization model

Two principal types (see `ARCHITECTURE.md` §8): account-owner and
privileged operator. Authorization-boundary threats are expressed as:
- an account-owner attempting an operator-only action, or
- an account-owner attempting an action against an account they do not
  own.

Vulnerable mode may omit one or both checks (configurable per-scenario, so
each authorization scenario documents exactly which check is weakened).
Hardened mode enforces both server-side, in the Backend — never trusting
CLI-side validation (per spec §5.1, the CLI is explicitly not a trust
boundary).

## 6. Explicit non-goals (restated from the source spec, binding here)

The system does not model, and this threat model explicitly excludes:
- attacks against the host operating system, Go runtime, or hardware,
- attacks against real external networks, banks, or payment systems,
- credential theft, malware, or persistence mechanisms,
- unbounded/autonomous attack execution outside a registered scenario's
  declared prerequisites, permitted actions, and stopping conditions.

Any experiment proposal that would require crossing these boundaries is
out of scope for BankSec Lab by design, not by oversight.

## 7. Known limitations (honest)

- The `PrivilegedAccess` interface used for direct ledger/key tampering
  scenarios is, by construction, a backdoor relative to the normal Backend
  API. It is deliberately scoped to the Attack Harness only and must never
  be reachable from the CLI or protocol server in any configuration — this
  is a structural requirement to verify during implementation (see
  `ATTACK_SURFACES.md` §3), not something this document can guarantee by
  itself.
- Hash-chained audit integrity protects against *in-band* tampering via the
  normal storage path; it does not protect against an attacker who can
  rewrite the entire chain and recompute all hashes (a fully-compromised
  storage file). This mirrors real audit-log trade-offs and is intentional,
  not a bug to "fix" later.
