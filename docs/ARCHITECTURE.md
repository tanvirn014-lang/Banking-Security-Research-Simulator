# BankSec Lab — Architecture

**Status:** Approved design, pre-implementation
**Source spec:** [BankSec_Lab_System_Specification.md](../BankSec_Lab_System_Specification.md)

## 1. Deployment model

BankSec Lab is **one Go module, one OS process**. No microservices, no
containers, no network infrastructure are required to run it. This is a
deliberate departure from a naive reading of the spec's "protocol-level
attacks" requirement, which could be misread as implying separate services —
see §3 for how real protocol semantics are achieved without them.

Supported execution modes:

- **Default:** CLI and Attack Harness communicate with the Backend over an
  in-memory transport (`net.Pipe`). No sockets are opened.
- **Optional network mode:** the same protocol can be carried over real
  loopback TCP (`127.0.0.1`), for experiments that specifically require real
  network timing/replay behavior (e.g., measuring replay-window timing under
  actual OS scheduling). Off by default.

## 2. Package layout

```
cmd/banksec/        entrypoint; wires config, transport, backend, CLI
internal/protocol/  wire format, framing, transport (net.Pipe + optional TCP)
internal/backend/   banking business logic, orchestration
internal/ledger/    double-entry ledger storage (SQLite via modernc.org/sqlite)
internal/keystore/  key lifecycle storage, physically separate from ledger
internal/crypto/    three crypto profiles (weak-educational/standard/pqc)
internal/audit/     append-only event stream
internal/detection/ rule engine subscribed to the audit stream
internal/harness/   attack scenario registration + execution + oracle
internal/benchmark/ repeated-run orchestration, JSON/CSV export
internal/agent/     deterministic AI-agent (Observation -> Action)
internal/quantum/   standalone Shor/Grover state-vector simulators
internal/config/    SecurityProfile definitions and loading
```

Each package has one responsibility and is tested in isolation. Only
`internal/protocol` and `internal/harness` cross process-external-looking
boundaries (the serialized wire protocol); everything else communicates via
plain Go calls, because nothing outside the process can legitimately attack
an in-process function call — serializing it would be security theater.

## 3. Component responsibility matrix

| Component | Owns | Upstream callers | Downstream dependencies |
|---|---|---|---|
| CLI (`cmd/banksec`) | input validation, display, config selection | researcher | `protocol` (client) |
| Protocol (`internal/protocol`) | message framing, auth tag, sequence numbers, transport | CLI, Harness (attack path) | `backend` |
| Backend (`internal/backend`) | business rules, transaction orchestration | protocol server | `ledger`, `keystore`, `crypto`, `audit` |
| Ledger (`internal/ledger`) | double-entry storage, balance invariants | backend, harness (Oracle read + PrivilegedAccess write) | SQLite |
| Keystore (`internal/keystore`) | key generation/storage/rotation/revocation | backend, harness (Oracle read + PrivilegedAccess write) | SQLite/file (separate DB from ledger) |
| Crypto (`internal/crypto`) | the three crypto profiles | backend, harness | Go stdlib, `circl` |
| Audit (`internal/audit`) | event recording | backend, keystore, detection | append-only store |
| Detection (`internal/detection`) | rule-based alerting | audit (subscribe + emit) | audit |
| Harness (`internal/harness`) | scenario registration/execution, outcome adjudication | benchmark, agent, researcher | protocol (attack path, §1-2 categories), ledger/keystore/audit (Oracle read-only for all categories; PrivilegedAccess read-write for §3-4 categories) |
| Benchmark (`internal/benchmark`) | repeated runs, aggregation, export | researcher | harness, audit/detection |
| Agent (`internal/agent`) | bounded policy over Observation -> Action | harness | harness (as its action surface) |
| Quantum (`internal/quantum`) | standalone algorithm simulators | CLI, benchmark | none (no link to `crypto`'s real keys) |
| Config (`internal/config`) | SecurityProfile definitions | cmd/banksec | consumed by backend/crypto/keystore at startup |

## 4. Communication design

### 4.1 Protocol boundary (the only "real" wire boundary)

`internal/protocol` defines a request/response message format carried over
`net.Pipe` (default) or loopback TCP (optional):

- **Framing:** length-prefixed, versioned message envelope.
- **Sequence number:** monotonically increasing per session; the server
  rejects or flags out-of-order/repeated sequence numbers (replay surface).
- **Authentication tag:** HMAC (standard profile) or signature (PQC
  profile) over the frame, keyed per-session; hardened mode verifies it
  server-side, vulnerable mode may skip or weaken this check (see
  `ATTACK_SURFACES.md` §2).
- **Declared crypto profile:** each session declares which crypto profile
  it expects to use. The **server**, not the client, enforces the active
  profile — a client requesting a weaker profile than the server's
  configured minimum is rejected in hardened mode (downgrade-attack
  surface, deliberately exploitable in vulnerable mode).

Both the CLI and the Attack Harness's attack-path use the same protocol
client implementation — the harness is "just another client" when it is
attacking, so attacks exercise genuine request paths rather than
privileged shortcuts.

### 4.2 Harness privileged channels (not a wire protocol — Go interfaces)

The Attack Harness holds **two** separate interfaces into
`ledger`/`keystore`/`audit`, injected only into the harness at
construction time and never exposed to the CLI or over the wire:

- **`Oracle`** (read-only, used by every scenario) — verifies ground truth
  independent of whatever the attack path claims happened (the spec
  requires outcomes be "determined from actual state," which an attack
  that can forge its own responses could otherwise defeat).
- **`PrivilegedAccess`** (read-write, used only by the database/ledger and
  key-management scenario categories) — simulates an insider/
  compromised-host actor by writing directly to storage, bypassing
  `internal/backend`'s business rules and invariant checks entirely. This
  is the *attack path itself* for those two categories, distinct from
  `Oracle`'s read-only verification role.

```go
// internal/harness package (interface sketch, not implementation)
type Oracle interface {
    LedgerSnapshot(ctx context.Context) (ledger.State, error)
    KeySnapshot(ctx context.Context, keyID string) (keystore.KeyMeta, error)
    AuditEventsSince(ctx context.Context, t time.Time) ([]audit.Event, error)
}

type PrivilegedAccess interface {
    RawLedgerWrite(ctx context.Context, entries []ledger.Entry) error
    RawAuditWrite(ctx context.Context, e audit.Event) error
    RawKeyBytes(ctx context.Context, id string) ([]byte, error)
}
```

See `COMPONENT_INTERFACES.md` ("`internal/harness`") for which scenario
categories use which channel.

### 4.3 Internal (in-process) calls

Backend -> Ledger/Keystore/Crypto/Audit are plain Go method calls. No
serialization, no auth tags — these are trusted internal boundaries by
design. Audit -> Detection is an in-process event subscription (Go
channel or callback registration), not a queue or broker.

## 5. Security-mode isolation

A `SecurityProfile` (in `internal/config`) is loaded **once**, at the start
of a CLI session or a benchmark run, and injected into `backend`, `crypto`,
`keystore`, and `protocol` at construction. It is **immutable for the
duration of that run** — there is no runtime API to flip modes mid-session.
Switching modes requires starting a new run (new process invocation or new
benchmark iteration), which also re-initializes storage to a defined
starting state (see `BENCHMARK_METHODOLOGY.md` §2 for how equivalent
initial state is produced across compared runs).

`SecurityProfile` determines, at minimum:
- active crypto profile (weak-educational / standard / post-quantum)
- protocol auth-tag enforcement strictness and minimum accepted profile
- keystore encryption-at-rest (on/off) and access-control strictness
- which Detection Engine rules are active
- audit integrity protection (hash-chained vs. plain-appendable; see
  `THREAT_MODEL.md` §4)

This is implemented as an injected interface/struct, not scattered
`if vulnerable { ... }` branches, so that "what does vulnerable mode
actually weaken" is answerable by reading one place.

## 6. Ledger integrity model

The ledger uses **double-entry bookkeeping**: every transaction writes a
balanced pair (or set) of entries (debit + credit), never a single mutable
`balance` field. An account's balance is a **derived** value (sum of its
entries), not stored state that can be directly overwritten through the
normal API.

This gives the data-integrity research objective a real, checkable
invariant: `sum(all entries for a transaction) == 0`, and
`sum(all entries, globally) == 0`. A tampering attack (direct DB write
bypassing the backend) is detectable by re-checking this invariant — it
does not need to be asserted or assumed.

## 7. Key management separation

`internal/keystore` uses its own storage (separate SQLite database or file,
not shared tables with `internal/ledger`). Rationale: a key-compromise
experiment should not be able to corrupt ledger data as a side effect, and a
ledger-tampering experiment should not be able to read key material as a
side effect. Each attack category gets an isolated blast radius.

## 8. Identity / role model

Beyond `Account` (a synthetic bank account), the system models two
principal types:
- **Account-owner** — may act on accounts they own (deposit, withdraw,
  transfer, view own history).
- **Privileged operator** (teller/admin analogue) — may act across
  accounts (e.g., unlock/freeze an account, view any transaction history,
  rotate keys).

Authorization-boundary attacks (§5.2 of `THREAT_MODEL.md`) are expressed as
a principal attempting an operation outside its granted role — this
requires at least these two principal types to be meaningfully expressible,
per the brainstorming discussion.

## 9. Known architectural limitations (honest, as required)

- A single-process design means there is no real OS-level process isolation
  between "the bank" and "the attacker" — the harness's privileged access is
  a Go-level contract (separate interface), not an OS security boundary.
  This is acceptable because the system's threat model explicitly excludes
  attacks against the host OS itself (see `THREAT_MODEL.md` §6, non-goals).
- `net.Pipe` transport means timing-based protocol attacks (true network
  jitter, real TCP retransmission behavior) are not representative unless
  the optional loopback-TCP mode is used; results from the two transports
  are not directly comparable and must be labeled with which transport was
  used.
- The Quantum subsystem's qubit bound (~16-20 qubits) means its Shor demo
  factors toy moduli (e.g., 15, 21, 35) only — this is not a statement
  about the practical security margin of any real key size used elsewhere
  in the system. See `CRYPTOGRAPHY.md` §5 for the explicit non-claim.
