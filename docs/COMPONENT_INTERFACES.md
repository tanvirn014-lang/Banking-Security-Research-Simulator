# BankSec Lab — Component Interface Specification

**Status:** Approved design, pre-implementation. Interface sketches below
are design-level type/signature declarations, not implementations — method
bodies are intentionally omitted.

## `internal/config`

**Responsibility:** define and load `SecurityProfile`; the single source of
truth for vulnerable/hardened behavior across all other packages.

```go
type SecurityProfile struct {
    Name                   string // "vulnerable" | "hardened"
    CryptoProfile          CryptoProfileName // weak-educational | standard | pqc
    MinAcceptedCryptoProfile CryptoProfileName // enforced by protocol server
    ProtocolAuthEnforced   bool
    KeystoreEncryptedAtRest bool
    AuditHashChained       bool
    DetectionRules         []DetectionRuleID
}

func Load(path string) (SecurityProfile, error)
```

**Inputs:** a profile file (format TBD at implementation time: YAML or
JSON, decided during implementation planning, not here).
**Outputs:** `SecurityProfile` value, consumed once at process/run start.
**Dependencies:** none (leaf package).

## `internal/protocol`

**Responsibility:** wire format, framing, transport (net.Pipe / optional
TCP), sequence-number and auth-tag enforcement.

```go
type Frame struct {
    Version    uint8
    Seq        uint64
    CryptoProf CryptoProfileName
    Payload    []byte
    AuthTag    []byte
}

type Client interface {
    Send(ctx context.Context, req Request) (Response, error)
}

type Server interface {
    Serve(ctx context.Context, backend backend.Service) error
}
```

**Inputs:** `Request` values from CLI/Harness; raw frames from transport.
**Outputs:** `Response` values; rejects (with typed errors:
`ErrReplayDetected`, `ErrAuthFailed`, `ErrProfileDowngrade`).
**Dependencies:** `internal/backend`, `internal/crypto` (for auth-tag
verification), `internal/config`.

## `internal/backend`

**Responsibility:** banking business rules, transaction orchestration,
authorization enforcement.

```go
type Service interface {
    CreateAccount(ctx context.Context, owner PrincipalID) (AccountID, error)
    Deposit(ctx context.Context, actor Principal, acct AccountID, amount Money) error
    Withdraw(ctx context.Context, actor Principal, acct AccountID, amount Money) error
    Transfer(ctx context.Context, actor Principal, from, to AccountID, amount Money) error
    Balance(ctx context.Context, actor Principal, acct AccountID) (Money, error)
    History(ctx context.Context, actor Principal, acct AccountID) ([]ledger.Entry, error)
}

type Principal struct {
    ID   PrincipalID
    Role Role // AccountOwner | PrivilegedOperator
}
```

**Inputs:** `Principal` + operation parameters.
**Outputs:** typed errors (`ErrInsufficientFunds`, `ErrUnauthorized`,
`ErrValidation`) or success + resulting state.
**Dependencies:** `internal/ledger`, `internal/keystore`, `internal/crypto`,
`internal/audit`, `internal/config`.

## `internal/ledger`

**Responsibility:** double-entry storage; balance is derived, never
directly mutable.

```go
type Entry struct {
    TxID      TransactionID
    AccountID AccountID
    Amount    Money // signed: debit negative, credit positive
    Timestamp time.Time
}

type Store interface {
    AppendTransaction(ctx context.Context, entries []Entry) error
    Balance(ctx context.Context, acct AccountID) (Money, error)
    History(ctx context.Context, acct AccountID) ([]Entry, error)
    CheckInvariant(ctx context.Context) (ok bool, violatingTxIDs []TransactionID, err error)
}
```

**Inputs:** balanced `[]Entry` sets (caller — `backend` — guarantees sum
is zero before calling `AppendTransaction`; the store rejects an unbalanced
set as a defensive check, not as the primary enforcement point).
**Outputs:** derived balances, invariant-check results (used by Detection
Engine and by the Harness oracle).
**Dependencies:** SQLite (`modernc.org/sqlite`).

## `internal/keystore`

**Responsibility:** key lifecycle, physically separate storage from
ledger.

```go
type KeyMeta struct {
    ID         string
    Profile    CryptoProfileName
    CreatedAt  time.Time
    RotatedAt  *time.Time
    RevokedAt  *time.Time
}

type Store interface {
    Generate(ctx context.Context, profile CryptoProfileName) (KeyMeta, error)
    Get(ctx context.Context, id string) (material []byte, meta KeyMeta, err error)
    Rotate(ctx context.Context, id string) (KeyMeta, error)
    Revoke(ctx context.Context, id string) error
}
```

**Inputs:** key IDs, profile selection.
**Outputs:** key material (hardened mode: only via an unlock path not
available to the attack path), `KeyMeta`.
**Dependencies:** separate SQLite/file store from `internal/ledger`;
`internal/crypto` (encryption-at-rest in hardened mode).

## `internal/crypto`

**Responsibility:** the three crypto profiles (`CRYPTOGRAPHY.md`).

```go
type CryptoProfileName string // "weak-educational" | "standard" | "pqc"

type Engine interface {
    Encrypt(profile CryptoProfileName, key, plaintext []byte) (ciphertext []byte, err error)
    Decrypt(profile CryptoProfileName, key, ciphertext []byte) (plaintext []byte, err error)
    Sign(profile CryptoProfileName, key, msg []byte) (sig []byte, err error)
    Verify(profile CryptoProfileName, pubkey, msg, sig []byte) (bool, error)
    MAC(profile CryptoProfileName, key, msg []byte) (tag []byte, err error)
}
```

**Inputs:** profile name, key material, data.
**Outputs:** ciphertext/signature/tag, or typed errors.
**Dependencies:** Go stdlib (`crypto/aes`, `crypto/hmac`, `crypto/ed25519`,
`crypto/ecdh`, `crypto/mlkem`), `cloudflare/circl` (ML-DSA), `math/big`
(weak-educational toy constructs).

## `internal/audit`

**Responsibility:** append-only event stream, optional hash-chaining.

```go
type Event struct {
    ID        string
    Timestamp time.Time
    Type      string
    Component string
    Actor     PrincipalID
    Operation string
    Outcome   string
    TxID      *TransactionID
    AttackID  *string
}

type Stream interface {
    Record(ctx context.Context, e Event) error
    Since(ctx context.Context, t time.Time) ([]Event, error)
    Subscribe(fn func(Event)) (unsubscribe func())
    VerifyChain(ctx context.Context) (ok bool, brokenAt *string, err error) // hardened mode only
}
```

**Inputs:** `Event` values from `backend`, `keystore`, `protocol`.
**Outputs:** queryable event history; a live subscription feed for
`internal/detection`.
**Dependencies:** storage (may share the ledger's SQLite instance in a
dedicated table, since audit is not a key-compromise or ledger-tampering
asset in the same sense — see `ARCHITECTURE.md` §7 for what *must* stay
separate: keys).

## `internal/detection`

**Responsibility:** rule-based alerting over the audit stream.

```go
type Rule interface {
    ID() DetectionRuleID
    Evaluate(window []audit.Event) (triggered bool, detail string)
}

type Engine interface {
    Register(r Rule)
    Run(ctx context.Context, stream audit.Stream) error // subscribes, evaluates, emits DetectionEvent
}

type DetectionEvent struct {
    RuleID    DetectionRuleID
    Timestamp time.Time
    RelatedEvent audit.Event
}
```

**Inputs:** subscription to `audit.Stream`.
**Outputs:** `DetectionEvent`s, themselves recorded back into the audit
stream with a distinct `Type`.
**Dependencies:** `internal/audit`, `internal/config` (which rules are
active per profile).

## `internal/harness`

**Responsibility:** scenario registration/execution; dual-channel access
(protocol attack path + oracle verification path).

```go
type Scenario struct {
    ID           string
    Category     string
    Prereqs      func(Oracle) (bool, error)
    // Execute is the attack path. Protocol-level and application-level
    // scenarios use a protocol.Client (they attack as "just another
    // client"). Database/ledger and key-management scenarios instead use
    // PrivilegedAccess, simulating an insider/compromised-host actor that
    // never goes through the Backend at all.
    Execute      func(context.Context, protocol.Client, PrivilegedAccess) error
    Verify       func(context.Context, Oracle) (success bool, evidence Evidence, err error)
    StopCond     func(Evidence) bool
}

// Oracle is read-only and used by every scenario's Verify step to
// adjudicate the outcome independent of what Execute claims happened.
type Oracle interface {
    LedgerSnapshot(ctx context.Context) (ledger.State, error)
    KeySnapshot(ctx context.Context, keyID string) (keystore.KeyMeta, error)
    AuditEventsSince(ctx context.Context, t time.Time) ([]audit.Event, error)
}

// PrivilegedAccess is read-write and simulates an insider/compromised-host
// actor. It is used only by the database/ledger tampering category
// (ATTACK_SURFACES.md §3) and the key-management category (§4) as their
// Execute step. It bypasses internal/backend's business rules and
// invariant checks entirely -- that bypass is the point: it models
// direct storage access, not a protocol-level attacker.
type PrivilegedAccess interface {
    RawLedgerWrite(ctx context.Context, entries []ledger.Entry) error      // bypasses balance-invariant enforcement
    RawAuditWrite(ctx context.Context, e audit.Event) error                // bypasses hash-chain linkage
    RawKeyBytes(ctx context.Context, id string) ([]byte, error)            // stored representation as-is: plaintext in vulnerable mode, still-wrapped ciphertext in hardened mode -- never pre-decrypted
}

type Runner interface {
    Run(ctx context.Context, s Scenario) (Result, error)
}
```

**Interfaces, who gets which:** application-level and protocol-level
scenarios (`ATTACK_SURFACES.md` §1-2) receive only `protocol.Client` in
`Execute` -- they are genuine remote-style attackers. Database/ledger and
key-management scenarios (§3-4) receive only `PrivilegedAccess` -- they
simulate an insider, never a protocol attacker. No scenario's `Execute`
step receives `Oracle`; verification is always a separate step so a
scenario cannot grade its own homework.
**Inputs:** a registered `Scenario`.
**Outputs:** `Result` (evidence-based success/failure, metrics).
**Dependencies:** `internal/protocol` (attack path, client role only, for
§1-2 categories), `internal/ledger`/`internal/keystore`/`internal/audit`
(`PrivilegedAccess`, read-write, for §3-4 categories only; `Oracle`,
read-only, for all categories' verification step).

## `internal/benchmark`

**Responsibility:** repeated-run orchestration, aggregation, export
(`BENCHMARK_METHODOLOGY.md`).

```go
type Runner interface {
    RunComparative(ctx context.Context, s harness.Scenario, reps int, seed int64) (RawResults, Summary, error)
    ExportJSON(w io.Writer, raw RawResults, summary Summary) error
    ExportCSV(w io.Writer, raw RawResults, summary Summary) error
}
```

**Inputs:** a scenario, repetition count, seed.
**Outputs:** raw per-run records + summary statistics; JSON/CSV files.
**Dependencies:** `internal/harness`, `internal/audit`/`internal/detection`
(for `detection_latency`), `internal/config` (switches `SecurityProfile`
between vulnerable/hardened runs).

## `internal/agent`

**Responsibility:** deterministic, offline AI-agent policy.

```go
type Observation struct {
    VisibleAccounts []AccountID
    VisibleBalances map[AccountID]Money
    RecentAudit     []audit.Event
    StepsRemaining  int
}

type Action struct {
    Kind   ActionKind // enum, bounded to harness-exposed scenario actions
    Target AccountID
}

type Policy interface {
    Decide(obs Observation) (Action, error)
}

type Agent struct {
    Policy      Policy
    Budget      int // max steps
    DecisionLog []Decision
}
```

**Inputs:** `Observation` built from harness/oracle state (read-only,
restricted to what the agent's scenario declares visible).
**Outputs:** `Action` within the harness's bounded set; a full
`DecisionLog` for reproducibility verification.
**Dependencies:** `internal/harness` (as its action surface).

## `internal/quantum`

**Responsibility:** standalone state-vector simulators for Shor/Grover.

```go
type Circuit struct {
    NumQubits int // bounded, e.g. <= 20
    State     []complex128
}

func Shor(ctx context.Context, n int) (factors []int, trace CircuitTrace, err error) // n bounded to toy moduli
func Grover(ctx context.Context, searchSpaceBits int, oracle func(x int) bool) (result int, trace CircuitTrace, err error)

var ErrQubitBoundExceeded = errors.New("qubit bound exceeded")
```

**Inputs:** toy-scale parameters only (modulus to factor, search-space
size, oracle function).
**Outputs:** result + `CircuitTrace` (for display/export); explicit
`ErrQubitBoundExceeded` above the documented bound — never a silent
wrong answer.
**Dependencies:** `math/cmplx` only. **No dependency on
`internal/crypto` or `internal/keystore`** — structurally enforced by
having no import of those packages (verifiable via `go list` dependency
check in CI).

## `cmd/banksec`

**Responsibility:** entrypoint; loads `SecurityProfile`, wires transport,
backend, storage; hosts the CLI loop.

**Inputs:** CLI arguments/flags, profile file path.
**Outputs:** process exit code; delegates all actual behavior to the
packages above.
**Dependencies:** all of the above, at the composition root only.
