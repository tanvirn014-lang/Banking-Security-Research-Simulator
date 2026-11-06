# BankSec Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Tasks within a milestone that the Dependency Graph marks parallel may run as separate concurrent task loops; everything else runs in the sequence given.

**Goal:** Implement the complete BankSec Lab system across 13 milestones —
foundation, core banking, security-mode differentiation, cryptography, key
management, audit, attack framework and scenarios, quantum simulations,
AI agent, benchmarking, integration validation, and documentation.

**Architecture:** One Go module, one process (`ARCHITECTURE.md`). CLI and
the Attack Harness's attack-path cross a real serialized protocol over
`net.Pipe`; everything else is trusted in-process Go calls. `SecurityProfile`
is injected once per run. This plan builds the plain mechanism first
(Milestone 2), then layers the vulnerable/hardened behavioral fork on top
(Milestone 3) — see `IMPLEMENTATION_PLAN.md` for why.

**Tech Stack:** Go 1.27 (stdlib `crypto/aes`, `crypto/cipher`,
`crypto/hmac`, `crypto/sha256`, `crypto/ed25519`, `crypto/ecdh`,
`crypto/mlkem`, `math/big`, `math/cmplx`, `log/slog`), `modernc.org/sqlite`,
`cloudflare/circl` (ML-DSA only).

**Spec:** `ARCHITECTURE.md`, `THREAT_MODEL.md`, `ATTACK_SURFACES.md`,
`CRYPTOGRAPHY.md`, `BENCHMARK_METHODOLOGY.md`, `COMPONENT_INTERFACES.md`
(read with `domain.X` replacing `ledger.X`/`backend.X` for shared types —
see `IMPLEMENTATION_PLAN.md`'s deviation note), `IMPLEMENTATION_PLAN.md`,
`DEPENDENCY_GRAPH.md`, `TEST_STRATEGY.md`.

## Global Constraints

- Go module name: `banksec-lab`, single module, no sub-modules.
- No production cryptographic primitive is implemented from scratch —
  stdlib or `cloudflare/circl` only. Weak-educational constructs (Task C2)
  are labeled toy constructs, never presented as secure.
- Run after **every** task: `gofmt -l .` (must print nothing),
  `go vet ./...`, `go test ./...`, `go test -race ./...`, `go build ./...`.
- Storage: `modernc.org/sqlite`, pure-Go, no cgo. Ledger, keystore, and
  audit each get their own SQLite file (never shared tables across those
  three — `ARCHITECTURE.md` §7).
- Config format: JSON. Fixture profiles at `configs/vulnerable.json`,
  `configs/hardened.json` (already created, Task F2).
- Money is `domain.Money` (`int64` minor units) everywhere — never
  floating point.
- `config.SecurityProfile` carries `AuthzEnforced bool` beyond
  `ARCHITECTURE.md` §5's listed fields (already added, Task F2) — a
  plan-level elaboration, not a spec change.
- This is a real git repository (worktree `worktree-foundation-core-banking`);
  commit at the end of every task as each task card specifies.
- Every new shared value type (`AccountID`, `Money`, `TransactionID`,
  `PrincipalID`, `Role`, `CryptoProfileName`, `DetectionRuleID`) lives in
  `internal/domain`, not in the package that happens to use it first.

## Review Focus

See `TEST_STRATEGY.md`'s "Review Focus" section for the full five-item
list with rationale (logical-vs-data race, PrivilegedAccess backdoor
containment, crypto-profile downgrade re-verification, revoked-key reuse,
Detection Engine actually running). Each item's owning task is named
inline at that task below (Tasks S3, H2, C5, K2, A4).

---

# Milestone 1 — Project Foundation

### Task 1 (F1): Go module + CLI skeleton — **DONE**

Completed and committed (`4d2da97`, `e56d4b7`) under the prior roadmap.
`go.mod` (module `banksec-lab`), `cmd/banksec/main.go`, `--version` flag,
`.gitignore` for build artifacts. No further action.

### Task 2 (F2): internal/config — SecurityProfile — **DONE**

Completed and committed (`8d06364`). `internal/config/profile.go`,
`SecurityProfile` struct (including `AuthzEnforced`), `Load(path string)`,
fixtures at `configs/vulnerable.json`/`configs/hardened.json`. No further
action.

### Task 3 (F3): internal/domain — shared value types

**Files:** Create `internal/domain/domain.go`, `internal/domain/domain_test.go`

**Interfaces:**
- Produces:
```go
type AccountID string
type TransactionID string
type Money int64 // minor units; debit negative, credit positive in ledger entries
type PrincipalID string
type Role string // "account-owner" | "privileged-operator"
type Principal struct { ID PrincipalID; Role Role }
type CryptoProfileName string // "weak-educational" | "standard" | "pqc"
type DetectionRuleID string
```
- Consumes: nothing (leaf package).

**Instructions:**
- No behavior beyond these type declarations and the two `Role` constants
  (`RoleAccountOwner`, `RolePrivilegedOperator`). This package must never
  import any other `internal/*` package — enforce via a test.

**Acceptance criteria:**
- Package compiles with zero dependencies on other `internal/*` packages.
- `Role` constants exist and are distinct.

**Tests:**
- `TestRoleConstants_Distinct` — asserts `RoleAccountOwner != RolePrivilegedOperator`.
- `TestNoInternalImports` — parses `domain.go`'s imports (via
  `go/parser`) and asserts none start with `banksec-lab/internal/`.

**Verification:** standard suite (Global Constraints).

**Commit:** `feat: shared domain value types`

### Task 4 (F4): Error handling conventions — internal/apperr

**Files:** Create `internal/apperr/apperr.go`, `internal/apperr/apperr_test.go`

**Interfaces:**
- Produces:
```go
// Code classifies an error for CLI exit codes and protocol error responses.
type Code string
const (
    CodeValidation   Code = "validation"
    CodeUnauthorized Code = "unauthorized"
    CodeNotFound     Code = "not_found"
    CodeConflict     Code = "conflict"   // e.g. replay/tamper/downgrade rejections
    CodeInternal     Code = "internal"
)

type Error struct { Code Code; Msg string; Err error } // implements error, Unwrap
func New(code Code, msg string) *Error
func Wrap(code Code, msg string, err error) *Error
func CodeOf(err error) Code // walks errors.As chain; CodeInternal if not an *Error
```

**Instructions:**
- Every sentinel error introduced in later tasks (`ErrInsufficientFunds`,
  `ErrUnauthorized`, `ErrReplayDetected`, etc.) is constructed via
  `apperr.New`/`apperr.Wrap` with the appropriate `Code`, so the CLI (Task
  T6) and protocol server (Task T5) can map errors to exit codes / response
  codes generically instead of a per-error-type switch statement.
- Document this convention in a short `CONVENTIONS.md` committed alongside
  (error codes, when to use `Wrap` vs `New`, that sentinel errors are
  compared with `errors.Is`, not string matching).

**Acceptance criteria:**
- `errors.Is(wrapped, originalSentinel)` works through `Wrap`.
- `CodeOf` returns `CodeInternal` for a plain `errors.New("x")`, and the
  correct code for an `*apperr.Error`.

**Tests:**
- `TestWrap_PreservesIsChecks` — wraps a sentinel, asserts `errors.Is` still matches.
- `TestCodeOf_UnknownError` — asserts `CodeInternal` for a non-`*apperr.Error`.
- `TestCodeOf_KnownError` — asserts the exact code round-trips.

**Verification:** standard suite.

**Commit:** `feat: error-code conventions via internal/apperr`

### Task 5 (F5): Logging conventions — internal/applog

**Files:** Create `internal/applog/applog.go`, `internal/applog/applog_test.go`

**Interfaces:**
- Produces:
```go
func New(w io.Writer) *slog.Logger // wraps slog.NewJSONHandler with fixed fields
// Convention: every log call includes "component" and, where applicable,
// "actor" and "attack_id" via slog.With(...) at the call site — this
// package only fixes the handler/format, not a wrapper API.
```

**Instructions:**
- Thin: one constructor around `log/slog`'s JSON handler. Do not build a
  custom logging abstraction — `slog.Logger` is used directly everywhere
  else; this task only standardizes construction (JSON output, consistent
  timestamp format) so every package's log lines parse the same way.

**Acceptance criteria:**
- `New` returns a `*slog.Logger` whose output is valid JSON per line.

**Tests:**
- `TestNew_ProducesValidJSONLines` — logs one line, `json.Unmarshal`s it,
  asserts no error and that a `"time"` key exists.

**Verification:** standard suite.

**Commit:** `feat: standardized JSON logging via internal/applog`

### Task 6 (F6): Test infrastructure — internal/testsupport

**Files:** Create `internal/testsupport/sqlite.go`, `internal/testsupport/testsupport_test.go`

**Interfaces:**
- Produces:
```go
func TempSQLitePath(t *testing.T) string // t.TempDir()-based unique path, cleans up automatically
func FixedClock(start time.Time) func() time.Time // deterministic clock for reproducibility tests
```

**Instructions:**
- Extracted from the duplicated `newTestStore(t)`-style helpers the
  earlier roadmap's Tasks 4-6 each wrote independently — Milestone 2's
  tasks import this package instead of re-deriving the pattern.

**Acceptance criteria:**
- Two calls to `TempSQLitePath` in the same test return different paths.
- `FixedClock` always returns the same instant regardless of real time
  elapsed.

**Tests:**
- `TestTempSQLitePath_Unique` — two calls, assert paths differ.
- `TestFixedClock_Stable` — call the returned func twice with a sleep in
  between, assert equal results.

**Verification:** standard suite.

**Commit:** `feat: shared SQLite/clock test helpers`

---

# Milestone 2 — Core Transaction System

### Task 7 (T1): internal/ledger — double-entry store (basic)

**Files:** Create `internal/ledger/store.go`, `internal/ledger/sqlite.go`, `internal/ledger/store_test.go`

**Dependencies:** F3 (domain types), F6 (test helpers)

**Interfaces:**
- Produces:
```go
type Entry struct {
    TxID      domain.TransactionID
    AccountID domain.AccountID
    Amount    domain.Money
    Timestamp time.Time
}
type Store interface {
    AppendTransaction(ctx context.Context, entries []Entry) error
    Balance(ctx context.Context, acct domain.AccountID) (domain.Money, error)
    History(ctx context.Context, acct domain.AccountID) ([]Entry, error)
    CheckInvariant(ctx context.Context) (ok bool, violatingTxIDs []domain.TransactionID, err error)
}
func NewSQLiteStore(path string) (Store, error)
var ErrUnbalancedEntries = apperr.New(apperr.CodeValidation, "entries do not sum to zero")
```

**Instructions:**
- Schema: one `entries` table (`tx_id`, `account_id`, `amount`,
  `timestamp`), indexed by `account_id`.
- `AppendTransaction` sums the batch's `Amount`; non-zero sum returns
  `ErrUnbalancedEntries` before any write (single DB transaction for the
  write itself — this is the structural guarantee behind "ledger
  integrity," not a security-mode toggle; it applies identically in both
  modes).
- `CheckInvariant` groups by `tx_id`, finds any whose sum is non-zero.

**Acceptance criteria:**
- Balanced entries succeed; unbalanced entries rejected before any row is
  written (verify via `History` returning empty after a rejected call).
- `CheckInvariant` returns `ok=true` after only-balanced writes.

**Tests:**
- `TestAppendTransaction_BalancedSucceeds` — deposit+credit pair, `Balance` reflects sum.
- `TestAppendTransaction_UnbalancedRejected` — asserts `errors.Is(err, ErrUnbalancedEntries)`, then `History` is empty.
- `TestHistory_OrderedByTime` — two transactions, asserts return order.
- `TestCheckInvariant_OKAfterBalancedWrites`.

**Verification:** standard suite + `go test -race ./internal/ledger/...`.

**Commit:** `feat: double-entry ledger store on SQLite`

### Task 8 (T2): internal/keystore — key store (basic, plaintext)

**Files:** Create `internal/keystore/store.go`, `internal/keystore/sqlite.go`, `internal/keystore/store_test.go`

**Dependencies:** F3, F6

**Interfaces:**
- Produces:
```go
type KeyMeta struct {
    ID        string
    Profile   domain.CryptoProfileName
    CreatedAt time.Time
    RotatedAt *time.Time
    RevokedAt *time.Time
}
type Store interface {
    Generate(ctx context.Context, profile domain.CryptoProfileName) (KeyMeta, error)
    Get(ctx context.Context, id string) (material []byte, meta KeyMeta, err error)
    Rotate(ctx context.Context, id string) (KeyMeta, error)
    Revoke(ctx context.Context, id string) error
}
func NewSQLiteStore(path string) (Store, error) // encrypted-at-rest arrives in Task K1
var ErrKeyRevoked = apperr.New(apperr.CodeConflict, "key has been revoked")
var ErrKeyNotFound = apperr.New(apperr.CodeNotFound, "key not found")
```

**Instructions:**
- Plain random key material (`crypto/rand`) sized per profile
  (32 bytes for `"standard"` is sufficient for this task — real
  profile-specific sizing is finalized in Milestone 4/5). Material is
  stored as-is (plaintext) — this is intentionally the vulnerable-mode
  behavior; Task K1 adds the hardened wrap.
- Own SQLite file, separate from the ledger's (`ARCHITECTURE.md` §7).

**Acceptance criteria:** Generate/Get/Rotate/Revoke round-trip; revoked
key's `Get` fails; unknown ID's `Get` fails.

**Tests:**
- `TestGenerateGet_RoundTrip`
- `TestRotate_UpdatesMetaAndMaterial` — material differs before/after.
- `TestRevoke_BlocksGet` — `errors.Is(err, ErrKeyRevoked)`.
- `TestGet_UnknownID` — `errors.Is(err, ErrKeyNotFound)`.

**Verification:** standard suite.

**Commit:** `feat: keystore with rotation and revocation (plaintext baseline)`

### Task 9 (T3): internal/audit — event stream (basic)

**Files:** Create `internal/audit/stream.go`, `internal/audit/sqlite.go`, `internal/audit/stream_test.go`

**Dependencies:** F3, F6

**Interfaces:**
- Produces:
```go
type Event struct {
    ID        string
    Timestamp time.Time
    Type      string
    Component string
    Actor     domain.PrincipalID
    Operation string
    Outcome   string
    TxID      *domain.TransactionID
    AttackID  *string
}
type Stream interface {
    Record(ctx context.Context, e Event) error
    Since(ctx context.Context, t time.Time) ([]Event, error)
    Subscribe(fn func(Event)) (unsubscribe func())
}
func NewSQLiteStream(path string) (Stream, error) // hash-chaining arrives in Task A1
```

**Instructions:**
- Own SQLite file, separate from ledger and keystore.
- `Subscribe`'s callbacks run synchronously from `Record` (single process,
  no queue needed).
- Because `Event.Actor` is now `domain.PrincipalID` (not a bare `string`,
  per the `internal/domain` deviation in `IMPLEMENTATION_PLAN.md`), the
  import-cycle workaround `COMPONENT_INTERFACES.md` used no longer
  applies — `internal/audit` imports `internal/domain`, never
  `internal/backend`.

**Acceptance criteria:** record/query round-trip; subscriber receives
events synchronously.

**Tests:**
- `TestRecordSince_RoundTrip`
- `TestSubscribe_ReceivesRecordedEvent` — channel-based receive with timeout.

**Verification:** standard suite.

**Commit:** `feat: audit event stream (basic, no hash-chaining yet)`

### Task 10 (T4): internal/backend — banking service (always-enforced baseline)

**Files:** Create `internal/backend/service.go`, `internal/backend/service_test.go`

**Dependencies:** T1, T2, T3

**Interfaces:**
- Produces:
```go
type Service interface {
    CreateAccount(ctx context.Context, owner domain.PrincipalID) (domain.AccountID, error)
    Deposit(ctx context.Context, actor domain.Principal, acct domain.AccountID, amount domain.Money) error
    Withdraw(ctx context.Context, actor domain.Principal, acct domain.AccountID, amount domain.Money) error
    Transfer(ctx context.Context, actor domain.Principal, from, to domain.AccountID, amount domain.Money) error
    Balance(ctx context.Context, actor domain.Principal, acct domain.AccountID) (domain.Money, error)
    History(ctx context.Context, actor domain.Principal, acct domain.AccountID) ([]ledger.Entry, error)
}
func NewService(l ledger.Store, k keystore.Store, a audit.Stream) Service
var ErrInsufficientFunds = apperr.New(apperr.CodeConflict, "insufficient funds")
var ErrUnauthorized = apperr.New(apperr.CodeUnauthorized, "unauthorized")
var ErrValidation = apperr.New(apperr.CodeValidation, "validation failed")
```

**Instructions:**
- This baseline **always** enforces account ownership and always
  validates non-negative amounts — there is no vulnerable/hardened fork
  yet (Task S1 adds the `SecurityProfile.AuthzEnforced` toggle on top of
  this). Think of this task as building the hardened behavior first, and
  S1 as adding the ability to *relax* it.
- Every operation records an `audit.Event` (success or failure).
- Account ownership tracked in a `domain.AccountID -> domain.PrincipalID`
  map maintained by the Service (in-memory for this task — acceptable
  since it's rebuilt from `CreateAccount` calls within a run; durability
  across process restarts is out of scope for this plan).
- `crypto.Engine` is **not** a constructor parameter yet — Milestone 4
  isn't built. `keystore.Store` is accepted but unused by business logic in
  this task (wired for later use, consistent with `COMPONENT_INTERFACES.md`'s
  declared dependency — an unused parameter is legal Go and not a defect).

**Acceptance criteria:** deposit/withdraw/transfer/balance/history work;
insufficient funds rejected; unauthorized owner rejected (always, in this
baseline); negative amount rejected; every call emits an audit event.

**Tests:**
- `TestDepositBalance_RoundTrip`
- `TestWithdraw_InsufficientFunds`
- `TestTransfer_UnauthorizedOwnerRejected` — owner-2 cannot transfer from owner-1's account.
- `TestDeposit_NegativeAmountRejected`
- `TestEveryOperation_EmitsAuditEvent`

**Verification:** standard suite.

**Commit:** `feat: banking backend with always-enforced authorization baseline`

### Task 11 (T5): internal/protocol — wire protocol (basic, no replay/tamper/downgrade yet)

**Files:** Create `internal/protocol/frame.go`, `internal/protocol/transport_pipe.go`, `internal/protocol/server.go`, `internal/protocol/client.go`, `internal/protocol/protocol_test.go`

**Dependencies:** T4

**Interfaces:**
- Produces:
```go
type Frame struct { Version uint8; Seq uint64; Payload []byte }
type Request struct { Op string; Actor domain.Principal; Params map[string]string }
type Response struct { OK bool; Error string; Data map[string]string }
type Client interface { Send(ctx context.Context, req Request) (Response, error) }
type Server interface { Serve(ctx context.Context, svc backend.Service) error }
func NewPipeTransport() (clientConn, serverConn net.Conn)
func NewClient(conn net.Conn) Client
func NewServer(conn net.Conn) Server
```

**Instructions:**
- Correct request/response plumbing over `net.Pipe` only — no sequence
  tracking, no auth tag, no profile declaration yet. This is deliberately
  minimal; Task S2 adds all three as a `SecurityProfile`-gated layer on
  top of this frame format (the `Frame` struct gains `CryptoProf` and
  `AuthTag` fields in Task S2, additively).
- `Op` dispatches to the matching `backend.Service` method; `Params` are
  string-encoded (CLI-friendly); errors map to `Response.Error` via
  `apperr.CodeOf`.

**Acceptance criteria:** every `backend.Service` operation is reachable
over the pipe and round-trips correctly.

**Tests:**
- `TestSendReceive_CreateAccount`
- `TestSendReceive_DepositAndBalance`
- `TestSendReceive_UnknownOp_ReturnsError`

**Verification:** standard suite.

**Commit:** `feat: basic request/response wire protocol over net.Pipe`

### Task 12 (T6): cmd/banksec — CLI wiring

**Files:** Modify `cmd/banksec/main.go`, Create `cmd/banksec/cli.go`, `cmd/banksec/cli_test.go`

**Dependencies:** T5

**Interfaces:**
- Produces: subcommands `create-account`, `deposit`, `withdraw`,
  `transfer`, `balance`, `history`. `runMain` (from Task F1) is
  **extended**, not replaced — `--version` must keep passing F1's own
  test after this task lands.
- Wiring order: `config.Load` -> `ledger.NewSQLiteStore` ->
  `keystore.NewSQLiteStore` -> `audit.NewSQLiteStream` ->
  `backend.NewService` -> `protocol.NewPipeTransport` +
  `protocol.NewServer(...).Serve` (background goroutine) +
  `protocol.NewClient(...)`.

**Acceptance criteria:** `deposit` then `balance` via the CLI reflects the
deposited amount; a forged `--as` principal that doesn't own the target
account is still rejected **by the Backend**, not merely by CLI-side
checks (there are none at this layer — `THREAT_MODEL.md`, CLI is not a
trust boundary).

**Tests:**
- `TestCLI_DepositThenBalance` — integration, full wiring in `t.TempDir()`.
- `TestCLI_ForgedPrincipalStillRejectedServerSide`.

**Verification:** standard suite (integration level — first appearance of
that test level per `TEST_STRATEGY.md`).

**Commit:** `feat: CLI wiring for core banking operations`

---

# Milestone 3 — Security Architecture

### Task 13 (S1): Backend authorization enforcement toggle + input validation

**Files:** Modify `internal/backend/service.go`, `internal/backend/service_test.go`

**Dependencies:** T4, F2 (`SecurityProfile.AuthzEnforced`)

**Interfaces:**
- `NewService` gains a parameter: `func NewService(l ledger.Store, k keystore.Store, a audit.Stream, p config.SecurityProfile) Service`.

**Instructions:**
- Authorization check from T4 now runs **only when** `p.AuthzEnforced` is
  true; vulnerable profile (`AuthzEnforced: false`) allows cross-account
  action by any account-owner principal (the deliberately exploitable
  surface for Task I1).
- Validation (non-negative amounts, account existence) remains always-on
  in both modes — business-rule correctness, not a security toggle
  (`ARCHITECTURE.md` §6: "business functionality same in both modes").

**Acceptance criteria:** same cross-account transfer attempt succeeds
under vulnerable profile, fails under hardened profile.

**Tests:**
- `TestTransfer_UnauthorizedAllowedWhenAuthzNotEnforced`
- `TestTransfer_UnauthorizedRejectedWhenAuthzEnforced` (re-asserts T4's
  test still holds with the profile parameter threaded through)

**Verification:** standard suite.

**Commit:** `feat: SecurityProfile-gated authorization enforcement`

### Task 14 (S2): Protocol replay/tamper/downgrade enforcement

**Files:** Modify `internal/protocol/frame.go`, `server.go`, `client.go`; `protocol_test.go`

**Dependencies:** T5, F2

**Interfaces:**
- `Frame` gains `CryptoProf domain.CryptoProfileName` and `AuthTag []byte`.
- `NewClient`/`NewServer` gain parameters: a placeholder single-profile MAC
  function `func(key, data []byte) []byte` (backed by `crypto/hmac` +
  `crypto/sha256` directly — `internal/crypto`'s `Engine` doesn't exist
  until Milestone 4; Task C5 replaces this placeholder with the real
  `Engine`) and a `macKey []byte`, plus `config.SecurityProfile`.
- New errors: `var ErrReplayDetected = apperr.New(apperr.CodeConflict, ...)`,
  `ErrAuthFailed = apperr.New(apperr.CodeConflict, ...)`,
  `ErrProfileDowngrade = apperr.New(apperr.CodeConflict, ...)`.

**Instructions:**
- Server tracks highest `Seq` seen per connection; hardened mode rejects
  `Seq <= lastSeen`, vulnerable mode does not track it.
- Server recomputes the MAC over the received payload; hardened mode
  rejects on mismatch, vulnerable mode skips verification when
  `p.ProtocolAuthEnforced` is false.
- Server compares `Frame.CryptoProf` against `p.MinAcceptedCryptoProfile`;
  hardened mode rejects below minimum, vulnerable mode does not check.
  (With only one real profile existing at this point, use the string
  `"standard"` for both declared and minimum — the *mechanism* is what's
  being tested here, not multi-profile selection; Task C5 exercises it
  against all three real profiles.)

**Acceptance criteria:** each of replay/tamper/downgrade independently
toggles between accepted (vulnerable) and rejected (hardened).

**Tests:**
- `TestReplay_RejectedWhenHardened` / `TestReplay_AcceptedWhenVulnerable`
- `TestTamper_RejectedWhenHardened` / `TestTamper_AcceptedWhenVulnerable`
- `TestDowngrade_RejectedWhenHardened` / `TestDowngrade_AcceptedWhenVulnerable`

**Verification:** standard suite.

**Commit:** `feat: protocol replay/tamper/downgrade enforcement`

### Task 15 (S3): Ledger concurrency safety and integrity under load — **Review Focus #1**

**Files:** Create `internal/backend/concurrency_test.go`; Modify `internal/backend/service.go` if the hardened transfer path needs explicit transaction-scoping (likely: wrap read-balance + append-transaction in one DB transaction for hardened mode).

**Dependencies:** S1

**Instructions:**
- **Hardened mode:** `Transfer` reads the source balance and appends the
  resulting entries inside a single serializing unit (DB transaction or
  equivalent locking) — concurrent transfers from the same account cannot
  both read a stale balance and both succeed past what funds allow.
- **Vulnerable mode:** `Transfer` reads the balance, then later appends
  entries, **without** that serializing unit — a real TOCTOU window
  exists. This must be achieved using ordinary, race-detector-safe Go
  concurrency primitives throughout (e.g., the ledger's own SQLite writes
  are still safely synchronized at the storage layer) — only the
  *business-level* atomicity is removed, never memory-level safety. See
  `TEST_STRATEGY.md`'s Review Focus #1: this is the most likely place for
  an implementer to accidentally introduce a real data race while trying
  to build a "vulnerable" mode.

**Acceptance criteria:**
- `go test -race` is clean on **both** modes' concurrency tests — no
  exceptions.
- Hardened mode: 20 concurrent transfers draining a 1000-unit balance by
  100 each never produce a negative balance and never violate
  `ledger.CheckInvariant`.
- Vulnerable mode: the same scenario is allowed (not required every run,
  but the test must demonstrate it occurring at least once across
  repeated attempts, or deterministically via an injected delay) to
  violate the balance invariant — documenting the vulnerability, not
  hiding it.

**Tests:**
- `TestConcurrentTransfers_HardenedPreservesInvariant`
- `TestConcurrentTransfers_VulnerableAllowsOverdraftButNoDataRace`

**Verification:** standard suite + `go test -race ./internal/backend/...` (required, not optional, for this task).

**Commit:** `test: concurrency safety differential between security modes`

### Task 16 (S4): Security-mode end-to-end test

**Files:** Create `internal/backend/securitymode_e2e_test.go`

**Dependencies:** S1, S2, S3

**Instructions:**
- One test file wiring the full stack (ledger/keystore/audit/backend/
  protocol) under each profile, running the same operation sequence, and
  asserting the three behavioral differences (authz, replay/tamper/
  downgrade, concurrency) all hold simultaneously in one coherent run —
  not just in isolation per earlier tasks.

**Acceptance criteria:** a single table-driven test, parameterized on
profile, demonstrates all three differences pass/fail as expected per
profile.

**Tests:**
- `TestSecurityMode_FullDifferential` (table-driven over both profiles)

**Verification:** standard suite.

**Commit:** `test: end-to-end security-mode differential across the full stack`

---

# Milestone 4 — Cryptographic System

### Task 17 (C1): internal/crypto — Engine interface + standard profile

**Files:** Create `internal/crypto/engine.go`, `internal/crypto/standard.go`, `internal/crypto/engine_test.go`

**Dependencies:** F3

**Interfaces:**
```go
type Engine interface {
    Encrypt(profile domain.CryptoProfileName, key, plaintext []byte) ([]byte, error)
    Decrypt(profile domain.CryptoProfileName, key, ciphertext []byte) ([]byte, error)
    Sign(profile domain.CryptoProfileName, key, msg []byte) ([]byte, error)
    Verify(profile domain.CryptoProfileName, pubkey, msg, sig []byte) (bool, error)
    MAC(profile domain.CryptoProfileName, key, msg []byte) ([]byte, error)
}
func NewEngine() Engine
var ErrProfileNotImplemented = apperr.New(apperr.CodeValidation, "crypto profile not implemented")
```

**Instructions:** `"standard"` only in this task: AES-GCM
(Encrypt/Decrypt), Ed25519 (Sign/Verify), HMAC-SHA-256 (MAC). Any other
profile name returns `ErrProfileNotImplemented` from every method until
Tasks C2-C4 add it.

**Acceptance criteria/Tests:** identical to the earlier roadmap's proven
design — `TestEncryptDecrypt_RoundTrip`, `TestSignVerify_RoundTrip`,
`TestMAC_TamperDetected`, `TestUnimplementedProfile`.

**Verification:** standard suite.

**Commit:** `feat: standard crypto profile (AES-GCM, Ed25519, HMAC-SHA256)`

### Task 18 (C2): Weak-educational crypto profile

**Files:** Create `internal/crypto/weakeducational.go`, `internal/crypto/weakeducational_test.go`

**Dependencies:** C1

**Interfaces:** Same `Engine` methods, dispatched for
`profile == "weak-educational"`.

**Instructions (per `CRYPTOGRAPHY.md` §1.1, binding — these are
deliberately-broken constructs, not bugs):**
- `Encrypt`/`Decrypt`: AES in ECB mode (manual block-by-block chaining via
  `crypto/aes`'s block cipher directly — not `cipher.NewCBCEncrypter`/GCM;
  no IV, so identical plaintext blocks produce identical ciphertext
  blocks, demonstrating pattern leakage).
- `Sign`/`Verify`: toy RSA with a fixed, documented small modulus (20-24
  bits, generated via `math/big` at package init from two small fixed
  primes — not a general RSA implementation, just enough for signatures
  over short digests) — brute-forceable within the time budget Task I5
  will assert.
- `MAC`: HMAC-SHA-256 with a truncated/weak key (document the exact
  truncation, e.g. first 4 bytes of the supplied key repeated to fill the
  block size) — demonstrating weak key-derivation, not a different hash.
- Every method's result, when logged or audited, is tagged with
  `"profile": "weak-educational"` so nothing downstream can mistake it
  for the standard profile's output.

**Acceptance criteria:** ECB mode visibly repeats ciphertext blocks for
repeated plaintext blocks (this is the point, not a bug); toy RSA
sign/verify round-trips; weak MAC still changes with input (it's weak,
not broken) but is demonstrably brute-forceable by Task I5.

**Tests:**
- `TestECBMode_RepeatsBlocksForRepeatedPlaintext` — two identical 16-byte
  plaintext blocks produce identical ciphertext blocks.
- `TestToyRSA_SignVerify_RoundTrip`
- `TestToyRSA_FactorableWithinBudget` — brute-force factor the fixed
  modulus within e.g. 1,000,000 trial divisions, asserting it succeeds
  (this *is* the acceptance criterion for "weak," not a vulnerability to
  fix).
- `TestWeakMAC_StillChangesWithInput`

**Verification:** standard suite.

**Commit:** `feat: weak-educational crypto profile (labeled, bounded toy constructs)`

### Task 19 (C3): Post-quantum profile — ML-KEM

**Files:** Create `internal/crypto/pqc_kem.go`, `internal/crypto/pqc_kem_test.go`

**Dependencies:** C1

**Instructions:**
- First: `go doc crypto/mlkem` against the installed `go1.27.3` toolchain
  to confirm the exact API (key generation, encapsulation/decapsulation
  function names) — do not assume the signature sketched here is final;
  record what you find in the task report.
- Wire ML-KEM-768 (or whatever `crypto/mlkem` exposes) into
  `Encrypt`/`Decrypt` for `profile == "pqc"` as a KEM-then-AEAD
  construction (encapsulate a shared secret, derive an AES-GCM key from
  it via HKDF or direct use per the stdlib API's guidance, encrypt the
  payload under that key). If `crypto/mlkem` is absent from the installed
  toolchain, fall back to `cloudflare/circl`'s ML-KEM implementation
  instead (per `IMPLEMENTATION_PLAN.md`'s substitution note) and record
  which path was taken.

**Acceptance criteria:** KEM-based encrypt/decrypt round-trips; a
tampered ciphertext fails to decrypt (AEAD integrity, not a separate
check).

**Tests:**
- `TestMLKEM_EncryptDecrypt_RoundTrip`
- `TestMLKEM_TamperedCiphertextFails`

**Verification:** standard suite.

**Commit:** `feat: post-quantum profile — ML-KEM key encapsulation`

### Task 20 (C4): Post-quantum profile — ML-DSA signatures

**Files:** Create `internal/crypto/pqc_dsa.go`, `internal/crypto/pqc_dsa_test.go`; Modify `go.mod`/`go.sum` (new dependency: `cloudflare/circl`)

**Dependencies:** C1

**Instructions:**
- Wire `cloudflare/circl`'s ML-DSA (Dilithium) into `Sign`/`Verify` for
  `profile == "pqc"`. Pin the dependency to a specific tagged `circl`
  version in `go.mod` (`go get cloudflare/circl@<tag>`) and record the
  exact version in the task report (per `CRYPTOGRAPHY.md` §6 — this
  document does not freeze a version number).

**Acceptance criteria:** sign/verify round-trips; a tampered message fails
verification.

**Tests:**
- `TestMLDSA_SignVerify_RoundTrip`
- `TestMLDSA_TamperedMessageFailsVerify`

**Verification:** standard suite.

**Commit:** `feat: post-quantum profile — ML-DSA signatures via cloudflare/circl`

### Task 21 (C5): Protocol profile wiring — **Review Focus #3**

**Files:** Modify `internal/protocol/server.go`, `client.go`; `protocol_test.go`

**Dependencies:** C1, C2, C3, C4, S2

**Instructions:**
- Replace S2's placeholder single-profile MAC function with the real
  `crypto.Engine`, selecting MAC (standard) vs. toy-weak MAC
  (weak-educational) vs. a PQC-appropriate authentication primitive per
  the frame's declared `CryptoProf`.
- **Re-verify** (not just re-use) the downgrade-enforcement test from S2
  against all three real profiles now that they exist — this is Review
  Focus #3 from `TEST_STRATEGY.md`: a regression here silently reopens
  the downgrade surface Task I2 depends on being closed.

**Acceptance criteria:** downgrade from `"pqc"`/`"standard"` to
`"weak-educational"` is rejected in hardened mode for all profile pairs,
not just the single pair S2 tested.

**Tests:**
- `TestDowngrade_AllProfilePairs_RejectedWhenHardened` (table-driven over
  all 3x3 profile-declared/profile-minimum combinations where declared <
  minimum)

**Verification:** standard suite.

**Commit:** `feat: wire real multi-profile crypto engine into protocol`

---

# Milestone 5 — Key Management

### Task 22 (K1): Keystore encrypted-at-rest toggle

**Files:** Modify `internal/keystore/sqlite.go`, `store_test.go`

**Dependencies:** T2, C1

**Interfaces:** `NewSQLiteStore` gains parameters:
`func NewSQLiteStore(path string, engine crypto.Engine, encryptAtRest bool) (Store, error)`.

**Instructions:**
- `encryptAtRest=true`: wrap generated material with
  `engine.Encrypt("standard", storeKey, material)` before persisting,
  where `storeKey` is generated once at store construction and held only
  in memory (never persisted itself — if it were, "encrypted at rest"
  would be meaningless). `Get` decrypts transparently.
- `encryptAtRest=false`: persist material as-is (T2's original behavior).

**Acceptance criteria:** raw row content differs observably between
modes for the same generated key (plaintext vs. ciphertext bytes); `Get`
returns usable material in both modes.

**Tests:**
- `TestEncryptAtRest_RawRowIsCiphertext` — reads the row directly via raw
  SQL, asserts it does not equal the material `Get` returns, under
  `encryptAtRest=true`.
- `TestNoEncryptAtRest_RawRowIsPlaintext` — asserts equality under
  `encryptAtRest=false`.

**Verification:** standard suite.

**Commit:** `feat: keystore encrypted-at-rest toggle`

### Task 23 (K2): Rotation/revocation enforcement across consumers — **Review Focus #4**

**Files:** Modify `internal/backend/service.go` (if it caches any key
material — audit and remove caching if found), `internal/protocol/server.go`
(same check); Create `internal/keystore/lifecycle_integration_test.go`

**Dependencies:** K1, T4, C5

**Instructions:**
- Audit every caller of `keystore.Store.Get` introduced so far
  (`internal/backend`, `internal/protocol`) and confirm none holds key
  material across more than one logical operation — each operation must
  re-`Get` immediately before use. This is Review Focus #4 from
  `TEST_STRATEGY.md`: a caching bug here would make Task I4's
  key-management attack scenario meaningless, since a revoked key would
  stay usable through the cache.
- If a caller is found to cache, fix it as part of this task (this is the
  one task in the plan explicitly scoped to touch other packages'
  internals, because the review focus item requires it).

**Acceptance criteria:** a key revoked mid-run immediately fails for the
next operation attempting to use it, in every consumer.

**Tests:**
- `TestRevokedKey_ImmediatelyRejectedByEveryConsumer` (parameterized over
  each known consumer)

**Verification:** standard suite.

**Commit:** `test: verify no consumer caches key material across revocation`

### Task 24 (K3): Access auditing

**Files:** Modify `internal/keystore/sqlite.go`, `store_test.go`

**Dependencies:** K1, T3

**Interfaces:** `NewSQLiteStore` gains an `audit.Stream` parameter.

**Instructions:** every `Generate`/`Get`/`Rotate`/`Revoke` call records an
`audit.Event` (`Component: "keystore"`, `Operation: <method name>`,
`Outcome: "ok"|"error"`).

**Acceptance criteria:** each of the four operations produces exactly one
audit event.

**Tests:**
- `TestEachKeystoreOperation_EmitsOneAuditEvent`

**Verification:** standard suite.

**Commit:** `feat: keystore access auditing`

### Task 25 (K4): Vulnerable vs. hardened storage mode end-to-end test

**Files:** Create `internal/keystore/securitymode_e2e_test.go`

**Dependencies:** K1, K2, K3

**Instructions:** one test wiring the keystore under both profiles via
`config.Load`, demonstrating the plaintext-vs-ciphertext difference and
the access-audit trail together.

**Tests:** `TestKeystore_SecurityModeDifferential`

**Verification:** standard suite.

**Commit:** `test: end-to-end key-management security-mode differential`

---

# Milestone 6 — Audit System

*(Depends only on Milestone 2; parallel with Milestones 4-5 — see
`DEPENDENCY_GRAPH.md`.)*

### Task 26 (A1): Hash-chaining and tamper detection

**Files:** Modify `internal/audit/sqlite.go`, `stream_test.go`

**Dependencies:** T3, F2

**Interfaces:** `NewSQLiteStream` gains `hashChained bool`;
`Stream` gains `VerifyChain(ctx context.Context) (ok bool, brokenAt *string, err error)`;
new error `ErrChainNotEnabled = apperr.New(apperr.CodeValidation, ...)`.

**Instructions:** each event's `hash = SHA256(prev_hash || serialized
event)` when `hashChained=true` (hardened mode); `VerifyChain` recomputes
and compares. `hashChained=false` (vulnerable mode): `VerifyChain` returns
`ErrChainNotEnabled`.

**Tests:**
- `TestVerifyChain_OKWhenUntampered`
- `TestVerifyChain_DetectsTamper` — raw-SQL `UPDATE` on a row, bypassing
  `Record`, then `VerifyChain` reports it.
- `TestVerifyChain_ErrorsWhenNotEnabled`

**Verification:** standard suite.

**Commit:** `feat: audit hash-chaining and tamper detection`

### Task 27 (A2): Querying refinements

**Files:** Modify `internal/audit/stream.go`, `sqlite.go`, `stream_test.go`

**Dependencies:** T3

**Interfaces:** `Stream` gains
`Filter(ctx context.Context, f Filter) ([]Event, error)` where
`Filter struct { Component string; AttackID *string; Since, Until time.Time }`
(zero-value fields mean "no constraint on this field").

**Tests:**
- `TestFilter_ByComponent`
- `TestFilter_ByAttackID`
- `TestFilter_ByTimeRange`

**Verification:** standard suite.

**Commit:** `feat: audit event filtering by component/attack/time-range`

### Task 28 (A3): JSON/CSV export

**Files:** Create `internal/audit/export.go`, `export_test.go`

**Dependencies:** A2

**Interfaces:**
```go
func ExportJSON(w io.Writer, events []Event) error
func ExportCSV(w io.Writer, events []Event) error
```

**Tests:**
- `TestExportJSON_RoundTrips` — export then `json.Unmarshal` back, compare.
- `TestExportCSV_ParsesBack` — export then `encoding/csv` read back, field count matches.

**Verification:** standard suite.

**Commit:** `feat: audit event JSON/CSV export`

### Task 29 (A4): Detection Engine — **Review Focus #5**

**Files:** Create `internal/detection/engine.go`, `internal/detection/rules.go`, `internal/detection/engine_test.go`

**Dependencies:** A1, F3

**Interfaces:**
```go
type Rule interface {
    ID() domain.DetectionRuleID
    Evaluate(window []audit.Event) (triggered bool, detail string)
}
type DetectionEvent struct { RuleID domain.DetectionRuleID; Timestamp time.Time; RelatedEvent audit.Event }
type Engine interface {
    Register(r Rule)
    Run(ctx context.Context, stream audit.Stream) error // subscribes, evaluates, emits
}
```

**Instructions:** `Run` calls `stream.Subscribe`; each new event is
evaluated against every registered rule; a trigger is recorded back into
the same `audit.Stream` as a new `Event` with `Type: "detection"`. Ship
at least one concrete rule: balance-invariant-violation (polls
`ledger.CheckInvariant` on a timer or on every ledger-related event —
implementer's choice, document which).
- **Review Focus #5:** the acceptance test must prove the Engine actually
  runs as part of normal backend operation (wired into Task T6/S4's CLI
  wiring as a background goroutine alongside the protocol server), not
  merely that `Evaluate` works when called directly from a unit test.

**Acceptance criteria:** triggering the ledger invariant (e.g., via a
direct-storage tamper in a test) produces a detection event within a
bounded time window, **while the full CLI-wired stack is running**, not
just via direct method calls.

**Tests:**
- `TestDetectionEngine_RuleTriggersOnViolation` (direct unit test)
- `TestDetectionEngine_RunsDuringNormalCLIOperation` (integration —
  satisfies Review Focus #5 explicitly)

**Verification:** standard suite.

**Commit:** `feat: rule-based Detection Engine wired into normal operation`

---

# Milestone 7 — Attack Framework

### Task 30 (H1): Scenario struct + Oracle interface

**Files:** Create `internal/harness/scenario.go`, `internal/harness/oracle.go`, `internal/harness/harness_test.go`

**Dependencies:** T1, T2, T3 (Oracle reads all three)

**Interfaces:**
```go
type Oracle interface {
    LedgerSnapshot(ctx context.Context) (ledger.State, error) // define ledger.State as all entries + invariant result
    KeySnapshot(ctx context.Context, keyID string) (keystore.KeyMeta, error)
    AuditEventsSince(ctx context.Context, t time.Time) ([]audit.Event, error)
}
type Scenario struct {
    ID       string
    Category string
    Prereqs  func(Oracle) (bool, error)
    Verify   func(context.Context, Oracle) (success bool, evidence Evidence, err error)
    StopCond func(Evidence) bool
}
type Evidence map[string]any
```

**Tests:**
- `TestOracle_LedgerSnapshot_ReflectsRealState`
- `TestScenario_PrereqsGateExecution`

**Verification:** standard suite.

**Commit:** `feat: attack scenario struct and read-only Oracle`

### Task 31 (H2): PrivilegedAccess interface — **Review Focus #2**

**Files:** Create `internal/harness/privileged.go`, `privileged_test.go`; Create `internal/protocol/no_privileged_access_test.go` (structural test)

**Dependencies:** H1

**Interfaces:**
```go
type PrivilegedAccess interface {
    RawLedgerWrite(ctx context.Context, entries []ledger.Entry) error
    RawAuditWrite(ctx context.Context, e audit.Event) error
    RawKeyBytes(ctx context.Context, id string) ([]byte, error)
}
```

**Instructions:**
- Implemented via direct SQL access to the ledger/audit/keystore SQLite
  files, bypassing `internal/backend` and `internal/keystore`'s own
  encryption/decryption entirely (`RawKeyBytes` returns the stored bytes
  as-is — plaintext in vulnerable mode, still-wrapped ciphertext in
  hardened mode).
- **Review Focus #2 (structural, not just behavioral):** add a test in
  `internal/protocol` — a different package than `internal/harness` —
  that attempts to construct a `protocol.Request` whose `Op` would need
  `PrivilegedAccess` and asserts no such `Op` is recognized by the server.
  This proves the interface is unreachable from the one real external
  entrypoint (the protocol server), not merely "nothing currently calls
  it."

**Acceptance criteria:** `PrivilegedAccess` methods work as a direct
insider-style bypass; the cross-package structural test confirms no
protocol `Op` routes to it.

**Tests:**
- `TestPrivilegedAccess_RawLedgerWrite_BypassesInvariantCheck`
- `TestPrivilegedAccess_RawKeyBytes_ReturnsStoredRepresentationAsIs`
- `TestProtocol_NoOpRoutesToPrivilegedAccess` (in `internal/protocol`)

**Verification:** standard suite.

**Commit:** `feat: PrivilegedAccess insider-simulation channel, structurally isolated`

### Task 32 (H3): Harness Runner (+ Result schema)

**Files:** Create `internal/harness/runner.go`, `runner_test.go`

**Dependencies:** H1, H2

**Interfaces:**
```go
type Result struct {
    AttackID            string
    TargetConfiguration string // "vulnerable" | "hardened"
    AttackType           string
    Success              bool
    ExecutionTimeMS       int64
    TimeToCompromiseMS    *int64
    DataLeakedBytes       *int64
    RecordsCompromised    *int64
    DetectionLatencyMS    *int64
    Attempts              int
    ComputationalCost     *int64
    MemoryUsageBytes      *int64
    Seed                  *int64
}
type Runner interface {
    Run(ctx context.Context, s Scenario, exec func(context.Context, protocol.Client, PrivilegedAccess) error) (Result, error)
}
```

**Instructions:** `Run` calls `exec`, then `s.Verify` via the Oracle,
populating `Result` from `Evidence` — fields not applicable to a given
scenario stay `nil`, never a fabricated zero. **This `Result` struct is
the "common result schema" that Milestone 11 is forbidden from
redefining** — see `DEPENDENCY_GRAPH.md` rule 2.

**Tests:**
- `TestRunner_PopulatesResultFromEvidence`
- `TestRunner_InapplicableFieldsStayNil`

**Verification:** standard suite.

**Commit:** `feat: harness Runner and common Result schema`

### Task 33 (H4): Framework tests

**Files:** Create `internal/harness/framework_test.go`

**Dependencies:** H3

**Instructions:** test the framework itself with a trivial stub scenario
(not a real attack) — prerequisite gating, stopping-condition evaluation,
and that `Runner` never reports `success=true` without the Oracle
actually confirming it (i.e., a stub `exec` that claims success via a
side channel the Oracle doesn't see must still report `success=false`).

**Tests:**
- `TestRunner_NeverTrustsExecClaimOverOracle`
- `TestScenario_StopCondHaltsRepeatedAttempts`

**Verification:** standard suite.

**Commit:** `test: attack harness framework guarantees`

---

# Milestone 8 — Attack Implementations

*(Five independent tasks, parallel once Milestone 7 and each one's own
upstream milestone are done — see `DEPENDENCY_GRAPH.md`.)*

### Task 34 (I1): Application-level scenarios

**Files:** Create `internal/harness/scenario_application.go`, `scenario_application_test.go`

**Dependencies:** H3, S1, S3

**Instructions:** register two scenarios: concurrent-overdraft race
(reuses S3's concurrency setup as the `exec` step) and authorization
bypass (reuses S1's cross-account transfer as the `exec` step), both
adjudicated via `Oracle.LedgerSnapshot`/invariant check.

**Tests:**
- `TestScenario_ConcurrentOverdraft_SucceedsVulnerable_FailsHardened`
- `TestScenario_AuthzBypass_SucceedsVulnerable_FailsHardened`

**Verification:** standard suite.

**Commit:** `feat: application-level attack scenarios`

### Task 35 (I2): Protocol-level scenarios

**Files:** Create `internal/harness/scenario_protocol.go`, `scenario_protocol_test.go`

**Dependencies:** H3, S2, C5

**Instructions:** register replay, tamper, and downgrade scenarios,
`exec` via `protocol.Client`, `Verify` via `Oracle.AuditEventsSince`
(checking for the rejection audit event in hardened mode).

**Tests:**
- `TestScenario_Replay_SucceedsVulnerable_FailsHardened`
- `TestScenario_Tamper_SucceedsVulnerable_FailsHardened`
- `TestScenario_Downgrade_SucceedsVulnerable_FailsHardened`

**Verification:** standard suite.

**Commit:** `feat: protocol-level attack scenarios`

### Task 36 (I3): Database/ledger scenarios

**Files:** Create `internal/harness/scenario_ledger.go`, `scenario_ledger_test.go`

**Dependencies:** H3, A1, A4

**Instructions:** register ledger-tampering and audit-tampering
scenarios, `exec` via `PrivilegedAccess.RawLedgerWrite`/`RawAuditWrite`,
`Verify` via `Oracle` checking `CheckInvariant`/`VerifyChain`, with
`DetectionLatencyMS` populated from the Detection Engine's emitted event
timestamp minus the tamper's own timestamp.

**Tests:**
- `TestScenario_LedgerTamper_DetectedHardened_UndetectedVulnerable`
- `TestScenario_AuditTamper_DetectedHardened_UndetectedVulnerable`

**Verification:** standard suite.

**Commit:** `feat: database/ledger attack scenarios`

### Task 37 (I4): Key-management scenarios

**Files:** Create `internal/harness/scenario_keystore.go`, `scenario_keystore_test.go`

**Dependencies:** H3, K1

**Instructions:** register a key-material-exposure scenario, `exec` via
`PrivilegedAccess.RawKeyBytes`, `Verify` asserting the returned bytes
equal known plaintext (vulnerable) vs. do not equal known plaintext
(hardened, since it's still wrapped), populating `DataLeakedBytes`.

**Tests:**
- `TestScenario_KeyExposure_PlaintextVulnerable_CiphertextHardened`

**Verification:** standard suite.

**Commit:** `feat: key-management attack scenario`

### Task 38 (I5): Cryptographic scenarios

**Files:** Create `internal/harness/scenario_crypto.go`, `scenario_crypto_test.go`

**Dependencies:** H3, C2

**Instructions:** register a classical-cryptanalysis scenario against the
weak-educational toy RSA modulus (brute-force factor, then forge a
signature), bounded by `computational_cost` (trial-division count).
`Verify` checks whether a valid forged signature was produced within the
attempt budget. Only meaningful under the weak-educational profile — the
scenario's `Prereqs` checks `CryptoProfile == "weak-educational"` and the
comparison "mode" here is weak-educational vs. standard/pqc crypto
profile, not vulnerable/hardened `SecurityProfile` (document this
distinction in the scenario's own comments, since it's the one M8 task
that forks on a different axis than the others).

**Tests:**
- `TestScenario_ToyRSAFactorAndForge_SucceedsWithinBudget`
- `TestScenario_ToyRSAFactorAndForge_InfeasibleUnderStandardProfile`

**Verification:** standard suite.

**Commit:** `feat: cryptographic attack scenario against weak-educational profile`

---

# Milestone 9 — Quantum-Inspired Simulations

*(Independent of every other milestone except Milestone 1 — see
`DEPENDENCY_GRAPH.md`.)*

### Task 39 (Q1): State-vector circuit primitives

**Files:** Create `internal/quantum/circuit.go`, `circuit_test.go`

**Dependencies:** F3

**Interfaces:**
```go
type Circuit struct { NumQubits int; State []complex128 } // len(State) == 1<<NumQubits
func NewCircuit(numQubits int) (*Circuit, error) // error if numQubits > 20
func (c *Circuit) ApplyH(qubit int)
func (c *Circuit) ApplyX(qubit int)
func (c *Circuit) ApplyCNOT(control, target int)
func (c *Circuit) Measure(qubit int) int // collapses state, returns 0 or 1
var ErrQubitBoundExceeded = apperr.New(apperr.CodeValidation, "qubit bound exceeded")
```

**Instructions:** genuine unitary-matrix state evolution (not a
shortcut) — `ApplyH` etc. operate on the full `2^NumQubits`-length
complex amplitude vector. Bound at `NumQubits <= 20` (2^20 = ~1M complex128
≈ 16MB, acceptable); `NewCircuit` returns `ErrQubitBoundExceeded` above
that, never a silent truncation.
- **No import of `internal/crypto` or any other package** — enforce via
  the same import-graph test pattern as Task F3's `TestNoInternalImports`.

**Tests:**
- `TestNewCircuit_ExceedsBound_ReturnsError`
- `TestApplyH_ProducesEqualSuperposition` — single-qubit H then measure
  many times, assert roughly 50/50 (statistical, bounded tolerance).
- `TestApplyCNOT_EntanglesQubits`
- `TestNoImportsOutsideStdlib`

**Verification:** standard suite.

**Commit:** `feat: bounded state-vector quantum circuit simulator`

### Task 40 (Q2): Shor-inspired factoring demo

**Files:** Create `internal/quantum/shor.go`, `shor_test.go`

**Dependencies:** Q1

**Interfaces:**
```go
func Shor(ctx context.Context, n int) (factors []int, trace CircuitTrace, err error) // n in {15, 21, 35}
```

**Instructions:** genuine period-finding via the circuit primitives
(quantum phase estimation / order-finding subroutine), not a classical
shortcut that just calls a factoring library. Every output carries the
mandatory label from `CRYPTOGRAPHY.md` §5.

**Tests:**
- `TestShor_Factors15` / `TestShor_Factors21` / `TestShor_Factors35`
- `TestShor_OutputCarriesSimulationLabel`

**Verification:** standard suite.

**Commit:** `feat: Shor-inspired factoring via state-vector simulation`

### Task 41 (Q3): Grover-inspired search demo + complexity reporting

**Files:** Create `internal/quantum/grover.go`, `grover_test.go`

**Dependencies:** Q1

**Interfaces:**
```go
func Grover(ctx context.Context, searchSpaceBits int, oracle func(x int) bool) (result int, trace CircuitTrace, err error)
func ComplexityReport(searchSpaceBits int) (classicalExpectedOps, quantumExpectedOps int)
```

**Instructions:** genuine amplitude amplification via the circuit
primitives, bounded to `searchSpaceBits <= 20`. `ComplexityReport` is a
pure theoretical-complexity calculation (O(N) vs O(sqrt(N))) — label its
output explicitly as theoretical, not measured.

**Tests:**
- `TestGrover_FindsMarkedElement`
- `TestComplexityReport_QuadraticSpeedupRatio`

**Verification:** standard suite.

**Commit:** `feat: Grover-inspired search and theoretical complexity report`

---

# Milestone 10 — AI-Agent Experiments

### Task 42 (G1): Observation/Action interfaces

**Files:** Create `internal/agent/types.go`, `types_test.go`

**Dependencies:** H3, at least one of I1-I5 registered

**Interfaces:**
```go
type Observation struct {
    VisibleAccounts []domain.AccountID
    VisibleBalances map[domain.AccountID]domain.Money
    RecentAudit     []audit.Event
    StepsRemaining  int
}
type ActionKind string // one constant per harness-registered scenario's exec step
type Action struct { Kind ActionKind; Target domain.AccountID }
type Policy interface { Decide(obs Observation) (Action, error) }
```

**Instructions:** `ActionKind` values are generated from the harness's
registered scenario IDs (Milestone 8) — the agent cannot select an action
the harness hasn't registered, keeping it bounded per `ARCHITECTURE.md`'s
AI-agent discussion.

**Tests:**
- `TestObservation_OnlyExposesDeclaredVisibility`

**Verification:** standard suite.

**Commit:** `feat: agent Observation/Action interfaces bounded to registered scenarios`

### Task 43 (G2): Deterministic baseline policy

**Files:** Create `internal/agent/policy_deterministic.go`, `policy_deterministic_test.go`

**Dependencies:** G1

**Instructions:** a rule-based (not learning — see
`IMPLEMENTATION_PLAN.md`'s infeasibility note) policy: given an
`Observation`, pick the next unexplored `ActionKind` against the first
`VisibleAccount`, deterministically ordered. "Reactive" means it branches
on `Observation` fields; "adaptive" does not mean it learns across runs.

**Tests:**
- `TestDeterministicPolicy_SameObservation_SameAction`
- `TestDeterministicPolicy_ExhaustsActionsInFixedOrder`

**Verification:** standard suite.

**Commit:** `feat: deterministic rule-based agent policy`

### Task 44 (G3): Agent execution loop

**Files:** Create `internal/agent/agent.go`, `agent_test.go`

**Dependencies:** G2

**Interfaces:**
```go
type Decision struct { Obs Observation; Action Action; Timestamp time.Time }
type Agent struct { Policy Policy; Budget int; DecisionLog []Decision }
func (a *Agent) Run(ctx context.Context, h harness.Runner) ([]harness.Result, error)
```

**Instructions:** loop: build `Observation` from current Oracle state ->
`Policy.Decide` -> execute via `harness.Runner` -> append to
`DecisionLog` -> decrement budget -> stop at zero or when no actions
remain.

**Tests:**
- `TestAgent_StopsAtBudget`
- `TestAgent_DecisionLogRecordsEveryStep`

**Verification:** standard suite.

**Commit:** `feat: agent execution loop with step budget and decision log`

### Task 45 (G4): Agent metrics + reproducibility test

**Files:** Create `internal/agent/reproducibility_test.go`

**Dependencies:** G3

**Instructions:** same seed (fixed via `internal/testsupport.FixedClock`
and a fixed initial ledger fixture) -> same `DecisionLog` action sequence,
asserted field-by-field, two separate `Agent.Run` invocations.

**Tests:**
- `TestAgent_SameSeed_SameActionSequence`

**Verification:** standard suite.

**Commit:** `test: agent reproducibility under fixed seed`

---

# Milestone 11 — Benchmarking

### Task 46 (B1): Comparative run orchestration

**Files:** Create `internal/benchmark/runner.go`, `runner_test.go`

**Dependencies:** H3 (reuses `harness.Result` — no new schema, per
`DEPENDENCY_GRAPH.md` rule 2), at least one M8 scenario

**Interfaces:**
```go
type RawResults []harness.Result
func RunComparative(ctx context.Context, h harness.Runner, s harness.Scenario, reps int, seed int64) (RawResults, error)
```

**Instructions:** per `BENCHMARK_METHODOLOGY.md` §2: re-initialize
storage to the same seeded fixture before each mode's run, repeat `reps`
times per mode, preserve every raw result including failures.

**Tests:**
- `TestRunComparative_PreservesAllRawRuns_IncludingFailures`
- `TestRunComparative_SameSeed_SameInitialState`

**Verification:** standard suite.

**Commit:** `feat: comparative benchmark run orchestration`

### Task 47 (B2): Summary statistics

**Files:** Create `internal/benchmark/summary.go`, `summary_test.go`

**Dependencies:** B1

**Interfaces:**
```go
type Summary struct { ScenarioID, Mode string; Mean, Median, StdDev map[string]float64; SuccessRate float64 }
func Summarize(raw RawResults) []Summary // one per (scenario, mode) pair
```

**Tests:**
- `TestSummarize_ComputesMeanMedianStdDev`
- `TestSummarize_SuccessRate`

**Verification:** standard suite.

**Commit:** `feat: benchmark summary statistics (v1 scope, no outlier rejection)`

### Task 48 (B3): JSON/CSV export

**Files:** Create `internal/benchmark/export.go`, `export_test.go`

**Dependencies:** B2

**Interfaces:**
```go
func ExportJSON(w io.Writer, raw RawResults, summary []Summary) error
func ExportCSV(w io.Writer, raw RawResults, summary []Summary) error
```

**Tests:**
- `TestExportJSON_RoundTrips`
- `TestExportCSV_ParsesBack`

**Verification:** standard suite.

**Commit:** `feat: benchmark JSON/CSV export`

### Task 49 (B4): Reproducibility test

**Files:** Create `internal/benchmark/reproducibility_test.go`

**Dependencies:** B3

**Instructions:** same seed -> identical raw results on every
non-timing field (`ExecutionTimeMS` is expected to vary; everything else
must not).

**Tests:**
- `TestBenchmark_SameSeed_IdenticalNonTimingFields`

**Verification:** standard suite.

**Commit:** `test: benchmark reproducibility under fixed seed`

---

# Milestone 12 — Integration and Validation

*(No new packages — test-writing and whole-project verification only.)*

### Task 50 (V1): End-to-end transaction tests

**Files:** Create `test/e2e_transactions_test.go` (or
`internal/backend/e2e_test.go` if a top-level `test/` package isn't
already established — implementer's call, document which)

**Dependencies:** everything in Milestones 2-3

**Instructions:** a broader version of S4, covering every banking
operation combination (not just the subset S4 exercised), both profiles.

**Tests:** `TestE2E_AllBankingOperations_BothProfiles`

**Verification:** standard suite.

**Commit:** `test: comprehensive end-to-end transaction coverage`

### Task 51 (V2): Aggregated security tests

**Files:** Create `test/security_differential_test.go`

**Dependencies:** Milestone 8 complete

**Instructions:** run every M8 scenario's differential assertion
(vulnerable succeeds / hardened fails) in one suite, as a single
regression gate — not new logic, an aggregation of what each I-task
already tests.

**Tests:** `TestSecurityDifferential_AllRegisteredScenarios`

**Verification:** standard suite.

**Commit:** `test: aggregated vulnerable-vs-hardened differential suite`

### Task 52 (V3): Full-project race detector pass

**Files:** none (verification-only task)

**Dependencies:** everything above

**Instructions:** `go test -race ./...` across the entire module;
investigate and fix (reopening the owning task, not a new one) any
failure.

**Verification:** `go test -race ./...` clean, zero warnings.

**Commit:** (none, unless a fix was needed — then commit against the
original owning task with a message referencing this validation step)

### Task 53 (V4): Benchmark reproducibility + build verification (project-wide)

**Files:** none (verification-only task)

**Dependencies:** V1-V3

**Instructions:** re-run B4's reproducibility test and A3/B3's JSON/CSV
round-trip tests once more at the project's final state (catches any
late regression from unrelated milestones); run the full standard suite
one final time.

**Verification:** the complete Global Constraints suite, clean.

**Commit:** (none unless a fix was needed)

---

# Milestone 13 — Documentation and Publication

### Task 54 (P1): README + technical documentation consolidation

**Files:** Create `README.md`

**Dependencies:** V4

**Instructions:** point to the existing `docs/*.md` files rather than
duplicating them; include quickstart (`go build`, `go run ./cmd/banksec
--version`, a short deposit/balance walkthrough).

**Verification:** `gofmt`/`vet`/`build` unaffected (docs-only change);
manually follow the quickstart once and confirm it works as written.

**Commit:** `docs: README and quickstart`

### Task 55 (P2): Reproducible example walkthrough

**Files:** Create `docs/EXAMPLE_WALKTHROUGH.md`

**Dependencies:** P1

**Instructions:** a fully scripted example: run one comparative benchmark
end-to-end (exact commands, exact expected shape of output), demonstrating
`BENCHMARK_METHODOLOGY.md` in practice.

**Verification:** manually run every command in the walkthrough once and
confirm the output matches what's documented.

**Commit:** `docs: reproducible benchmark walkthrough`

### Task 56 (P3): Git cleanup + GitHub publication (requires separate approval)

**Files:** none code-related

**Dependencies:** P2

**Instructions:** this task's deliverable is **preparation only** —
clean commit history review, a LICENSE file if you want one named, final
`git status` cleanliness check. The actual publication step (creating a
GitHub repository, `git remote add`, `git push`) is explicitly **not**
auto-executed by this plan — per `IMPLEMENTATION_PLAN.md`'s infeasibility
note, it requires your explicit go-ahead, named repository, and visibility
choice (public/private) at the time this task is reached.

**Verification:** `git status` clean, `git log --oneline` reviewed for
anything that shouldn't be public (no accidental secrets, no stray
binaries — `git log -p | grep`-style check for anything matching key
material patterns).

**Commit:** (none — this task ends in a question to you, not a commit)

---

## Self-Review

1. **Spec coverage:** every milestone and every bullet under every
   milestone in your request maps to at least one task above (cross-check
   against the "Milestones at a glance" table in `IMPLEMENTATION_PLAN.md`,
   which lists task-ID ranges per milestone). The four dependency rules
   are each enforced structurally, not just asserted (see
   `DEPENDENCY_GRAPH.md`'s "applied" section). No requirement was silently
   dropped; three needed documented substitutions (GitHub publication,
   PQC library fallback, "adaptive" agent interpretation), all recorded in
   `IMPLEMENTATION_PLAN.md`.
2. **Step scan:** every task names exact file paths, exact signatures, and
   named tests with one-line assertions; no task says "handle edge cases"
   or leaves a type undefined that a later task references.
3. **Type consistency:** `domain.AccountID`/`Money`/`TransactionID`/
   `PrincipalID`/`Role`/`Principal`/`CryptoProfileName`/`DetectionRuleID`
   are used identically from Task F3 through Task I5 and beyond — checked
   by replacing every `ledger.AccountID`-style reference from
   `COMPONENT_INTERFACES.md` with `domain.AccountID` consistently.
4. **Review Focus:** all five items from `TEST_STRATEGY.md` have an owning
   task with an explicit test (S3, H2, C5, K2, A4) — cross-referenced
   above at each task's heading.
5. **Proportion:** 56 tasks across 13 milestones for a system this large
   is proportional to the spec's own scope (seven components, seven
   research categories, benchmarking, two new subsystems); code blocks are
   signatures and short instructions, not full implementations — no task
   carries a complete function body except where an exact toy-construct
   value is spec-mandated (none are).
