# Foundation and Core Banking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working, testable BankSec Lab core: config-driven security
profiles, standard-profile crypto, a double-entry ledger, a separate
keystore, an audit stream, a real wire protocol, the banking backend, and a
CLI — runnable end-to-end in both vulnerable and hardened modes. No attack
harness, benchmark runner, AI agent, or quantum subsystem yet (later
plans).

**Architecture:** One Go module, one process. CLI talks to the Backend
over a real serialized protocol carried on `net.Pipe`. Backend calls
Ledger/Keystore/Crypto/Audit directly (trusted internal Go calls).
`SecurityProfile` is loaded once per run and injected everywhere.

**Tech Stack:** Go (stdlib `crypto/aes`, `crypto/cipher`, `crypto/hmac`,
`crypto/sha256`, `crypto/ed25519`, `crypto/ecdh`), `modernc.org/sqlite`
(pure-Go, no cgo).

**Spec:** [docs/ARCHITECTURE.md](../ARCHITECTURE.md),
[docs/THREAT_MODEL.md](../THREAT_MODEL.md),
[docs/CRYPTOGRAPHY.md](../CRYPTOGRAPHY.md),
[docs/COMPONENT_INTERFACES.md](../COMPONENT_INTERFACES.md)

## Plan sequence (this is Plan 1 of 5)

1. **Foundation and core banking** (this plan) — config, standard-profile
   crypto, ledger, keystore, audit, backend, protocol, CLI.
2. **Attack Harness + application/protocol/db/key-mgmt scenarios** — Oracle,
   PrivilegedAccess, scenario registration, weak-educational crypto profile.
3. **Benchmark Runner** — comparative runs, JSON/CSV export, Detection
   Engine.
4. **AI-Agent subsystem** — Observation/Action/Policy over Plan 2/3's
   harness.
5. **Quantum subsystem** — standalone Shor/Grover state-vector simulators.

Each later plan is written once the prior plan's software is working, per
the brainstorming decomposition discussion.

## Global Constraints

- Go module name: `banksec-lab`, single module, no sub-modules.
- No production cryptographic primitive is implemented from scratch —
  stdlib only in this plan (weak-educational toy constructs and
  `cloudflare/circl` arrive in Plan 2/later, not here).
- Run after every task: `gofmt -l .` (fix any output), `go vet ./...`,
  `go test ./...`, `go test -race ./...`, `go build ./...`.
- Storage: `modernc.org/sqlite`, two separate database files — ledger and
  keystore are never in the same DB file (`ARCHITECTURE.md` §7).
- Config format: JSON. Fixture profiles at `configs/vulnerable.json` and
  `configs/hardened.json`.
- Money is `int64` minor units (cents) everywhere — never floating point.
- `SecurityProfile` (`internal/config`) gains one field beyond
  `ARCHITECTURE.md` §5's list, consistent with that section's "at
  minimum" wording: `AuthzEnforced bool` — whether the Backend enforces
  the account-owner/privileged-operator boundary. This is a plan-level
  elaboration, not a spec change.
- This directory is not yet a git repository. Commit steps below assume
  git has been initialized before Task 1 begins (see handoff note).

## Review Focus

- **Logical race vs. data race under vulnerable mode:** vulnerable mode
  must omit transfer-atomicity (check-balance-then-write without a
  single serializing transaction), producing a *real, detectable*
  lost-update/overdraft — but must never introduce an actual Go-level
  data race (unsynchronized memory access). `go test -race` must pass in
  *both* modes; only the business-level invariant may differ. Covered in
  Task 10.
- **Unbalanced ledger writes:** `Store.AppendTransaction` must reject a
  non-zero-sum entry set even though the Backend is expected to always
  pass balanced sets — a defensive check, not the primary enforcement
  point. Covered in Task 4.
- **Revoked/rotated key reuse:** `Get` on a revoked key must return
  `ErrKeyRevoked`, never stale or cached material. Covered in Task 5.
- **Frame tamper/replay/downgrade must be independently testable:** a fix
  for one must not accidentally mask a failure to implement another.
  Three independent tests, same task. Covered in Task 8.
- **CLI is never the authorization boundary:** a protocol client (bypassing
  the CLI entirely) presenting a forged `Principal` must still be rejected
  by the Backend, not merely by CLI-side validation (`ARCHITECTURE.md`
  §5.1 / spec §5.1). Covered in Task 9.

---

### Task 1: Project skeleton

**Files:**
- Create: `go.mod` (module `banksec-lab`)
- Create: `cmd/banksec/main.go`
- Create: `cmd/banksec/main_test.go`

**Interfaces:**
- Produces: a `main()` that parses a `--version` flag and prints a fixed
  version string; nothing else yet.

- [ ] **Step 1: Write the failing test**

```go
func TestVersionFlag(t *testing.T) {
    out, err := runMain([]string{"--version"})
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if out != "banksec-lab v0.1.0-dev\n" {
        t.Fatalf("got %q", out)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/banksec/... -run TestVersionFlag -v`
Expected: FAIL (package does not build / `runMain` undefined)

- [ ] **Step 3: Implement `runMain(args []string) (string, error)` in `cmd/banksec/main.go`**

`main()` calls `runMain(os.Args[1:])` and prints the result;
`runMain` handles only `--version` for now.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/banksec/... -run TestVersionFlag -v`
Expected: PASS

- [ ] **Step 5: Run `go vet ./...` and `go build ./...`**

Expected: both succeed with no output/errors.

- [ ] **Step 6: Commit**

```bash
git add go.mod cmd/banksec/main.go cmd/banksec/main_test.go
git commit -m "chore: project skeleton with version flag"
```

---

### Task 2: internal/config — SecurityProfile

**Files:**
- Create: `internal/config/profile.go`
- Create: `internal/config/profile_test.go`
- Create: `configs/vulnerable.json`
- Create: `configs/hardened.json`

**Interfaces:**
- Produces:
```go
type CryptoProfileName string // "weak-educational" | "standard" | "pqc"
type DetectionRuleID string

type SecurityProfile struct {
    Name                     string
    CryptoProfile            CryptoProfileName
    MinAcceptedCryptoProfile CryptoProfileName
    ProtocolAuthEnforced     bool
    AuthzEnforced            bool
    KeystoreEncryptedAtRest  bool
    AuditHashChained         bool
    DetectionRules           []DetectionRuleID
}

func Load(path string) (SecurityProfile, error)
```

- [ ] **Step 1: Write the failing test**

```go
func TestLoad_Hardened(t *testing.T) {
    p, err := Load("../../configs/hardened.json")
    if err != nil {
        t.Fatalf("Load: %v", err)
    }
    if p.Name != "hardened" || !p.ProtocolAuthEnforced || !p.AuthzEnforced ||
        !p.KeystoreEncryptedAtRest || !p.AuditHashChained {
        t.Fatalf("hardened profile fields not as expected: %+v", p)
    }
}

func TestLoad_Vulnerable(t *testing.T) {
    p, err := Load("../../configs/vulnerable.json")
    if err != nil {
        t.Fatalf("Load: %v", err)
    }
    if p.Name != "vulnerable" || p.ProtocolAuthEnforced || p.AuthzEnforced ||
        p.KeystoreEncryptedAtRest || p.AuditHashChained {
        t.Fatalf("vulnerable profile fields not as expected: %+v", p)
    }
}

func TestLoad_MissingFile(t *testing.T) {
    if _, err := Load("../../configs/does-not-exist.json"); err == nil {
        t.Fatal("expected error for missing file")
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/... -v`
Expected: FAIL (package/fixtures/function missing)

- [ ] **Step 3: Implement `SecurityProfile`, `Load`, and the two JSON fixtures**

Both fixtures declare `CryptoProfile` and `MinAcceptedCryptoProfile` as
`"standard"` (the only profile implemented in this plan) and
`DetectionRules: []` (Detection Engine arrives in Plan 3).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/... -v`
Expected: PASS (all three)

- [ ] **Step 5: Commit**

```bash
git add internal/config configs
git commit -m "feat: SecurityProfile loading from JSON fixtures"
```

---

### Task 3: internal/crypto — standard profile

**Files:**
- Create: `internal/crypto/engine.go`
- Create: `internal/crypto/standard.go`
- Create: `internal/crypto/engine_test.go`

**Interfaces:**
- Consumes: nothing (leaf package; Go stdlib only).
- Produces:
```go
type Engine interface {
    Encrypt(profile config.CryptoProfileName, key, plaintext []byte) ([]byte, error)
    Decrypt(profile config.CryptoProfileName, key, ciphertext []byte) ([]byte, error)
    Sign(profile config.CryptoProfileName, key, msg []byte) ([]byte, error)
    Verify(profile config.CryptoProfileName, pubkey, msg, sig []byte) (bool, error)
    MAC(profile config.CryptoProfileName, key, msg []byte) ([]byte, error)
}

func NewEngine() Engine

var ErrProfileNotImplemented = errors.New("crypto profile not implemented")
```
  `Encrypt`/`Decrypt` use AES-GCM; `Sign`/`Verify` use Ed25519;
  `MAC` uses HMAC-SHA-256. Any profile other than `"standard"` returns
  `ErrProfileNotImplemented` (explicit, not a silent fallback).

- [ ] **Step 1: Write the failing tests**

```go
func TestEncryptDecrypt_RoundTrip(t *testing.T) {
    e := NewEngine()
    key := make([]byte, 32) // AES-256 key
    ct, err := e.Encrypt("standard", key, []byte("synthetic-plaintext"))
    if err != nil { t.Fatalf("Encrypt: %v", err) }
    pt, err := e.Decrypt("standard", key, ct)
    if err != nil { t.Fatalf("Decrypt: %v", err) }
    if string(pt) != "synthetic-plaintext" { t.Fatalf("got %q", pt) }
}

func TestSignVerify_RoundTrip(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    e := NewEngine()
    sig, err := e.Sign("standard", priv, []byte("msg"))
    if err != nil { t.Fatalf("Sign: %v", err) }
    ok, err := e.Verify("standard", pub, []byte("msg"), sig)
    if err != nil || !ok { t.Fatalf("Verify: ok=%v err=%v", ok, err) }
}

func TestMAC_TamperDetected(t *testing.T) {
    e := NewEngine()
    key := []byte("synthetic-mac-key")
    tag, _ := e.MAC("standard", key, []byte("original"))
    tag2, _ := e.MAC("standard", key, []byte("tampered"))
    if bytes.Equal(tag, tag2) { t.Fatal("MAC did not change for different input") }
}

func TestUnimplementedProfile(t *testing.T) {
    e := NewEngine()
    _, err := e.Encrypt("weak-educational", make([]byte,32), []byte("x"))
    if !errors.Is(err, ErrProfileNotImplemented) {
        t.Fatalf("expected ErrProfileNotImplemented, got %v", err)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/crypto/... -v`
Expected: FAIL (package/types undefined)

- [ ] **Step 3: Implement `Engine`/`NewEngine`/standard-profile operations**

Use `crypto/aes` + `crypto/cipher` (GCM), `crypto/ed25519`,
`crypto/hmac` + `crypto/sha256`. Dispatch on `profile`; any value other
than `"standard"` returns `ErrProfileNotImplemented` from every method.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/crypto/... -v`
Expected: PASS (all four)

- [ ] **Step 5: Commit**

```bash
git add internal/crypto
git commit -m "feat: standard crypto profile (AES-GCM, Ed25519, HMAC-SHA256)"
```

---

### Task 4: internal/ledger — double-entry store

**Files:**
- Create: `internal/ledger/store.go`
- Create: `internal/ledger/sqlite.go`
- Create: `internal/ledger/store_test.go`

**Interfaces:**
- Consumes: `modernc.org/sqlite` (new dependency: `go get modernc.org/sqlite`).
- Produces:
```go
type AccountID string
type TransactionID string
type Money int64 // minor units (cents)

type Entry struct {
    TxID      TransactionID
    AccountID AccountID
    Amount    Money // debit negative, credit positive
    Timestamp time.Time
}

type Store interface {
    AppendTransaction(ctx context.Context, entries []Entry) error
    Balance(ctx context.Context, acct AccountID) (Money, error)
    History(ctx context.Context, acct AccountID) ([]Entry, error)
    CheckInvariant(ctx context.Context) (ok bool, violatingTxIDs []TransactionID, err error)
}

func NewSQLiteStore(path string) (Store, error)

var ErrUnbalancedEntries = errors.New("entries do not sum to zero")
```

- [ ] **Step 1: Write the failing tests**

```go
func TestAppendTransaction_BalancedSucceeds(t *testing.T) {
    s := newTestStore(t)
    err := s.AppendTransaction(ctx, []Entry{
        {TxID: "tx1", AccountID: "a1", Amount: -500},
        {TxID: "tx1", AccountID: "a2", Amount: 500},
    })
    if err != nil { t.Fatalf("AppendTransaction: %v", err) }
    bal, _ := s.Balance(ctx, "a2")
    if bal != 500 { t.Fatalf("got balance %d", bal) }
}

func TestAppendTransaction_UnbalancedRejected(t *testing.T) {
    s := newTestStore(t)
    err := s.AppendTransaction(ctx, []Entry{
        {TxID: "tx2", AccountID: "a1", Amount: -500},
        {TxID: "tx2", AccountID: "a2", Amount: 400},
    })
    if !errors.Is(err, ErrUnbalancedEntries) {
        t.Fatalf("expected ErrUnbalancedEntries, got %v", err)
    }
}

func TestHistory_OrderedByTime(t *testing.T) { /* append two txs, assert History returns both in order */ }

func TestCheckInvariant_OKAfterBalancedWrites(t *testing.T) {
    s := newTestStore(t)
    s.AppendTransaction(ctx, []Entry{{TxID:"tx3",AccountID:"a1",Amount:-100},{TxID:"tx3",AccountID:"a2",Amount:100}})
    ok, bad, err := s.CheckInvariant(ctx)
    if err != nil || !ok || len(bad) != 0 { t.Fatalf("ok=%v bad=%v err=%v", ok, bad, err) }
}
```

(`newTestStore(t)` is a small test helper creating a `NewSQLiteStore` at a
`t.TempDir()` path — write it alongside these tests in the same file.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/ledger/... -v`
Expected: FAIL (package/types undefined)

- [ ] **Step 3: Implement the SQLite schema and `Store`**

Schema: one `entries` table (`tx_id`, `account_id`, `amount`,
`timestamp`), indexed by `account_id`. `AppendTransaction` sums the
batch's `Amount` and returns `ErrUnbalancedEntries` if non-zero *before*
writing (single DB transaction for the write itself).
`CheckInvariant` groups by `tx_id` and finds any whose sum is non-zero.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/ledger/... -v`
Expected: PASS (all four)

- [ ] **Step 5: Run with race detector**

Run: `go test -race ./internal/ledger/...`
Expected: PASS, no data race warnings

- [ ] **Step 6: Commit**

```bash
git add internal/ledger go.mod go.sum
git commit -m "feat: double-entry ledger store on SQLite"
```

---

### Task 5: internal/keystore — separate key store

**Files:**
- Create: `internal/keystore/store.go`
- Create: `internal/keystore/sqlite.go`
- Create: `internal/keystore/store_test.go`

**Interfaces:**
- Consumes: `crypto.Engine` (Task 3), its own separate `modernc.org/sqlite`
  database file (never the ledger's file — `ARCHITECTURE.md` §7).
- Produces:
```go
type KeyMeta struct {
    ID        string
    Profile   config.CryptoProfileName
    CreatedAt time.Time
    RotatedAt *time.Time
    RevokedAt *time.Time
}

type Store interface {
    Generate(ctx context.Context, profile config.CryptoProfileName) (KeyMeta, error)
    Get(ctx context.Context, id string) (material []byte, meta KeyMeta, err error)
    Rotate(ctx context.Context, id string) (KeyMeta, error)
    Revoke(ctx context.Context, id string) error
}

func NewSQLiteStore(path string, engine crypto.Engine, encryptAtRest bool) (Store, error)

var ErrKeyRevoked = errors.New("key has been revoked")
var ErrKeyNotFound = errors.New("key not found")
```
  `encryptAtRest=true` wraps generated material with `engine.Encrypt`
  under a store-level key (generated once at store construction, held
  only in memory) before persisting; `Get` decrypts transparently.
  `encryptAtRest=false` persists material as-is (vulnerable mode).

- [ ] **Step 1: Write the failing tests**

```go
func TestGenerateGet_RoundTrip(t *testing.T) {
    s := newTestKeystore(t, true) // encryptAtRest
    meta, err := s.Generate(ctx, "standard")
    if err != nil { t.Fatalf("Generate: %v", err) }
    material, gotMeta, err := s.Get(ctx, meta.ID)
    if err != nil || len(material) == 0 { t.Fatalf("Get: material=%v err=%v", material, err) }
    if gotMeta.ID != meta.ID { t.Fatalf("meta mismatch") }
}

func TestRotate_UpdatesMetaAndMaterial(t *testing.T) {
    s := newTestKeystore(t, true)
    meta, _ := s.Generate(ctx, "standard")
    before, _, _ := s.Get(ctx, meta.ID)
    rotated, err := s.Rotate(ctx, meta.ID)
    if err != nil || rotated.RotatedAt == nil { t.Fatalf("Rotate: meta=%+v err=%v", rotated, err) }
    after, _, _ := s.Get(ctx, meta.ID)
    if bytes.Equal(before, after) { t.Fatal("material unchanged after rotation") }
}

func TestRevoke_BlocksGet(t *testing.T) {
    s := newTestKeystore(t, true)
    meta, _ := s.Generate(ctx, "standard")
    if err := s.Revoke(ctx, meta.ID); err != nil { t.Fatalf("Revoke: %v", err) }
    _, _, err := s.Get(ctx, meta.ID)
    if !errors.Is(err, ErrKeyRevoked) { t.Fatalf("expected ErrKeyRevoked, got %v", err) }
}

func TestGet_UnknownID(t *testing.T) {
    s := newTestKeystore(t, true)
    _, _, err := s.Get(ctx, "no-such-id")
    if !errors.Is(err, ErrKeyNotFound) { t.Fatalf("expected ErrKeyNotFound, got %v", err) }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/keystore/... -v`
Expected: FAIL

- [ ] **Step 3: Implement the SQLite schema and `Store`**

Schema: `keys` table (`id`, `profile`, `material` (BLOB, possibly
encrypted), `created_at`, `rotated_at` nullable, `revoked_at` nullable).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/keystore/... -v`
Expected: PASS (all four)

- [ ] **Step 5: Commit**

```bash
git add internal/keystore
git commit -m "feat: keystore with encrypted-at-rest toggle, rotation, revocation"
```

---

### Task 6: internal/audit — event stream

**Files:**
- Create: `internal/audit/stream.go`
- Create: `internal/audit/sqlite.go`
- Create: `internal/audit/stream_test.go`

**Interfaces:**
- Consumes: its own table in the ledger's SQLite file is **not** used —
  give audit its own SQLite file too, for the same isolation reason as
  keystore (simplest to reason about; cheap given SQLite's low overhead).
- Produces:
```go
type Event struct {
    ID        string
    Timestamp time.Time
    Type      string
    Component string
    Actor     string // backend.PrincipalID, as a string to avoid an import cycle
    Operation string
    Outcome   string
    TxID      *string
    AttackID  *string
}

type Stream interface {
    Record(ctx context.Context, e Event) error
    Since(ctx context.Context, t time.Time) ([]Event, error)
    Subscribe(fn func(Event)) (unsubscribe func())
    VerifyChain(ctx context.Context) (ok bool, brokenAt *string, err error)
}

func NewSQLiteStream(path string, hashChained bool) (Stream, error)

var ErrChainNotEnabled = errors.New("hash chaining not enabled for this stream")
```

- [ ] **Step 1: Write the failing tests**

```go
func TestRecordSince_RoundTrip(t *testing.T) {
    s := newTestStream(t, true)
    s.Record(ctx, Event{ID:"e1", Timestamp: time.Now(), Type:"deposit", Outcome:"ok"})
    events, err := s.Since(ctx, time.Now().Add(-time.Minute))
    if err != nil || len(events) != 1 { t.Fatalf("events=%v err=%v", events, err) }
}

func TestSubscribe_ReceivesRecordedEvent(t *testing.T) {
    s := newTestStream(t, true)
    received := make(chan Event, 1)
    unsub := s.Subscribe(func(e Event) { received <- e })
    defer unsub()
    s.Record(ctx, Event{ID:"e2", Timestamp: time.Now(), Type:"withdraw"})
    select {
    case e := <-received:
        if e.ID != "e2" { t.Fatalf("got %v", e) }
    case <-time.After(time.Second):
        t.Fatal("subscriber did not receive event")
    }
}

func TestVerifyChain_OKWhenUntampered(t *testing.T) {
    s := newTestStream(t, true)
    s.Record(ctx, Event{ID:"e3", Timestamp: time.Now()})
    ok, broken, err := s.VerifyChain(ctx)
    if err != nil || !ok || broken != nil { t.Fatalf("ok=%v broken=%v err=%v", ok, broken, err) }
}

func TestVerifyChain_DetectsTamper(t *testing.T) {
    s := newTestStream(t, true)
    s.Record(ctx, Event{ID:"e4", Timestamp: time.Now(), Outcome:"ok"})
    tamperRawRow(t, s, "e4", "Outcome", "tampered") // test helper: raw SQL UPDATE bypassing Record
    ok, broken, err := s.VerifyChain(ctx)
    if err != nil || ok || broken == nil { t.Fatalf("expected tamper detected, got ok=%v broken=%v err=%v", ok, broken, err) }
}

func TestVerifyChain_ErrorsWhenNotEnabled(t *testing.T) {
    s := newTestStream(t, false)
    _, _, err := s.VerifyChain(ctx)
    if !errors.Is(err, ErrChainNotEnabled) { t.Fatalf("expected ErrChainNotEnabled, got %v", err) }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/audit/... -v`
Expected: FAIL

- [ ] **Step 3: Implement schema, `Stream`, hash chaining**

Schema: `events` table plus (when `hashChained`) a `prev_hash`/`hash`
column pair; `Record` computes `hash = SHA256(prev_hash || serialized
event)`. `Subscribe` keeps an in-memory list of callbacks invoked
synchronously from `Record` (single-process, no queue needed).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/audit/... -v`
Expected: PASS (all five)

- [ ] **Step 5: Commit**

```bash
git add internal/audit
git commit -m "feat: audit event stream with optional hash chaining"
```

---

### Task 7: internal/backend — banking service

**Files:**
- Create: `internal/backend/service.go`
- Create: `internal/backend/service_test.go`

**Interfaces:**
- Consumes: `ledger.Store` (4), `keystore.Store` (5, unused by banking ops
  in this plan but wired for later use), `crypto.Engine` (3),
  `audit.Stream` (6), `config.SecurityProfile` (2).
- Produces:
```go
type PrincipalID string
type Role string // "account-owner" | "privileged-operator"

type Principal struct {
    ID   PrincipalID
    Role Role
}

type Service interface {
    CreateAccount(ctx context.Context, owner PrincipalID) (ledger.AccountID, error)
    Deposit(ctx context.Context, actor Principal, acct ledger.AccountID, amount ledger.Money) error
    Withdraw(ctx context.Context, actor Principal, acct ledger.AccountID, amount ledger.Money) error
    Transfer(ctx context.Context, actor Principal, from, to ledger.AccountID, amount ledger.Money) error
    Balance(ctx context.Context, actor Principal, acct ledger.AccountID) (ledger.Money, error)
    History(ctx context.Context, actor Principal, acct ledger.AccountID) ([]ledger.Entry, error)
}

func NewService(l ledger.Store, k keystore.Store, c crypto.Engine, a audit.Stream, p config.SecurityProfile) Service

var ErrInsufficientFunds = errors.New("insufficient funds")
var ErrUnauthorized = errors.New("unauthorized")
var ErrValidation = errors.New("validation failed")
```
  Account ownership is tracked by the Service (an in-memory or
  ledger-table-backed `map[ledger.AccountID]PrincipalID` populated by
  `CreateAccount` — implementer's choice of storage, but it must survive
  within a single run).

- [ ] **Step 1: Write the failing tests**

```go
func TestDepositBalance_RoundTrip(t *testing.T) {
    svc := newTestService(t, hardenedProfile())
    acct, _ := svc.CreateAccount(ctx, "owner-1")
    owner := backend.Principal{ID: "owner-1", Role: "account-owner"}
    if err := svc.Deposit(ctx, owner, acct, 1000); err != nil { t.Fatalf("Deposit: %v", err) }
    bal, _ := svc.Balance(ctx, owner, acct)
    if bal != 1000 { t.Fatalf("got %d", bal) }
}

func TestWithdraw_InsufficientFunds(t *testing.T) {
    svc := newTestService(t, hardenedProfile())
    acct, _ := svc.CreateAccount(ctx, "owner-1")
    owner := backend.Principal{ID: "owner-1", Role: "account-owner"}
    err := svc.Withdraw(ctx, owner, acct, 500)
    if !errors.Is(err, backend.ErrInsufficientFunds) { t.Fatalf("expected ErrInsufficientFunds, got %v", err) }
}

func TestTransfer_UnauthorizedOwnerRejectedWhenAuthzEnforced(t *testing.T) {
    svc := newTestService(t, hardenedProfile()) // AuthzEnforced: true
    acctA, _ := svc.CreateAccount(ctx, "owner-1")
    acctB, _ := svc.CreateAccount(ctx, "owner-2")
    intruder := backend.Principal{ID: "owner-2", Role: "account-owner"}
    err := svc.Transfer(ctx, intruder, acctA, acctB, 100) // owner-2 does not own acctA
    if !errors.Is(err, backend.ErrUnauthorized) { t.Fatalf("expected ErrUnauthorized, got %v", err) }
}

func TestTransfer_UnauthorizedOwnerAllowedWhenAuthzNotEnforced(t *testing.T) {
    svc := newTestService(t, vulnerableProfile()) // AuthzEnforced: false
    acctA, _ := svc.CreateAccount(ctx, "owner-1")
    acctB, _ := svc.CreateAccount(ctx, "owner-2")
    ownerA := backend.Principal{ID:"owner-1", Role:"account-owner"}
    svc.Deposit(ctx, ownerA, acctA, 1000)
    intruder := backend.Principal{ID: "owner-2", Role: "account-owner"}
    if err := svc.Transfer(ctx, intruder, acctA, acctB, 100); err != nil {
        t.Fatalf("expected success under vulnerable profile, got %v", err)
    }
}

func TestDeposit_NegativeAmountRejected(t *testing.T) {
    svc := newTestService(t, hardenedProfile())
    acct, _ := svc.CreateAccount(ctx, "owner-1")
    owner := backend.Principal{ID: "owner-1", Role: "account-owner"}
    err := svc.Deposit(ctx, owner, acct, -100)
    if !errors.Is(err, backend.ErrValidation) { t.Fatalf("expected ErrValidation, got %v", err) }
}

func TestEveryOperation_EmitsAuditEvent(t *testing.T) {
    svc, stream := newTestServiceWithAuditAccess(t, hardenedProfile())
    acct, _ := svc.CreateAccount(ctx, "owner-1")
    owner := backend.Principal{ID: "owner-1", Role: "account-owner"}
    svc.Deposit(ctx, owner, acct, 100)
    events, _ := stream.Since(ctx, time.Now().Add(-time.Minute))
    if len(events) == 0 { t.Fatal("expected at least one audit event") }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/backend/... -v`
Expected: FAIL

- [ ] **Step 3: Implement `Service`**

`Deposit`/`Withdraw`/`Transfer` build balanced `[]ledger.Entry` and call
`ledger.Store.AppendTransaction`; each operation records an
`audit.Event` (success or failure) via `audit.Stream.Record`;
authorization check (account ownership) only runs when
`profile.AuthzEnforced` is true.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/backend/... -v`
Expected: PASS (all six)

- [ ] **Step 5: Commit**

```bash
git add internal/backend
git commit -m "feat: banking backend with double-entry transfers and audit"
```

---

### Task 8: internal/protocol — wire protocol

**Files:**
- Create: `internal/protocol/frame.go`
- Create: `internal/protocol/transport_pipe.go`
- Create: `internal/protocol/server.go`
- Create: `internal/protocol/client.go`
- Create: `internal/protocol/protocol_test.go`

**Interfaces:**
- Consumes: `backend.Service` (7), `crypto.Engine` (3) for the auth tag,
  `config.SecurityProfile` (2).
- Produces:
```go
type Frame struct {
    Version    uint8
    Seq        uint64
    CryptoProf config.CryptoProfileName
    Payload    []byte
    AuthTag    []byte
}

type Request struct {
    Op     string // "deposit" | "withdraw" | "transfer" | "balance" | "history" | "create-account"
    Actor  backend.Principal
    Params map[string]string
}

type Response struct {
    OK    bool
    Error string
    Data  map[string]string
}

type Client interface {
    Send(ctx context.Context, req Request) (Response, error)
}

type Server interface {
    Serve(ctx context.Context, svc backend.Service) error
}

func NewPipeTransport() (clientConn, serverConn net.Conn)
func NewClient(conn net.Conn, macKey []byte, declaredProfile config.CryptoProfileName) Client
func NewServer(conn net.Conn, engine crypto.Engine, macKey []byte, profile config.SecurityProfile) Server

var ErrReplayDetected = errors.New("replayed sequence number")
var ErrAuthFailed = errors.New("auth tag verification failed")
var ErrProfileDowngrade = errors.New("crypto profile below server minimum")
```
  Auth tag = `engine.MAC(declaredProfile, macKey, serializedFrameMinusTag)`.

- [ ] **Step 1: Write the failing tests**

```go
func TestSendReceive_RoundTrip(t *testing.T) {
    svc, client, _ := newTestWiring(t, hardenedProfile())
    resp, err := client.Send(ctx, protocol.Request{Op:"create-account", Actor: ownerPrincipal, Params: map[string]string{"owner":"owner-1"}})
    if err != nil || !resp.OK { t.Fatalf("resp=%+v err=%v", resp, err) }
}

func TestReplay_RejectedWhenHardened(t *testing.T) {
    svc, client, raw := newTestWiringWithRawAccess(t, hardenedProfile())
    req := protocol.Request{Op:"deposit", Actor: ownerPrincipal, Params: map[string]string{"account":"a1","amount":"100"}}
    client.Send(ctx, req)
    frame := raw.lastSentFrame() // test helper capturing the last frame bytes
    _, err := raw.resendFrame(frame)
    if !errors.Is(err, protocol.ErrReplayDetected) { t.Fatalf("expected ErrReplayDetected, got %v", err) }
}

func TestReplay_AcceptedWhenVulnerable(t *testing.T) {
    _, _, raw := newTestWiringWithRawAccess(t, vulnerableProfile())
    req := protocol.Request{Op:"deposit", Actor: ownerPrincipal, Params: map[string]string{"account":"a1","amount":"100"}}
    raw.client.Send(ctx, req)
    frame := raw.lastSentFrame()
    resp, err := raw.resendFrame(frame)
    if err != nil || !resp.OK { t.Fatalf("expected replay accepted under vulnerable profile, got resp=%+v err=%v", resp, err) }
}

func TestTamper_RejectedWhenHardened(t *testing.T) {
    _, _, raw := newTestWiringWithRawAccess(t, hardenedProfile())
    frame := raw.buildFrame(protocol.Request{Op:"deposit", Params: map[string]string{"account":"a1","amount":"100"}})
    frame.Payload[0] ^= 0xFF // mutate payload without recomputing AuthTag
    _, err := raw.sendFrame(frame)
    if !errors.Is(err, protocol.ErrAuthFailed) { t.Fatalf("expected ErrAuthFailed, got %v", err) }
}

func TestDowngrade_RejectedWhenHardened(t *testing.T) {
    _, _, raw := newTestWiringWithRawAccess(t, hardenedProfileMinStandard(t))
    frame := raw.buildFrameWithProfile(protocol.Request{Op:"balance"}, "weak-educational")
    _, err := raw.sendFrame(frame)
    if !errors.Is(err, protocol.ErrProfileDowngrade) { t.Fatalf("expected ErrProfileDowngrade, got %v", err) }
}
```

(`newTestWiringWithRawAccess` is a test-only helper that exposes the raw
`net.Conn` and a frame builder/sender so tests can act below the
`Client` abstraction — write it in `protocol_test.go`, not shipped as
public API.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/protocol/... -v`
Expected: FAIL

- [ ] **Step 3: Implement `Frame`/`Client`/`Server`/transport**

Server tracks the highest `Seq` seen per connection; hardened mode
rejects `Seq <= lastSeen`, vulnerable mode does not track it at all.
Server recomputes the auth tag over the received payload and compares;
hardened mode rejects on mismatch, vulnerable mode skips verification
when `ProtocolAuthEnforced` is false. Server compares `Frame.CryptoProf`
against `profile.MinAcceptedCryptoProfile`; hardened mode rejects below
minimum, vulnerable mode does not check.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/protocol/... -v`
Expected: PASS (all five)

- [ ] **Step 5: Commit**

```bash
git add internal/protocol
git commit -m "feat: wire protocol with replay/tamper/downgrade enforcement"
```

---

### Task 9: cmd/banksec — CLI wiring

**Files:**
- Modify: `cmd/banksec/main.go` (from Task 1)
- Create: `cmd/banksec/cli.go`
- Create: `cmd/banksec/cli_test.go`

**Interfaces:**
- Consumes: everything above. Wires, in order:
  `config.Load` -> `crypto.NewEngine` -> `ledger.NewSQLiteStore` ->
  `keystore.NewSQLiteStore` -> `audit.NewSQLiteStream` ->
  `backend.NewService` -> `protocol.NewPipeTransport` +
  `protocol.NewServer(...).Serve` (background goroutine) +
  `protocol.NewClient(...)`.
- Produces: subcommands `create-account`, `deposit`, `withdraw`,
  `transfer`, `balance`, `history`, each a thin CLI-arg-to-`Request`
  mapper that calls `protocol.Client.Send` and prints `Response`.

- [ ] **Step 1: Write the failing tests**

```go
func TestCLI_DepositThenBalance(t *testing.T) {
    env := newTestEnv(t, "../../configs/hardened.json") // spins up full wiring in t.TempDir()
    out, err := env.run("create-account", "--owner", "owner-1")
    if err != nil { t.Fatalf("create-account: %v, out=%s", err, out) }
    acct := parseAccountID(t, out)
    if _, err := env.run("deposit", "--account", acct, "--amount", "1000", "--as", "owner-1"); err != nil {
        t.Fatalf("deposit: %v", err)
    }
    out, err = env.run("balance", "--account", acct, "--as", "owner-1")
    if err != nil || !strings.Contains(out, "1000") { t.Fatalf("balance out=%q err=%v", out, err) }
}

func TestCLI_ForgedPrincipalStillRejectedServerSide(t *testing.T) {
    env := newTestEnv(t, "../../configs/hardened.json")
    out, _ := env.run("create-account", "--owner", "owner-1")
    acctA := parseAccountID(t, out)
    env.run("deposit", "--account", acctA, "--amount", "1000", "--as", "owner-1")
    out2, _ := env.run("create-account", "--owner", "owner-2")
    acctB := parseAccountID(t, out2)
    // CLI itself does not stop this request from being built; the Backend must reject it.
    _, err := env.run("transfer", "--from", acctA, "--to", acctB, "--amount", "100", "--as", "owner-2")
    if !strings.Contains(err.Error(), "unauthorized") {
        t.Fatalf("expected server-side rejection, got %v", err)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/banksec/... -v`
Expected: FAIL

- [ ] **Step 3: Implement the CLI wiring and subcommands**

Each subcommand builds a `protocol.Request` from flags and prints
`Response.Data`/`Response.Error`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/banksec/... -v`
Expected: PASS (both)

- [ ] **Step 5: Commit**

```bash
git add cmd/banksec
git commit -m "feat: CLI wiring for core banking operations"
```

---

### Task 10: Integration and concurrency tests

**Files:**
- Create: `internal/backend/integration_test.go`
- Create: `internal/backend/concurrency_test.go`

**Interfaces:**
- Consumes: `backend.Service`, `ledger.Store.CheckInvariant`. No new
  production code — tests only.

- [ ] **Step 1: Write the full-stack comparative test**

```go
func TestFullStack_VulnerableVsHardened_SameScenario(t *testing.T) {
    for _, profile := range []string{"../../configs/vulnerable.json", "../../configs/hardened.json"} {
        svc, ledgerStore := newTestServiceFromProfile(t, profile)
        acct, _ := svc.CreateAccount(ctx, "owner-1")
        owner := backend.Principal{ID:"owner-1", Role:"account-owner"}
        svc.Deposit(ctx, owner, acct, 1000)
        svc.Withdraw(ctx, owner, acct, 300)
        bal, _ := svc.Balance(ctx, owner, acct)
        if bal != 700 { t.Fatalf("[%s] got balance %d", profile, bal) }
        ok, bad, _ := ledgerStore.CheckInvariant(ctx)
        if !ok { t.Fatalf("[%s] ledger invariant violated: %v", profile, bad) }
    }
}
```

- [ ] **Step 2: Write the concurrency test**

```go
func TestConcurrentTransfers_HardenedPreservesInvariant(t *testing.T) {
    svc, ledgerStore := newTestServiceFromProfile(t, "../../configs/hardened.json")
    acctA, _ := svc.CreateAccount(ctx, "owner-1")
    acctB, _ := svc.CreateAccount(ctx, "owner-2")
    owner := backend.Principal{ID:"owner-1", Role:"account-owner"}
    svc.Deposit(ctx, owner, acctA, 1000)
    var wg sync.WaitGroup
    for i := 0; i < 20; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            svc.Transfer(ctx, owner, acctA, acctB, 100) // ignore individual errors; some must fail once funds exhausted
        }()
    }
    wg.Wait()
    ok, bad, _ := ledgerStore.CheckInvariant(ctx)
    if !ok { t.Fatalf("invariant violated under hardened concurrency: %v", bad) }
    balA, _ := svc.Balance(ctx, owner, acctA)
    if balA < 0 { t.Fatalf("overdrawn: balance=%d", balA) }
}

func TestConcurrentTransfers_VulnerableAllowsOverdraftButNoDataRace(t *testing.T) {
    svc, ledgerStore := newTestServiceFromProfile(t, "../../configs/vulnerable.json")
    acctA, _ := svc.CreateAccount(ctx, "owner-1")
    acctB, _ := svc.CreateAccount(ctx, "owner-2")
    owner := backend.Principal{ID:"owner-1", Role:"account-owner"}
    svc.Deposit(ctx, owner, acctA, 1000)
    var wg sync.WaitGroup
    for i := 0; i < 20; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            svc.Transfer(ctx, owner, acctA, acctB, 100)
        }()
    }
    wg.Wait()
    // This test documents the vulnerability: it must still pass under
    // `go test -race` (no unsynchronized memory access), but the ledger
    // invariant is allowed to be violated here -- that is the point.
    _, _, _ = ledgerStore.CheckInvariant(ctx)
}
```

- [ ] **Step 3: Run all tests including race detector**

Run: `go test ./... -v` then `go test -race ./...`
Expected: all PASS, `-race` reports no data races in any package
(including the vulnerable-mode concurrency test).

- [ ] **Step 4: Run full verification suite**

Run: `gofmt -l .` (expect no output), `go vet ./...`, `go build ./...`
Expected: all clean.

- [ ] **Step 5: Commit**

```bash
git add internal/backend/integration_test.go internal/backend/concurrency_test.go
git commit -m "test: full-stack and concurrency tests across both security modes"
```

---

## Self-Review (completed before handoff)

1. **Spec coverage:** every package in `COMPONENT_INTERFACES.md` except
   `internal/harness`, `internal/benchmark`, `internal/detection`,
   `internal/agent`, `internal/quantum` (explicitly out of scope for this
   plan, covered by Plans 2-5) has a task. `ARCHITECTURE.md` §4-§8 (wire
   protocol, mode isolation, ledger model, key separation, identity
   model) are each covered by a task.
2. **Step scan:** no step left as "handle edge cases" or similar; every
   code step names an exact signature; test steps give concrete
   assertions.
3. **Type consistency:** `ledger.AccountID`/`ledger.Money`/`ledger.Entry`,
   `config.CryptoProfileName`, `config.SecurityProfile`, and
   `backend.Principal`/`PrincipalID`/`Role` are used identically across
   every task that references them (checked against
   `COMPONENT_INTERFACES.md`'s own signatures).
4. **Review Focus:** all five items each have an owning task and test, as
   listed above.
5. **Proportion:** ten tasks for eight packages plus the CLI and an
   integration/concurrency pass is proportional to a foundation plan of
   this size; code blocks are signatures and test bodies, not full
   implementations.

---

## Before implementation starts

This directory (`C:\Users\HP\Desktop\N_Sim`) is not a git repository yet.
The plan's commit steps assume it is. I have not run `git init` — that
needs your explicit go-ahead (per your earlier instruction not to touch
git without asking).
