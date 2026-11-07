# BankSec Lab — Cryptography

**Status:** Implemented (Milestone 4; see `internal/crypto`). This
document describes the actual, shipped implementation, not the original
pre-implementation design — every claim below was verified directly
against the code during Milestone 13's documentation pass. Where the
original design called for something that was never built, that is
stated explicitly as a gap, not silently dropped from the document.

**Binding rule (from the source spec, non-negotiable):** BankSec Lab
never implements a production cryptographic primitive from scratch. All
real cryptography comes from the Go standard library. (The original
design also allowed `cloudflare/circl` as a fallback for post-quantum
signatures; as implemented, Go 1.27.3's own standard library already
ships `crypto/mldsa`, so `circl` turned out unnecessary and is not a
dependency of this project at all — see `go.mod`.) Any intentionally
weak or simplified construction is a labeled educational toy, never
presented as a secure implementation.

## 1. Three fixed crypto profiles

`internal/crypto.Engine` exposes exactly three profiles (selected via
`domain.CryptoProfileName`, driven by `SecurityProfile`) across exactly
five operations: `Encrypt`, `Decrypt`, `Sign`, `Verify`, `MAC` — see
`internal/crypto/engine.go`. **There is no key-exchange/key-agreement
method on `Engine` at all** (see §1.2's gap note below).

### 1.1 weak-educational (`internal/crypto/weakeducational.go`)

| Primitive | As implemented | Purpose |
|---|---|---|
| Asymmetric | a fixed, small toy RSA modulus (`ToyRSAPublicKey`) | brute-forceable by trial division within a bounded trial budget, for classical cryptanalysis demos (`internal/harness`'s `crypto-toy-rsa-factor-forge` scenario, `internal/quantum`'s classical RSA baseline) |
| Symmetric | AES in ECB mode (`weakECBEncrypt`/`weakECBDecrypt`) | demonstrates pattern leakage (identical plaintext blocks produce identical ciphertext blocks) |
| MAC | HMAC-SHA-256 truncated to 4 bytes (`weakMAC`, `weakMACTruncatedLen`) | demonstrates a weak, brute-forceable tag length |

**Not implemented, despite appearing in the original design table:**
small-group Diffie-Hellman (no key-exchange primitive exists anywhere in
this codebase — see §1.2) and static/reused-IV demonstration (ECB mode
has no IV/nonce concept at all, so "IV handling" does not apply to it;
this was an inconsistency in the original design table itself, not a
missed implementation step — see `docs/ATTACK_COVERAGE.md` §5).

All weak-educational constructs are built from stdlib primitives used
*incorrectly on purpose*, or deliberately tiny `math/big` parameters —
never a hand-rolled cipher. Every weak-educational output is labeled
`"profile": "weak-educational"`.

### 1.2 standard (`internal/crypto/standard.go`)

| Primitive | As implemented |
|---|---|
| Symmetric encryption | AES-256-GCM, `crypto/aes` + `crypto/cipher` |
| MAC | HMAC-SHA-256, `crypto/hmac` + `crypto/sha256` |
| Signatures | Ed25519, `crypto/ed25519` |

**Gap, carried forward unresolved since Milestone 4's own security
review, confirmed still true by direct code inspection as of Milestone
12's verification pass:** the original design table also specified
**X25519 key agreement** (`crypto/ecdh`) for the standard profile. It was
never implemented — `Engine` has no key-exchange method, and no code
anywhere in this repository imports `crypto/ecdh` or performs a
Diffie-Hellman-style key agreement. This is why the small-parameter
Diffie-Hellman discrete-log attack (`ATTACK_SURFACES.md` §5) is marked
**Unsupported**, not merely unimplemented: there is no real target
component for it to exercise. This has been flagged in every
whole-branch security review since Milestone 4 and remains an open
design question for the user: how key exchange should be integrated
into `Engine` and the wire protocol, if it is wanted at all.

### 1.3 post-quantum (`internal/crypto/pqc_kem.go`, `pqc_dsa.go`)

| Primitive | As implemented |
|---|---|
| Key encapsulation | ML-KEM-768 (NIST FIPS 203), Go 1.27.3 standard library `crypto/mlkem` |
| Signatures | ML-DSA-44 (NIST FIPS 204), Go 1.27.3 standard library `crypto/mldsa` — **not** `cloudflare/circl` as the original design anticipated; by the time this was implemented, Go's own standard library already shipped it, confirmed via `go doc crypto/mldsa` |

Encrypt/Decrypt under `"pqc"` is a KEM-then-AEAD construction:
encapsulate a shared secret against the recipient's ML-KEM public key,
then encrypt the payload under that secret with the same AES-GCM
implementation the standard profile uses — the shared secret is used
directly as the AES-256-GCM key (ML-KEM's 32-byte shared secret is
already uniformly random, so no separate HKDF derivation step is used).
Signing is deterministic (`SignDeterministic`, not the randomized
`Sign`), for the same reproducibility reason the rest of this project
favors determinism (`ARCHITECTURE.md`'s reproducibility principle).

**Not implemented:** a hybrid classical+PQC mode (e.g. X25519 + ML-KEM
combined). The original design described this as "matching current
real-world PQC migration practice," but it was never built — `"pqc"` is
pure ML-KEM/ML-DSA only, and (per §1.2's gap) there is no X25519
implementation to combine it with anyway.

## 2. Weak-construct parameter bounds

`internal/crypto`'s weak-educational toy RSA modulus is **fixed, not
randomly generated per run**: `N = 997 × 1009 = 1,006,573` (~20 bits,
`ToyRSAPublicKey`), chosen once so expected attempt counts and time
bounds are stable across repeated experiments — a trial-division attack
against it (`internal/harness`'s `crypto-toy-rsa-factor-forge` scenario)
is bounded to 1,000,000 trials.

This is a **different, larger** modulus than `internal/quantum`'s own
toy RSA inputs (`n ∈ {15, 21, 35}`, used for the genuinely-simulated
Shor's-algorithm demonstration) — `internal/quantum`'s moduli are
smaller specifically so the full quantum phase-estimation circuit fits
within the qubit bound (`QUANTUM_METHODOLOGY.md` §5); `internal/crypto`'s
toy RSA is sized for a *classical* trial-division attack to be
tractable-but-not-instant instead. The two are unrelated numbers for
unrelated purposes — do not conflate them.

## 3. Server-side profile enforcement

The protocol server (`internal/protocol` + `internal/backend`) enforces a
**minimum accepted crypto profile** per `SecurityProfile`. A client
declaring a weaker profile than the server's minimum is rejected in
hardened mode. In vulnerable mode, the server accepts whatever the client
declares — this is the deliberately exploitable downgrade surface
(`ATTACK_SURFACES.md` §2). The server never infers trust from a
client-declared profile without checking it against its own configured
floor.

## 4. Key management interaction

`internal/keystore` stores, per key: profile it was generated under,
creation time, rotation state, and (hardened mode only) wraps key material
with AES-GCM under a store-level key before persisting; vulnerable mode
persists key material in plaintext. See `ATTACK_SURFACES.md` §4 for the
corresponding attack scenario.

## 5. Quantum subsystem — explicit non-claims

`internal/quantum` is **structurally disconnected** from `internal/crypto`:
it never receives, touches, or attempts to factor/break any real key
generated for the standard or PQC profiles. It operates exclusively on
small, fixed, documented toy inputs (e.g., RSA modulus 15, 21, or 35 for
Shor; a search space up to 2^16-2^20 for Grover).

Every surface that displays quantum-subsystem output (CLI, benchmark
export, documentation) must carry the label: **"Classical simulation of a
quantum algorithm's logic, at toy scale. Not executed on quantum hardware.
Not a demonstrated attack against this system's real cryptographic keys."**
This is a hard requirement from the source spec's non-goals (§2.2) and is
treated as a correctness requirement, not a style preference — see the
qubit-bound error test in `ATTACK_SURFACES.md` §7.

See `QUANTUM_METHODOLOGY.md` for the full research methodology: exactly
what each of `internal/quantum`'s four experiments measures, what
idealized-quantum-operation assumptions they depend on, and what cannot
be concluded from any of them.

## 6. Adding a new cryptographic algorithm or profile

`internal/crypto.Engine` is the single seam every other package goes
through for cryptographic operations (`internal/backend`,
`internal/keystore`, `internal/protocol`'s auth-tag computation all call
`Engine`, never a primitive directly). To add a new algorithm:

1. **Adding a new primitive to an EXISTING profile** (e.g. a different
   MAC construction for `"standard"`): implement it in that profile's own
   file (`standard.go`, `weakeducational.go`, or `pqc_kem.go`/
   `pqc_dsa.go`), update the `switch profile` branch in the relevant
   `Engine` method (`engine.go`), and add a round-trip test plus (for a
   profile with an intentional weakness) a test that actually
   demonstrates the weakness — see `TestECBMode_RepeatsBlocksForRepeatedPlaintext`/
   `TestECBMode_ModifiedCiphertextGoesUndetected` for the pattern: prove
   the weakness exists by actually exercising it, not by asserting it in
   a comment.
2. **Adding a whole new profile** (a 4th `domain.CryptoProfileName`):
   every `Engine` method's `switch profile` must handle it explicitly —
   `ErrProfileNotImplemented` is returned for any name none of the
   `case`s match, so a new profile that's only partially wired (e.g.
   `Encrypt` updated but `MAC` forgotten) fails loudly on first use of the
   missing method, not silently. `internal/config.SecurityProfile`'s own
   `CryptoProfile`/`MinAcceptedCryptoProfile` fields, and
   `internal/protocol`'s `profileRank` downgrade-detection logic, also
   need to know about a new profile's relative strength ranking.
3. **Adding key exchange** (closing the §1.2 gap, if ever undertaken):
   this needs a new `Engine` method (there is no `KeyExchange` method to
   extend today), a design decision on how the protocol layer
   (`internal/protocol`) would carry the exchange (a new frame type? an
   extension to the existing handshake, which today has none — auth keys
   are provisioned out-of-band per connection, see
   `internal/protocol/client.go`'s own doc comment on `NewClient`), and
   should start with its own `superpowers:brainstorming`-style scoping
   pass given how much of the wire protocol currently assumes no
   handshake exists at all.

Whatever is added, keep the binding rule: no cryptographic primitive is
ever hand-rolled from scratch — real cryptography is Go standard library
only; an intentionally weak construction is clearly labeled as such and
proven weak by a real test, never merely asserted.

## 7. Known limitations (honest)

- The weak-educational profile's "brute-forceable within a bounded
  budget" claim for its toy RSA modulus depends on the host machine's
  performance; `internal/crypto`'s own trial-division bound
  (1,000,000 trials) and `internal/quantum`'s equivalent bound
  (`MaxRSAFactorModulus`) are both generous enough to complete in well
  under a second on ordinary development hardware, but neither document
  claims a precise wall-clock figure, since that is genuinely
  machine-dependent.
- §1.2's X25519 key-agreement gap and §1.3's hybrid-mode gap (both
  named in the original design but never implemented) remain open,
  carried-forward items — see those sections above for the full
  explanation, and `docs/ATTACK_COVERAGE.md` for how this constrains
  attack-scenario coverage.
