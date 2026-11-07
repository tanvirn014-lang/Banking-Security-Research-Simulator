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

`internal/crypto.Engine` exposes seven operations (selected via
`domain.CryptoProfileName`, driven by `SecurityProfile`) across exactly
three profiles — see `internal/crypto/engine.go`: the original five
(`Encrypt`, `Decrypt`, `Sign`, `Verify`, `MAC`), plus
`GenerateKeyPair`/`DeriveSharedSecret` (key exchange, §1.2). These two
new methods are implemented directly on `Engine` rather than a separate
interface: direct inspection confirms `engine struct{}` is the only
concrete `Engine` implementation anywhere in this codebase, with zero
mocks or fakes, so there is no second implementation or test double that
a separate interface would spare from growing two unused methods.

**Key agreement alone does not authenticate the peer**, for either
profile: nothing in `GenerateKeyPair`/`DeriveSharedSecret` proves a
received public key actually came from the party you intended to talk
to. A man-in-the-middle who can intercept and replace public values in
transit defeats both profiles equally (`internal/crypto/engine.go`'s own
doc comment on both methods states this). This project has no live
handshake anywhere in `internal/protocol` to attack that boundary on —
see §6 item 3 below — so this is a documented property of the
primitive, not a claim that it is fit to use unauthenticated in a real
protocol.

### 1.1 weak-educational (`internal/crypto/weakeducational.go`)

| Primitive | As implemented | Purpose |
|---|---|---|
| Asymmetric | a fixed, small toy RSA modulus (`ToyRSAPublicKey`) | brute-forceable by trial division within a bounded trial budget, for classical cryptanalysis demos (`internal/harness`'s `crypto-toy-rsa-factor-forge` scenario, `internal/quantum`'s classical RSA baseline) |
| Key exchange | a fixed, small safe-prime subgroup DH group (`ToyDHPublicParams`, `weakDHGenerateKeyPair`/`weakDHDeriveSharedSecret`) | brute-forceable via classical baby-step-giant-step within a bounded budget, for the `crypto-dh-discrete-log` attack scenario |
| Symmetric | AES in ECB mode (`weakECBEncrypt`/`weakECBDecrypt`) | demonstrates pattern leakage (identical plaintext blocks produce identical ciphertext blocks) |
| MAC | HMAC-SHA-256 truncated to 4 bytes (`weakMAC`, `weakMACTruncatedLen`) | demonstrates a weak, brute-forceable tag length |

**Not implemented, despite appearing in the original design table:**
static/reused-IV demonstration (ECB mode has no IV/nonce concept at all,
so "IV handling" does not apply to it; this was an inconsistency in the
original design table itself, not a missed implementation step — see
`docs/ATTACK_COVERAGE.md` §5).

All weak-educational constructs are built from stdlib primitives used
*incorrectly on purpose*, or deliberately tiny `math/big` parameters —
never a hand-rolled cipher. Every weak-educational output is labeled
`"profile": "weak-educational"`.

**Key exchange construction detail:** the toy DH group is a *safe
prime* (`toyDHP = 2*toyDHQ + 1`, both prime) with `toyDHG` generating
the order-`toyDHQ` subgroup — not an arbitrary prime modulus. This
matters: in a group of composite order, a peer public key from a small
subgroup (the trivial case being `1`) makes the derived secret
predictable regardless of either party's private exponent.
`weakDHDeriveSharedSecret` validates every peer public key for both
range (`1 < y < p-1`) and subgroup membership (`y^toyDHQ mod p == 1`)
before using it. `ToyDHPublicParams()` returns defensive copies,
matching `ToyRSAPublicKey()`'s existing pattern. Both key-exchange
methods return the **raw** agreed secret, not a key: neither this
profile's nor the standard profile's output is suitable as a symmetric
key without first passing through a key-derivation function. No caller
in this codebase consumes this output as a key, so no KDF is added.

### 1.2 standard (`internal/crypto/standard.go`)

| Primitive | As implemented |
|---|---|
| Symmetric encryption | AES-256-GCM, `crypto/aes` + `crypto/cipher` |
| MAC | HMAC-SHA-256, `crypto/hmac` + `crypto/sha256` |
| Signatures | Ed25519, `crypto/ed25519` |

**Implemented** (closing the gap carried forward since Milestone 4's
security review, repeated through Milestone 12's verification pass):
the original design table's **X25519 key agreement** (`crypto/ecdh`)
for the standard profile. `standardGenerateKeyPair` uses
`ecdh.X25519().GenerateKey(rand.Reader)`;
`standardDeriveSharedSecret` reconstructs both keys via `crypto/ecdh`
and calls `PrivateKey.ECDH` — propagating its errors unchanged,
including its documented rejection of an all-zero (low-order peer
public key) result. This is why the small-parameter Diffie-Hellman
discrete-log attack (`ATTACK_SURFACES.md` §9) is now **Implemented &
Verified**: there is a real target component (the weak-educational
profile's own DH primitive, §1.1) for it to exercise. Key agreement
alone does not authenticate the peer — see §1 above, which applies
identically to both profiles.

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

**`GenerateKeyPair`/`DeriveSharedSecret` return `ErrProfileNotImplemented`
for `"pqc"`, as a considered decision, not a gap:** `"pqc"`'s own key
establishment already happens via ML-KEM encapsulation inside
`Encrypt`/`Decrypt` above — a two-message, asymmetric KEM shape (one
side generates a keypair; the *other* side encapsulates against that
public key, producing both a ciphertext and the shared secret in one
step) that does not fit `GenerateKeyPair`/`DeriveSharedSecret`'s
symmetric generate-then-exchange-then-derive shape (there is no
equivalent "the first side also calls `DeriveSharedSecret`" step in
KEM). Forcing ML-KEM into this signature would misrepresent how it
actually works.

**Not implemented:** a hybrid classical+PQC mode (e.g. X25519 + ML-KEM
combined). The original design described this as "matching current
real-world PQC migration practice," but it was never built — `"pqc"` is
pure ML-KEM/ML-DSA only. §1.2's X25519 implementation exists as a
standalone `standard`-profile primitive now, but nothing combines its
output with `"pqc"`'s ML-KEM output; building that combination remains
a separate, unimplemented gap.

## 2. Weak-construct parameter bounds

`internal/crypto`'s weak-educational toy RSA modulus is **fixed, not
randomly generated per run**: `N = 997 × 1009 = 1,006,573` (~20 bits,
`ToyRSAPublicKey`), chosen once so expected attempt counts and time
bounds are stable across repeated experiments — a trial-division attack
against it (`internal/harness`'s `crypto-toy-rsa-factor-forge` scenario)
is bounded to 1,000,000 trials.

Similarly, the weak-educational toy DH group is also fixed: `toyDHQ =
490481`, `toyDHP = 2*toyDHQ + 1 = 980963` (~20 bits, `ToyDHPublicParams`),
a safe prime deliberately kept below `internal/quantum`'s own
`MaxDiscreteLogModulus = 1,000,000` — the baby-step-giant-step attack
(`crypto-dh-discrete-log` scenario) sizes its cost from `toyDHP` itself,
not from the smaller `toyDHQ`, so `toyDHP` is what had to stay inside
that budget. **Unlike the toy RSA modulus's fixed trial count,** the DH
group's parameters are fixed but each party's *keypair* is not: every
call to `weakDHGenerateKeyPair`/`standardGenerateKeyPair` sources its
private value from `crypto/rand`, not from a scenario's seed — so
`crypto-dh-discrete-log`'s exact `ComputationalCost` (baby-step-
giant-step's operation count) varies run to run even at a fixed seed,
though whether the attack succeeds at all does not (see
`ATTACK_SURFACES.md` §10 for the full disclosure).

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
3. **Key exchange** (closing the former §1.2 gap): done, as a
   primitive only — see §1.1/§1.2 above and
   See this project's design notes for the full design and its scope
   decisions. `internal/protocol`'s
   wire format is untouched: there is still no live handshake anywhere
   in this system, and `NewClient`/`NewServer` are still handed a
   pre-provisioned session key exactly as before. Wiring key exchange
   into the protocol layer itself remains a separate, larger unit of
   work, deliberately out of scope here, and should start with its own
   design/scoping pass given how much of the wire protocol currently
   assumes no handshake exists at all.

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
- §1.3's hybrid-mode gap (named in the original design but never
  implemented) remains an open, carried-forward item — see that section
  above for the full explanation. §1.2's X25519 key-agreement gap is
  closed as of this unit of work.
