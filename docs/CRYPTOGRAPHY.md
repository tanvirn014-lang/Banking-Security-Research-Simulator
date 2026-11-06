# BankSec Lab — Cryptography

**Status:** Approved design, pre-implementation

**Binding rule (from the source spec, non-negotiable):** BankSec Lab never
implements a production cryptographic primitive from scratch. All real
cryptography comes from the Go standard library or `cloudflare/circl`. Any
intentionally weak or simplified construction is a labeled educational
toy, never presented as a secure implementation.

## 1. Three fixed crypto profiles

`internal/crypto` exposes exactly three profiles, selected via
`SecurityProfile` (`ARCHITECTURE.md` §5) and enforced server-side:

### 1.1 weak-educational

| Primitive | Choice | Purpose |
|---|---|---|
| Asymmetric | small-parameter RSA (e.g., 16-24 bit modulus) and small-group Diffie-Hellman | brute-forceable within seconds, for classical cryptanalysis demos |
| Symmetric | AES in ECB mode | demonstrates pattern leakage |
| IV handling | static/reused IV | demonstrates IV-reuse weaknesses |
| MAC | HMAC with a truncated/weak key | demonstrates weak key-derivation |

All weak-educational constructs are built from stdlib primitives used
*incorrectly on purpose* (e.g., `crypto/aes` in ECB mode via manual block
chaining) or deliberately tiny `math/big` parameters — never a hand-rolled
cipher. Every output involving this profile is labeled
`"profile": "weak-educational"` and documented as unsafe by design.

### 1.2 standard

| Primitive | Library |
|---|---|
| Symmetric encryption | AES-GCM, `crypto/aes` + `crypto/cipher` |
| MAC | HMAC-SHA-256, `crypto/hmac` + `crypto/sha256` |
| Signatures | Ed25519, `crypto/ed25519` |
| Key agreement | X25519, `crypto/ecdh` |

### 1.3 post-quantum

| Primitive | Library |
|---|---|
| Key encapsulation | ML-KEM, Go stdlib `crypto/mlkem` (verify exact Go version/API at implementation time) |
| Signatures | ML-DSA, `cloudflare/circl` |
| Hybrid mode | classical (X25519) + ML-KEM combined, matching current real-world PQC migration practice |

## 2. Weak-construct parameter bounds

To keep classical-cryptanalysis scenarios (`ATTACK_SURFACES.md` §5)
tractable and reproducible, weak-educational RSA/DH parameters are fixed at
registration time per scenario (e.g., a documented 20-bit RSA modulus), not
randomly generated per run, so that expected attempt counts and time
bounds are stable across repeated experiments. Parameter choices are
recorded alongside benchmark results (seed/config, per
`BENCHMARK_METHODOLOGY.md`).

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

## 6. Known limitations (honest)

- `crypto/mlkem`'s exact API has changed across Go versions; the
  implementation plan must pin a specific Go version and verify the API
  surface before building against it.
- `cloudflare/circl`'s ML-DSA implementation should be pinned to a specific
  tagged version and its changelog checked for any security advisories at
  implementation time — this document does not freeze a version number,
  since that would go stale immediately.
- The weak-educational profile's "brute-forceable within seconds" claim
  depends on the implementation host's performance; parameter bounds should
  be re-validated against the actual benchmark hardware during
  implementation, not assumed from this document alone.
