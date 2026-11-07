# BankSec Lab — Quantum-Inspired Cryptanalysis Experiments: Research Methodology

This document explains exactly what `internal/quantum`'s four
experiments measure, how each measurement is produced, what assumptions
each one depends on, and — most importantly — what **cannot** be
concluded from any of them. It is the honest-reporting document the
Milestone 9 instructions require, read alongside `docs/CRYPTOGRAPHY.md`
§5 (the mandatory non-claims every quantum-subsystem output must carry)
and the in-code doc comments on `Circuit`, `Shor`, `Grover`,
`RSAFactorTrialDivision`, and `DiscreteLogBabyStepGiantStep`, which this
document cross-references rather than duplicates in full.

## 1. The four experiments, in one sentence each

| # | Experiment | What it is | File |
|---|---|---|---|
| 1 | `RSAFactorTrialDivision` | A genuine classical factoring algorithm (trial division), run against a small, insecure RSA-shaped modulus. | `classical.go` |
| 2 | `DiscreteLogBabyStepGiantStep` | A genuine classical discrete-log algorithm (baby-step giant-step), run against a small, insecure group. | `classical.go` |
| 3 | `Grover` | A classical **simulation** of Grover's quantum amplitude-amplification algorithm's logic, at toy qubit counts. | `grover.go` |
| 4 | `Shor` | A classical **simulation** of Shor's quantum phase-estimation / order-finding algorithm's logic, at toy qubit counts. | `shor.go` |

Experiments 1-2 are **real classical computation** — there is no
simulation involved; the CPU genuinely performs the trial divisions /
modular multiplications the algorithm calls for, on real (if tiny)
numbers. Experiments 3-4 are **classical simulations of a different
kind of computation** — the CPU performs ordinary floating-point
(complex128) linear algebra that *mimics* what a quantum computer's
state evolution would do, for a register small enough (≤20 qubits) that
the full amplitude vector fits in memory and gate operations complete in
reasonable time.

These are fundamentally different activities, and the two output types
(`ClassicalTrace` vs. `CircuitTrace`) and two labels
(`ClassicalBaselineLabel` vs. `SimulationLabel`) exist specifically so
no output ever blurs that distinction.

## 2. What is measured, and how

### 2.1 Classical baselines (experiments 1-2)

Both algorithms are implemented exactly as a textbook description would
specify — no shortcut that calls a bigger factoring/discrete-log library,
no precomputed answer table. `ClassicalTrace` reports two numbers kept
deliberately apart:

- **`OperationCount`** — the actual number of elementary steps the
  algorithm performed (trial divisions attempted; baby-steps plus
  giant-steps computed). This is a count of *algorithmic work*,
  independent of what machine it ran on.
- **`MeasuredCPUTimeMS`** — real wall-clock time, from `time.Now()` at
  entry to `time.Now()` at the result, on whatever machine ran the test.
  This number depends on the machine, Go's scheduler, and everything
  else that affects wall-clock measurement, and is not a
  machine-independent property of the algorithm the way
  `OperationCount` is.

Both are bounded (`MaxRSAFactorModulus`, `MaxDiscreteLogModulus`, both
1,000,000) because both algorithms are `O(sqrt(n))` — safe at toy scale,
impractically slow unbounded. This mirrors `Circuit`'s own `MaxQubits`
bound: a documented ceiling with a clear error, never a silent slow-down.

### 2.2 Quantum-algorithm simulations (experiments 3-4)

`Circuit` (`circuit.go`) is a **state-vector simulator**: it holds the
full `2^NumQubits`-length complex amplitude vector and evolves it via
genuine unitary (norm-preserving, reversible) linear algebra. Every gate
— `ApplyH`, `ApplyX`, `ApplyCNOT`, `ApplyControlledPhase` — is a real,
standard quantum gate's matrix action, implemented directly against the
full amplitude vector, never a precomputed shortcut.

Three operations are a different kind of unitary, used only where a
textbook toy simulator of this scale needs one, and documented
individually in `circuit.go` (a security review, finding M6, caught
this document previously saying "two gates" and omitting the third
entirely, and separately saying Grover's marking oracle used
`ApplyPermutationUnitary` when it actually uses `ApplyPhaseOracle` —
both corrected here):

- **`ApplyPermutationUnitary`** (used by `Shor` for its controlled
  modular-exponentiation oracle) lifts an arbitrary classically-computed
  *bijection* on basis indices directly to a unitary permutation matrix,
  without decomposing it further into elementary one-/two-qubit gates
  (the ancilla-heavy adder/Toffoli circuitry a real quantum compiler
  would use for this is a disproportionate undertaking for a toy
  simulator, and no well-known toy Shor/Grover implementation goes that
  far either).
- **`ApplyPhaseOracle`** (used by `Grover` for its marking oracle)
  similarly wraps an arbitrary caller-supplied classical predicate as a
  diagonal sign-flip unitary.
- **`ApplyDiffusion`** (used by `Grover` for its diffusion/reflection
  step) is a *fixed*, well-known operator (not an arbitrary oracle), but
  is likewise implemented directly via its mean-amplitude identity rather
  than built up from `ApplyH`/`ApplyX`/`ApplyControlledPhase`.

All three are still **genuine unitary operations over genuinely
superposed amplitudes** — the superposition, interference, and
entanglement the rest of the circuit produces are real (simulated)
quantum effects; only these three operations' own internal
implementation skips a further gate-by-gate decomposition that would not
change the physics being demonstrated, only its cost to build. `ApplyH`,
`ApplyX`, `ApplyCNOT`, `ApplyControlledPhase`, and the
`ApplyQFT`/`ApplyInverseQFT` built from them, by contrast, **are**
elementary-gate-decomposed, verified directly against a brute-force
reference DFT matrix (`TestApplyQFT_MatchesTextbookDFTMatrix` and
`TestApplyQFT_MatchesTextbookDFTMatrix_AcrossQubitCounts`, covering
n=1..8 plus a non-contiguous sub-register) rather than only
self-consistency.

`CircuitTrace` keeps four numbers separate:

- **`QubitsUsed` / `GateOperations` / `OracleQueries`** — structural
  counts of the simulated circuit itself (how many qubits; how many gate
  applications; how many oracle/controlled-unitary invocations).
  `GateOperations` is named for exactly what it counts — a running total
  of `Apply*` calls — not "circuit depth" (a security review correction,
  finding M1: true circuit depth is the length of the longest
  dependency chain of gates that cannot run in parallel, which this
  package has never computed). For `Shor`, both `GateOperations` and
  `OracleQueries` sum across **every** candidate-base attempt within one
  `Shor` call, including attempts that didn't yield a usable period, not
  just the successful one. `OracleQueries` specifically counts controlled
  modular-exponentiation invocations (one per counting qubit) for `Shor`,
  and amplitude-amplification iterations (one oracle-plus-diffusion pair
  each) for `Grover`.
- **`SimulatedCPUTimeMS`** — real, measured wall-clock time this
  classical simulation took on this machine. This is **not** a
  measurement of quantum hardware performance, and must never be
  compared to one — see §4.
- **`TheoreticalComplexity`** — a *fixed, human-written statement* of the
  algorithm's known textbook asymptotic complexity on real quantum
  hardware (e.g. Shor's `O((log N)^3)` gate count; Grover's `O(sqrt(N))`
  query count). This string is never computed from the run's own
  measurements — it is a citation of known results, kept visibly
  separate from anything this code measured.
- **`Label`** — the mandatory `SimulationLabel` disclosure.

### 2.3 The one classical shortcut each quantum experiment takes, disclosed

Both `Shor` and `Grover` take one classical-preprocessing shortcut,
each documented at its call site and repeated here for visibility:

- **`Shor`** classically tries candidate bases `a` in a fixed order
  (`2, 3, 4, ...`, skipping non-coprime values) rather than uniformly at
  random, and classically computes each oracle's multiplier `a^(2^j) mod
  n` via ordinary repeated squaring before handing it to the circuit as
  a fixed classical parameter. Both are exactly what the real algorithm
  does too (the real algorithm's classical control computer also picks
  `a` and precomputes the modular-exponentiation circuit's classical
  parameters) — nothing here substitutes for the quantum part itself,
  which is still the order-finding via phase estimation.
- **`Grover`** classically pre-scans the oracle over all `N` inputs once
  to count `M` (the number of marked elements), needed to compute the
  optimal iteration count `floor(pi/4 * sqrt(N/M))`. Real Grover usage
  either assumes `M` known in advance or finds it via *quantum counting*
  (a separate algorithm, not implemented here). This pre-scan is **not**
  included in `CircuitTrace.OracleQueries` — it is this toy demo's own
  classical bookkeeping shortcut to pick a correct iteration count, not
  part of the `O(sqrt(N/M))` theoretical query complexity being
  demonstrated. Counting it as an "oracle query" would conflate the
  demo's own setup cost with the thing being measured.

### 2.4 Grover is genuinely probabilistic, and honestly reports failure

Real Grover's algorithm never succeeds with probability exactly 1 —
amplitude amplification rotates the state toward (not onto) the marked
subspace, and the optimal iteration count is itself only an integer
approximation of the ideal (generally irrational) rotation angle. A
security review (finding I1) caught an early version of this code
*silently returning an unmarked element with `err == nil`* whenever more
than half the search space was marked (`M > N/2`), because the iteration
formula `floor(pi/4 * sqrt(N/M))`, forced up to a minimum of 1, can
overshoot the optimal angle badly enough to drive the true success
probability to **exactly 0** — reproduced concretely with `N=4, M=3`.

Two changes followed from treating this as "the simulation must report
what really happened," not as a bug to paper over with a bigger forced
iteration count:

1. Whenever `M > N/2`, `Grover` now runs **zero** amplification
   iterations: the uniform superposition's own success probability
   (`M/N`) already exceeds 50% in that regime, and any amplification
   only makes it worse (the "more than half marked" case is a well-known
   edge case in the Grover literature, not something this simulator
   invented a special rule for).
2. **Every** `Grover` call verifies its own measured result against the
   real `oracle` before reporting success. If the measurement lands on
   an unmarked element — which can genuinely happen, with calculable
   probability, for ANY `M` — `Grover` returns `ErrGroverMeasurementUnmarked`
   rather than a false success.

This means a caller of `Grover` must handle a non-nil error as a normal,
expected outcome of a probabilistic algorithm, not an exceptional
condition. A real quantum computer running this exact circuit would face
the identical chance of an unmarked measurement — this is Grover's own
genuine behavior, faithfully simulated, not a simulation artifact.

## 3. Determinism and reproducibility

Real quantum measurement is genuinely probabilistic (Born-rule
sampling). The user's "include deterministic test cases" requirement is
satisfied not by removing that randomness, but by **seeding it
reproducibly**:

- `Circuit.Measure`/`MeasureAll` sample via a caller-supplied
  `*rand.Rand` (`NewCircuitWithRand`), never a time-seeded global source,
  when determinism matters.
- `Shor` seeds each `(n, a)` attempt's `*rand.Rand` from `(n, a)` itself.
- `Grover` seeds its circuit's `*rand.Rand` from `(searchSpaceBits, M)`.
- `RSAFactorTrialDivision` and `DiscreteLogBabyStepGiantStep` involve no
  randomness at all — both algorithms are fully deterministic by
  construction.

This matches this project's existing `seed`-parameterized-reproducibility
convention (`internal/harness.Runner`), and is why `Shor(ctx, 15)`
returns the same factors `{3, 5}` on every run, rather than "probably
the right answer most of the time."

## 4. What CANNOT be concluded from these experiments

This section exists because the user's instructions explicitly require
it, and because every one of these points is a real, common
misreading of a toy quantum-algorithm demo:

1. **No actual quantum speedup is demonstrated.** `Shor` and `Grover`
   are classical programs. Classically simulating `n` qubits costs
   `O(2^n)` in both time and memory (every gate touches the full
   amplitude vector) — the simulation gets *exponentially slower* as
   qubit count grows, which is the *opposite* of the polynomial/quadratic
   speedup a real quantum computer is theorized to provide for these
   algorithms. `SimulatedCPUTimeMS` growing with qubit count is not
   evidence against quantum speedup — it is a property of classical
   simulation, unrelated to the question.
2. **No real quantum hardware was used, or modeled with any fidelity.**
   These are *idealized* unitary operations: perfect gates, no
   decoherence, no gate-error rates, no connectivity constraints, no
   calibration drift, no error correction. Real quantum hardware today
   has all of these, and they materially affect whether an algorithm
   like Shor's actually succeeds at any non-trivial scale. This code
   says nothing about that gap.
3. **No attack against this project's real cryptographic keys is
   demonstrated.** `internal/quantum` is structurally disconnected from
   `internal/crypto` (enforced by `TestNoImportsOutsideStdlib` — this
   package imports no other `banksec-lab` package at all) and only ever
   operates on the small, fixed, documented toy inputs named above. It
   never receives, touches, or attempts to factor/break a key generated
   for this project's `standard` or `pqc` profiles.
4. **The classical baselines (experiments 1-2) are not "what classical
   computers can do against real RSA/discrete-log,"** and the quantum
   simulations (3-4) are not "what quantum computers can do against
   real RSA/discrete-log." Both operate on deliberately tiny, insecure
   parameters chosen so the demonstration completes in milliseconds —
   see §5 for exactly how tiny, and why that is not representative of
   anything at cryptographic scale.
5. **`ComplexityReport`'s numbers are not measured, and never will be.**
   They are a direct evaluation of two well-known closed-form formulas
   (`N` and `ceil(pi/4*sqrt(N))`). No simulation runs to produce them.
   Reporting a *measured* number next to them as if the two were
   comparable would be exactly the "fabricating performance
   improvements" the user's requirements explicitly forbid — this
   codebase never does that: `Grover`'s own `CircuitTrace` reports its
   *measured* `SimulatedCPUTimeMS` separately, and nothing anywhere
   divides one by the other to manufacture a "speedup number."

## 5. Parameter scale, and why it is deliberately tiny

| Experiment | Example parameters | Why this small |
|---|---|---|
| RSA trial division | `n = 3233 = 61 × 53` | `O(sqrt(n))` trial division finishes in microseconds; a cryptographically-sized RSA modulus (2048+ bits) would make trial division run for longer than the age of the universe — the algorithm doesn't change, only `n`'s size, which is exactly why classical factoring is considered infeasible at real RSA scale. |
| Discrete log BSGS | `p = 23`, a tiny prime | Baby-step giant-step is `O(sqrt(p))` time *and space*; a cryptographically-sized prime (hundreds of bits) would need a baby-step hash table far larger than any computer's memory. |
| Shor | `n ∈ {15, 21, 35}` | Each needs `workBits = ceil(log2 n)` work qubits plus `countBits = 2*workBits+1` counting qubits (`13`, `16`, `19` total respectively) — at `n`'s next realistic step up, qubit count would exceed `Circuit.MaxQubits = 20` (`2^20` complex128 ≈ 16 MiB; one qubit more doubles that, and one more doubles it again). |
| Grover | up to `searchSpaceBits = 20` (`N` up to `2^20`) | Same `MaxQubits` bound: the state vector's `O(2^n)` memory cost is the hard ceiling on how large a search space this classical simulator can hold at all, regardless of how fast the search itself would be. |

The qubit-count ceiling is not an implementation inconvenience to be
worked around — it is the direct, correctly-modeled classical cost of
simulating a quantum computer on a classical one, and is itself one of
this document's key honest findings: *this is why quantum simulators on
classical hardware cannot demonstrate quantum advantage even in
principle, independent of how well-optimized the simulator's code is.*

## 6. Theoretical scaling comparison (never fabricated, always labeled)

The only place this codebase compares classical and quantum scaling is
`ComplexityReport`, and it is always a **theoretical, closed-form
calculation** — never a ratio of two measured run times:

| Problem | Classical (textbook) | Quantum (textbook, idealized hardware) |
|---|---|---|
| Unstructured search, `N` items | `O(N)` (exhaustive) | `O(sqrt(N))` (Grover) |
| Factoring an `n`-bit RSA modulus | sub-exponential (general number field sieve) — NOT trial division's `O(sqrt(N))`, which is exponential in bit-length and is not how real classical attacks against RSA-scale moduli are actually attempted | `O((log N)^3)` gate operations (Shor) |

The second row's classical entry is deliberately *not* trial division's
complexity: `RSAFactorTrialDivision` exists as this package's
classical-baseline *experiment* (consistent, honest, and simple to
verify at toy scale), but citing its `O(sqrt(N))` complexity as "the"
classical attack on RSA would be inaccurate and misleading — real
classical cryptanalysis of RSA-scale moduli uses sub-exponential methods
(the general number field sieve), which is the only honest basis for
comparison against Shor's polynomial-time result. This table states both
sides as textbook facts; no number in it is computed by this codebase.

## 7. Summary: what this package is, and is not

`internal/quantum` **is**:
- A correct, from-scratch, genuinely-simulated state-vector quantum
  circuit simulator at toy qubit counts, with its elementary-gate layer
  (`ApplyH`/`ApplyX`/`ApplyCNOT`/`ApplyControlledPhase`/`ApplyQFT`)
  verified against independent reference mathematics, not just
  self-consistency.
- A correct implementation of Shor's and Grover's algorithms' *logic*,
  including their genuine quantum subroutines (phase estimation,
  amplitude amplification), running against honestly-disclosed toy
  inputs with honestly-disclosed classical shortcuts.
- A correct, from-scratch implementation of two classical cryptanalysis
  baselines, included specifically to give the quantum simulations'
  theoretical complexity claims something real to be compared against.
- A worked demonstration of *why* qubit count is the hard ceiling on
  classical quantum simulation — itself a legitimate research finding,
  not just an implementation limit to apologize for.

`internal/quantum` **is not**:
- A quantum computer, or a model of one with any physical fidelity
  (no noise, no decoherence, no hardware constraints).
- Evidence of a practical quantum or classical attack against this
  project's real cryptographic keys, or against real-world RSA/discrete-
  log at cryptographic scale.
- A source of any *measured* performance comparison between classical
  and quantum computation — every such comparison in this package is a
  cited, closed-form, theoretical formula, kept visibly separate from
  anything actually measured.
