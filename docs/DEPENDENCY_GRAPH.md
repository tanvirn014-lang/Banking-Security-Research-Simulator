# BankSec Lab — Dependency Graph

**Status:** Draft, awaiting approval. Companion to
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) and
[TASK_BREAKDOWN.md](TASK_BREAKDOWN.md).

## Task-level graph

```
F1 (done) --> F2 (done) --> F3 domain --> F4 apperr --> F5 applog --> F6 testsupport
                                                                      |
                                                                      v
                              T1 ledger --------------------------+
                              T2 keystore(basic) ------------------+--> T4 backend --> T5 protocol(basic) --> T6 CLI
                              T3 audit(basic) --------------------+
                                                                      |
                     +---------------+---------------+----------------+----------------+-----------------+
                     v               v               v                v                v                 v
              S1 backend authz  S2 protocol    S3 ledger        C1 standard       A1 audit         H1 Scenario+Oracle
              + validation      replay/tamper/ concurrency      crypto profile    hash-chain              |
                     |          downgrade      safety               |                 |                   v
                     |               |            |             C2 weak-edu       A2 querying      H2 PrivilegedAccess
                     +-------+-------+                              |                 |                   |
                              v                                  C3 ML-KEM         A3 export               v
                      S4 security-mode                           (stdlib)            |            H3 Harness Runner
                      e2e test                                       |             A4 Detection       (+ Result schema)
                              |                                  C4 ML-DSA         Engine                  |
                              |                                   (circl)             |             H4 framework tests
                              |                                       \_______________|_________________/ |
                              |                                              |                            |
                              +---------------------+------------------------+                            |
                                                     v                                                     |
                                          C5 protocol profile wiring                                       |
                                  (needs S2 AND C1-C4; M7 already done in parallel above)                  |
                                                     |                                                     |
                                   +-----------------+                                                     |
                                   v                                                                       |
                           K1 keystore encrypted-at-rest (needs only C1, not C5 — starts as soon           |
                                   |                       as C1 lands, parallel with C2-C5)                |
                           K2 rotation/revocation enforcement (needs K1 + C5)                               |
                                   |                                                                        |
                           K3 access auditing                                                               |
                                   |                                                                        |
                           K4 vuln/hardened storage e2e test                                                |
                                   |                                                                        |
            +----------------------+----------------+---------------------+------------------+--------------+
            v                      v                v                     v                  v
      I1 application         I2 protocol       I3 db/ledger          I4 key-mgmt       I5 cryptographic
      (needs S1,S3,H3)       (needs S2,C5,H3)  (needs A1,A4,H3)      (needs K1,H3)     (needs C2,H3)
            \______________________\______________________\______________________\______________/
                                              |
                      +-----------------------+-----------------------+
                      v                                               v
         G1-G4 AI-agent (needs H*, some I*)                B1-B4 Benchmarking (needs H3, some I*)
                      \_______________________________________________/
                                              |
                                              v
                                    V1-V4 Integration & validation
                                              |
                                              v
                                    P1-P3 Documentation & publication

   Q1-Q3 Quantum (needs only F1-F6) ---------------------------------> feeds into V4/P1 only as a labeled demo,
                                                                        never into I1-I5 or C1-C5
```

Note the diagram's middle row: S1-S3 (Milestone 3), C1-C4 (Milestone 4's
profile interfaces), A1-A4 (Milestone 6), and H1-H4 (Milestone 7) all
branch directly off Milestone 2 and have no dependencies on each other —
they converge only where the graph shows an explicit merge (S4; C5; M8's
I-tasks). This is the plan's single biggest parallelization opportunity
and corrects an earlier draft of this diagram that over-serialized H1-H4
behind K4/A4 without cause.

## The four ordering rules, applied

1. **"Do not implement attack scenarios before their target components
   exist."** Enforced: every I-task (M8) depends on the specific milestone
   that builds its target (I1→S1/S3, I2→S2/C5, I3→A1/A4, I4→K1, I5→C2) —
   see the table above. No I-task is schedulable before Milestone 7
   (the generic framework) regardless.
2. **"Do not implement benchmarks before the common result schema
   exists."** Enforced: the schema is `harness.Result` (Task H3, Milestone
   7), not a separate Milestone 11 task — B1 in `TASK_BREAKDOWN.md` is
   "extend/aggregate H3's schema," not "define a schema." Benchmarking
   cannot start before H3.
3. **"Do not implement AI agents before the attack interface and
   observation model exist."** Enforced: G1 (Observation/Action
   interfaces) depends on H1-H3; the whole of Milestone 10 depends on
   Milestone 7 and needs at least one Milestone 8 scenario registered to
   give the agent something to choose between.
4. **"Do not integrate cryptographic protocols before their interfaces are
   finalized."** Enforced: C5 (protocol profile wiring) depends on C1-C4
   (all four profile interfaces) being complete, not just C1. S2 (basic
   protocol replay/tamper, Milestone 3) intentionally predates real crypto
   profile selection — it uses a placeholder single-profile MAC (already
   built in the earlier 5-plan roadmap's Task 8) — and C5 is the task that
   replaces the placeholder with real per-profile selection. This is a
   deliberate two-step integration, not a violation: S2 integrates a
   protocol *mechanism*, C5 integrates the *finalized* multi-profile
   crypto interface into it.

## Parallelization opportunities

Parallelize only where interfaces are stable and files don't overlap:

- **M3 (Security) × M4's C1-C4 × M6 (Audit) × M7 (Harness framework):**
  all four branch directly off M2 with no shared files between them (see
  the corrected diagram above). Fully parallel once M2 is done. M7 in
  particular does not need M3 at all — a point the first draft of this
  graph got wrong.
- **M5 (Key management) is only partly gated on M4:** Task K1 needs only
  `internal/crypto`'s `Engine` interface and standard profile (C1) — not
  the weak-educational/PQC profiles (C2-C4) or the protocol-wiring task
  (C5). So K1-K4 can start as soon as C1 lands, in parallel with C2-C5,
  M3, M6, and M7. Only Task K2 (which re-verifies key consumers after
  C5's real multi-profile wiring) needs C5 specifically — everything else
  in M5 does not.
- **M8's five I-tasks (I1-I5):** touch disjoint files
  (`internal/harness/scenario_application.go`,
  `scenario_protocol.go`, `scenario_ledger.go`, `scenario_keystore.go`,
  `scenario_crypto.go` — see `TASK_BREAKDOWN.md`), share no state beyond
  the already-finalized `harness.Scenario`/`Oracle`/`PrivilegedAccess`
  interfaces from M7. Five-way parallel once M7 is done and each one's own
  upstream milestone is done (I5 can start as soon as M4.C2 lands, even
  before M5/M6 finish; I1 can start as soon as M3 lands, before M4
  finishes at all).
- **M10 (AI-agent) × M11 (Benchmarking):** disjoint packages
  (`internal/agent` vs `internal/benchmark`), both depend only on M7+M8,
  no shared files. Fully parallel.
- **M9 (Quantum):** parallel with literally everything from M2 onward —
  it only needs M1. The earliest safe point to assign it is immediately
  after Milestone 1, and it can land any time before M12 needs to run a
  full project build.
- **Not parallel:** M2's six tasks share `internal/backend` as a common
  integration point (T4 depends on T1-T3's interfaces being stable) — ship
  T1-T3 first, then T4, then T5-T6 sequentially. M3's four tasks similarly
  converge on S4 (the end-to-end test), so S1-S3 can be three-way parallel
  but S4 must wait for all three.

## Milestone-level critical path

The shortest chain that cannot be parallelized away, now that M7's
framework and M5's K1-K4 are correctly shown as largely parallel with
M3/M4/M6 rather than sequentially after them:

```
M1 -> M2 -> M3 -> C5 (needs both S2 from M3 and C1-C4 from M4, built in
                       parallel with M3) -> I2 (or any M8 task whose own
                       upstream milestone is by then also done, since M7
                       finished in parallel back at M2) -> M10 or M11 -> M12 -> M13
```

M4's C1-C4, M5's K1-K4 (mostly), M6, and M7 are **not** on the critical
path — each can complete in parallel with M3, gated only by M2. The only
milestone-level convergence points that cannot be parallelized away are:
M2 (everything depends on it), M3+M4 converging at C5, and M7+M3/M4/M5/M6
converging at whichever M8 task is chosen first. M9 never sits on the
critical path at all — it needs only M1 and feeds nothing upstream of
M12/P1.
