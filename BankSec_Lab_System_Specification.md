# BankSec Lab

## System Specification

**Document type:** System specification\
**Status:** Draft for architecture brainstorming and approval\
**Primary implementation language:** Go\
**Operating model:** Local, offline, controlled research environment\
**Data policy:** Synthetic data only

------------------------------------------------------------------------

## 1. System Overview

BankSec Lab is a modular, terminal-based banking security research
simulator. It provides a controlled environment in which a researcher
can operate a simulated banking system, configure vulnerable and
hardened security controls, execute bounded attack scenarios, observe
defensive behavior, and measure experimental outcomes.

The system is intended for academic research, security education, and
repeatable experimentation. It must operate locally and use synthetic
accounts, transactions, credentials, keys, and other test data. It must
not connect to real banking systems or target external infrastructure.

The system combines:

-   A simulated banking application and transaction ledger.
-   Security controls and cryptographic services.
-   Vulnerable and hardened configurations for controlled comparison.
-   An attack harness for executing approved, bounded scenarios against
    the simulator.
-   Audit and detection capabilities.
-   Benchmarking and exportable experimental results.
-   An AI-agent subsystem, initially capable of deterministic offline
    operation.
-   Small-scale educational simulations of selected quantum-related
    algorithms, where feasible.

### 1.1 Research objective

The system should support experiments that investigate how selected
application, protocol, data-integrity, key-management, cryptographic,
and AI-agent attack scenarios affect a simulated banking environment,
and how different defensive configurations prevent, detect, or limit
those effects.

The system must measure actual execution outcomes. It must not hardcode
attack success, detection, or benchmark values.

### 1.2 Intended users

-   Researchers conducting controlled security experiments.
-   Students learning banking-system security concepts.
-   Developers evaluating security controls in a reproducible simulator.

------------------------------------------------------------------------

## 2. Goals and Non-Goals

### 2.1 Goals

1.  Simulate core banking operations using synthetic data.
2.  Provide modular security and cryptographic components.
3.  Support controlled vulnerable-versus-hardened experiments.
4.  Implement an extensible interface for attack scenarios.
5.  Record security-relevant events and experimental outcomes.
6.  Produce reproducible benchmark results in machine-readable formats.
7.  Support deterministic, offline AI-agent experiments.
8.  Provide clearly labelled educational simulations of selected quantum
    algorithms.
9.  Maintain a testable, auditable, and maintainable Go codebase.

### 2.2 Non-goals

The system is not intended to:

-   Connect to real banks, payment networks, or financial service
    providers.
-   Process real money or real customer information.
-   Scan, exploit, or interact with external targets.
-   Store real credentials, production keys, or personal financial data.
-   Provide an uncontrolled autonomous attack platform.
-   Claim that a classical simulation is equivalent to execution on a
    quantum computer.
-   Replace production cryptographic libraries with custom cryptographic
    implementations.

------------------------------------------------------------------------

## 3. Scope and Safety Boundaries

All experiments must remain inside the local simulator and use synthetic
assets.

The attack harness must only interact with explicitly registered
simulator components. Each attack scenario must declare its
prerequisites, permitted actions, expected observations, and stopping
conditions.

The system must not include functionality for credential theft, malware
deployment, persistence, external scanning, or uncontrolled
exploitation. Demonstrations of weaknesses should be implemented as
bounded educational scenarios against intentionally vulnerable simulator
configurations.

Vulnerable configurations must be isolated and clearly labelled. They
must not be presented as safe for real-world deployment.

------------------------------------------------------------------------

## 4. High-Level Architecture

The following is a conceptual architecture. Process boundaries, storage
technology, and deployment details remain decisions for the
architecture-design phase.

``` mermaid
flowchart TD
    R[Researcher] --> CLI[Terminal Client / CLI]
    CLI --> P[Communication Protocol]
    P --> S[Banking Backend]

    S --> V[Database Vault / Ledger]
    S --> C[Cryptographic Engine]
    S --> K[Key Management]
    S --> A[Audit and Event Stream]

    H[Attack Harness] --> P
    H --> S
    H --> C
    H --> K
    H --> V

    AG[AI Agent Subsystem] --> H
    H --> B[Benchmark Runner]
    A --> B
    B --> O[JSON / CSV Results]
```

### 4.1 Architectural principles

-   Keep components modular and define explicit interfaces between them.
-   Separate normal banking operations from attack orchestration.
-   Make security configuration explicit and observable.
-   Ensure that benchmark results are derived from actual executions.
-   Keep the initial implementation local and offline.
-   Record important design decisions as Architecture Decision Records
    (ADRs).
-   Avoid premature commitment to unresolved implementation choices.

------------------------------------------------------------------------

## 5. Core System Components

### 5.1 Terminal Client

The terminal client is the researcher's primary interface.

Expected responsibilities:

-   Create and manage synthetic accounts.
-   Deposit and withdraw simulated funds.
-   Transfer funds between simulated accounts.
-   Display account balances.
-   Display transaction history.
-   Select security configurations.
-   Launch approved attack scenarios.
-   Run benchmarks.
-   Display and export results.

The CLI should validate input and display clear errors. It must not be
treated as a trusted security boundary; validation and authorization
must also occur in the backend.

### 5.2 Banking Backend

The backend implements the simulator's banking business logic.

Expected responsibilities:

-   Process account and transaction requests.
-   Validate transaction parameters.
-   Enforce account and operation rules.
-   Coordinate ledger updates.
-   Invoke cryptographic and key-management services.
-   Emit audit events.
-   Expose controlled interfaces to the attack harness.

Transactions should preserve the simulator's defined consistency and
integrity rules. The exact transaction model and concurrency strategy
should be finalized during architecture design.

### 5.3 Database Vault and Ledger

The storage layer holds synthetic banking data and transaction records.

Potential data includes:

-   Account identifiers and metadata.
-   Account balances or derived balance state.
-   Transaction records.
-   Ledger entries.
-   Security configuration metadata.
-   Key references or protected key material, depending on the selected
    design.
-   Audit and experiment metadata.

The system should make it possible to study data-integrity weaknesses in
a controlled way. The design must distinguish intentional vulnerable
behavior from the hardened storage behavior.

The database technology, schema, and whether vulnerable and hardened
modes share or isolate storage are open architecture decisions.

### 5.4 Communication Protocol

The communication layer defines how the CLI, backend, and research
components exchange requests and responses.

It should support experiments involving message validation,
authentication, integrity, replay resistance, and protocol-level
security properties.

Protocol weaknesses must be simulated within the local environment. The
design should document message formats, trust boundaries, validation
rules, and the security properties expected from each configuration.

### 5.5 Cryptographic Engine

The cryptographic engine provides cryptographic operations used by the
simulator.

Candidate algorithms and primitives include:

-   AES for symmetric encryption.
-   HMAC-SHA-256 for message authentication.
-   Ed25519 for digital signatures.
-   X25519 for key agreement.
-   Small-parameter Diffie--Hellman demonstrations for educational
    experiments.
-   ML-KEM and ML-DSA for post-quantum cryptography experiments, subject
    to library and implementation availability.

The system may expose multiple experimental profiles, such as weak
educational configurations, standard classical configurations, and
post-quantum configurations. Exact profiles must be finalized after
checking library support and defining the research methodology.

**Cryptographic implementation rule:** use established, maintained
libraries for real cryptographic primitives. Do not implement production
cryptography from scratch. Any intentionally weak or simplified
cryptographic construction must be clearly labelled as educational and
must never be confused with a secure implementation.

### 5.6 Key Management and Secret Store

This component manages keys and related metadata.

Expected responsibilities:

-   Generate or provision test keys.
-   Store and retrieve keys according to the selected security profile.
-   Support key rotation and revocation where applicable.
-   Enforce access boundaries.
-   Record key-management events.
-   Provide controlled weak-versus-hardened key-management scenarios.

The storage format, encryption-at-rest approach, key hierarchy, and
exact separation between the key store and database remain design
decisions.

### 5.7 Audit and Event Stream

The audit subsystem records security-relevant system activity.

An event may contain fields such as:

-   Event identifier.
-   Timestamp.
-   Event type.
-   Component.
-   Actor or simulated principal.
-   Operation.
-   Outcome.
-   Related transaction identifier.
-   Related attack or experiment identifier.
-   Relevant detection or response metadata.

Audit records should support filtering, export, and correlation with
benchmark results. The system should consider integrity protection for
audit data and should record failures as well as successful operations.

### 5.8 Attack Harness

The attack harness provides a controlled framework for registering and
executing attack scenarios against the simulator.

Each scenario should define:

-   Unique identifier and name.
-   Attack category.
-   Description and research objective.
-   Required simulator configuration.
-   Preconditions.
-   Permitted actions.
-   Execution procedure.
-   Expected observations.
-   Success and failure criteria.
-   Stopping conditions.
-   Evidence and metrics to collect.

The harness must not assume that an attack succeeded. It must determine
the result from the target simulator's actual state and observable
responses.

### 5.9 Benchmark Runner

The benchmark runner coordinates repeatable experiments and collects
measurements.

It should support:

-   Running one or more attack scenarios.
-   Comparing vulnerable and hardened configurations.
-   Repeating experiments with recorded seeds where applicable.
-   Recording successful and failed attempts.
-   Exporting raw results to JSON and CSV.
-   Producing summary comparisons without discarding raw measurements.

Benchmark methodology must define warm-up behavior, repetitions, timing
boundaries, hardware/software context, and aggregation rules before
results are used in research claims.

### 5.10 AI-Agent Subsystem

The AI-agent subsystem explores how an automated agent can interact with
the simulator and attack harness.

The initial implementation should be deterministic and offline. It
should have:

-   A defined observation format.
-   A bounded set of permitted actions.
-   Explicit action and execution limits.
-   Decision and action logs.
-   Reproducible behavior where possible.
-   Clear separation between agent decisions and attack execution.

An optional LLM-backed agent may be considered later. It must remain
disabled by default unless explicitly configured, and it must not
receive unrestricted system or network access.

### 5.11 Quantum-Algorithm Simulation Subsystem

This subsystem may provide small-scale educational simulations of
selected quantum-related algorithms, such as Shor's and Grover's
algorithms.

The implementation must clearly distinguish:

-   Classical computation simulating selected algorithmic steps.
-   Theoretical quantum-computing properties and complexity.
-   Actual execution on quantum hardware, which is not implied by a
    local classical simulation.

Use small parameters suitable for demonstration. Do not make claims of
practical quantum attacks against real banking cryptography based on toy
simulations.

------------------------------------------------------------------------

## 6. Banking Functionality

The simulator should provide a minimal but coherent set of banking
operations:

1.  Account creation.
2.  Deposit.
3.  Withdrawal.
4.  Transfer between accounts.
5.  Balance inquiry.
6.  Transaction-history inquiry.

The same core business functionality should be available in vulnerable
and hardened configurations wherever practical. Differences between
configurations should arise from explicitly selected security controls,
not from unrelated changes to the banking behavior.

The specification does not yet define detailed business rules such as
overdraft policy, transaction limits, account states, or reversal
behavior. These should be decided during requirements refinement.

------------------------------------------------------------------------

## 7. Security Modes

The simulator should support at least two experimental security
configurations.

### 7.1 Vulnerable mode

Vulnerable mode enables deliberately weakened or omitted controls for
approved educational experiments. Each weakness must be documented,
bounded, and isolated within the simulator.

### 7.2 Hardened mode

Hardened mode enables the corresponding defensive controls. It should
provide a meaningful comparison target for the same attack scenario.

### 7.3 Comparison requirements

-   Identify the active mode in CLI output and experiment records.
-   Keep configuration differences explicit and documented.
-   Use equivalent initial synthetic data when comparing modes.
-   Record configuration and seed information with results.
-   Do not claim a defense worked unless the execution evidence supports
    that conclusion.

------------------------------------------------------------------------

## 8. Attack Research Categories

The framework may organize experiments into the following categories.

### 8.1 Application-level scenarios

Investigate weaknesses in business logic, authorization, validation, and
transaction handling within the simulator.

### 8.2 Protocol-level scenarios

Investigate message integrity, authentication, replay resistance,
request validation, and related communication properties.

### 8.3 Database and ledger scenarios

Investigate unauthorized or inconsistent changes to synthetic records,
ledger integrity, and detection of tampering.

### 8.4 Key-management scenarios

Investigate weak key storage, access-control failures, lifecycle
weaknesses, and the effects of key rotation or revocation controls.

### 8.5 Cryptographic scenarios

Compare explicitly weak educational configurations with established
cryptographic protections. Document assumptions and limitations for
every experiment.

### 8.6 AI-agent scenarios

Study how a bounded agent selects actions, uses observations, and
interacts with vulnerable or hardened simulator components. Record the
agent's reasoning trace or decision metadata to the extent supported by
the implementation.

------------------------------------------------------------------------

## 9. Main Workflows

### 9.1 Normal banking workflow

1.  Researcher starts the local application.
2.  Researcher selects or confirms the active security configuration.
3.  Researcher creates or selects synthetic accounts.
4.  Researcher performs a banking operation.
5.  Backend validates and processes the request.
6.  Storage and ledger state are updated according to the transaction
    rules.
7.  Audit events are recorded.
8.  CLI displays the result.

### 9.2 Attack-experiment workflow

1.  Researcher selects an approved attack scenario.
2.  System checks scenario prerequisites and active configuration.
3.  Harness initializes the experiment and records its metadata.
4.  Scenario performs only its permitted actions against the local
    simulator.
5.  Simulator state and defensive responses are observed.
6.  Harness determines the outcome from evidence.
7.  Audit and benchmark data are collected.
8.  Raw results are saved and made available for inspection.

### 9.3 Comparative benchmark workflow

1.  Prepare a known synthetic dataset and experiment configuration.
2.  Run the scenario against vulnerable mode.
3.  Reset or restore an equivalent initial state.
4.  Run the same scenario against hardened mode.
5.  Repeat runs according to the benchmark methodology.
6.  Preserve each raw result.
7.  Generate comparative summaries.
8.  Export results to JSON and CSV.

------------------------------------------------------------------------

## 10. Data Model Candidates

The following are conceptual entities, not a finalized database schema.

  Entity               Purpose
  -------------------- ------------------------------------------------
  `Account`            Synthetic account identity and metadata
  `Transaction`        Banking operation request and outcome
  `LedgerEntry`        Record of a balance-affecting event
  `ProtocolMessage`    Message exchanged between simulator components
  `CryptoProfile`      Active cryptographic configuration
  `KeyRecord`          Key metadata and lifecycle state
  `AuditEvent`         Security and operational event
  `AttackDefinition`   Registered attack scenario metadata
  `AttackExecution`    One execution of an attack scenario
  `BenchmarkResult`    Measurements and outcome of an experiment
  `AgentObservation`   Information presented to the AI agent
  `AgentAction`        Action selected by the AI agent

The final schema should be derived from the approved workflows and
consistency requirements.

------------------------------------------------------------------------

## 11. Benchmarking and Measurement

The system should collect measurements that are meaningful for the
selected experiment. Candidate metrics include:

  -----------------------------------------------------------------------
  Metric                              Meaning
  ----------------------------------- -----------------------------------
  `attack_id`                         Identifier of the scenario

  `target_configuration`              Vulnerable or hardened
                                      configuration

  `attack_type`                       Scenario category

  `success`                           Evidence-based outcome

  `execution_time_ms`                 Measured execution duration

  `time_to_compromise`                Time until the defined compromise
                                      condition is met, if applicable

  `data_leaked_bytes`                 Amount of synthetic data exposed,
                                      if applicable

  `records_compromised`               Number of synthetic records
                                      affected

  `detection_latency`                 Time between the defined attack
                                      event and detection

  `attempts`                          Number of attempts made

  `computational_cost`                Defined measure of computational
                                      work

  `memory_usage`                      Memory measurement, if reliably
                                      available

  `seed`                              Random seed used for
                                      reproducibility, when applicable
  -----------------------------------------------------------------------

Not every metric applies to every scenario. The system should represent
unavailable or inapplicable measurements honestly rather than filling
them with fabricated values.

### 11.1 Experimental integrity

-   Preserve raw run-level results.
-   Record the software version and relevant environment information.
-   Record seeds and configuration.
-   Include failed and inconclusive runs.
-   Define success criteria before executing an experiment.
-   Do not hardcode benchmark outcomes.
-   Document measurement limitations and sources of noise.
-   Use repeated runs and appropriate summary statistics.

------------------------------------------------------------------------

## 12. Non-Functional Requirements

### 12.1 Modularity

Components should have clear responsibilities and stable interfaces.

### 12.2 Reproducibility

Experiments should be repeatable with recorded configurations, inputs,
and seeds where applicable.

### 12.3 Observability

The system should expose enough logs, audit events, and result metadata
to explain what happened during an experiment.

### 12.4 Reliability

Banking operations and experiment execution should handle invalid input,
errors, and partial failures predictably.

### 12.5 Portability

The initial system should run locally on commonly available development
environments supported by Go.

### 12.6 Maintainability

Use idiomatic Go, clear package boundaries, focused tests, and
documented design decisions.

### 12.7 Isolation

Attack scenarios must be restricted to the local simulator and synthetic
data.

### 12.8 Performance

Performance should be measured rather than assumed. Avoid premature
optimization before establishing representative workloads.

------------------------------------------------------------------------

## 13. Technology and Development Constraints

Current constraints and preferences:

-   **Primary language:** Go.
-   **Interface:** Terminal CLI.
-   **Execution:** Local and offline by default.
-   **Data:** Synthetic data only.
-   **Storage:** To be selected through an architecture decision.
-   **Cryptography:** Maintained libraries and standard implementations
    where applicable.
-   **Configuration:** A documented configuration format, to be
    selected.
-   **Results:** JSON and CSV exports.
-   **Testing:** Go unit, integration, security-behavior, and benchmark
    tests.
-   **Version control:** Git; remote publication requires explicit
    approval.

Recommended verification commands include:

``` bash
gofmt -w .
go vet ./...
go test ./...
go test -race ./...
go build ./...
```

The exact commands and CI workflow should be adapted to the final
repository structure.

------------------------------------------------------------------------

## 14. Testing Strategy

Testing should verify real behavior, not merely that code paths execute.

### 14.1 Unit tests

Test individual packages, validation rules, cryptographic wrappers, and
business logic.

### 14.2 Integration tests

Test complete banking workflows across the CLI/backend/storage
boundaries selected by the architecture.

### 14.3 Security-behavior tests

Verify that each intentionally vulnerable scenario demonstrates its
documented behavior and that hardened controls produce the expected
defensive behavior.

### 14.4 Attack-harness tests

Verify prerequisites, action boundaries, stopping conditions, result
classification, and evidence collection.

### 14.5 Benchmark tests

Verify that measurements are collected from actual executions, raw
results are preserved, and JSON/CSV output is valid.

### 14.6 Concurrency and race tests

Use Go's race detector and targeted concurrency tests where shared state
or concurrent operations exist.

### 14.7 Reproducibility tests

Verify that deterministic scenarios produce consistent outcomes under
equivalent configurations and seeds.

------------------------------------------------------------------------

## 15. Documentation Requirements

The repository should maintain at least:

  -----------------------------------------------------------------------
  Document                            Purpose
  ----------------------------------- -----------------------------------
  `SYSTEM_SPECIFICATION.md`           System purpose, scope, behavior,
                                      and requirements

  `ARCHITECTURE.md`                   Approved component architecture and
                                      interfaces

  `THREAT_MODEL.md`                   Assets, trust boundaries, threats,
                                      and safety constraints

  `ATTACK_SURFACES.md`                Simulator attack surfaces and
                                      scenario boundaries

  `CRYPTOGRAPHY.md`                   Algorithms, libraries, profiles,
                                      and limitations

  `BENCHMARK_METHODOLOGY.md`          Metrics, procedures, repetitions,
                                      and analysis rules

  `IMPLEMENTATION_PLAN.md`            Ordered development milestones and
                                      tasks

  `TEST_STRATEGY.md`                  Test levels, coverage goals, and
                                      verification procedures

  `ADRs/`                             Records of important architecture
                                      decisions
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 16. Open Architecture Decisions

The following issues must be resolved during brainstorming and
architecture design. This document intentionally does not pretend they
have already been decided.

1.  **Process boundaries:** Should the simulator be a single Go process
    with modular packages, or should selected components run as separate
    local processes?
2.  **Storage:** Which database or embedded storage technology best
    supports the required ledger behavior, experiments, and portability?
3.  **Mode isolation:** How should vulnerable and hardened
    configurations be separated and reset between experiments?
4.  **Protocol design:** What message format and transport are
    appropriate for the research goals?
5.  **Attack execution:** Should scenarios run in-process, in isolated
    subprocesses, or through another bounded execution model?
6.  **Detection architecture:** Which controls detect attacks, and how
    are detection events correlated with attack execution?
7.  **Cryptographic profiles:** Which algorithms and library versions
    are feasible and appropriate for the target environment?
8.  **Post-quantum scope:** Which PQC experiments are supported by
    stable libraries, and what comparisons are scientifically
    meaningful?
9.  **Quantum simulation methodology:** Which small-parameter
    demonstrations are feasible and what claims can they legitimately
    support?
10. **AI-agent interface:** What observations, actions, budgets, and
    stopping conditions should the initial deterministic agent have?
11. **Benchmark methodology:** Which metrics are essential for each
    experiment, and how should timing and repetitions be controlled?
12. **Data consistency:** What transaction and ledger invariants must
    hold in each mode?

Each significant decision should be recorded in an ADR with context,
alternatives, decision, and consequences.

------------------------------------------------------------------------

## 17. Suggested Development Sequence

The following sequence is a planning recommendation, not an assertion
that implementation has begun or that every milestone is mandatory.

1.  Requirements clarification and threat-model review.
2.  Architecture decisions and package/interface design.
3.  Go project foundation, CLI skeleton, configuration, and logging.
4.  Core banking operations and ledger behavior.
5.  Storage implementation and transaction consistency.
6.  Security-mode configuration and defensive-control interfaces.
7.  Cryptographic engine and key-management integration.
8.  Audit and event collection.
9.  Attack-harness interfaces and scenario registration.
10. Initial application, protocol, storage, and key-management
    scenarios.
11. Benchmark runner and JSON/CSV result export.
12. Quantum-related educational simulations, if justified by scope and
    feasibility.
13. Deterministic AI-agent subsystem.
14. Integration, security review, reproducibility checks, and
    documentation.
15. Optional external LLM integration only after the offline baseline is
    reliable.

------------------------------------------------------------------------

## 18. Definition of Done

A feature should not be considered complete merely because code has been
written.

A feature is complete when:

-   Its behavior and boundaries are documented.
-   Relevant tests exist and pass.
-   Errors and invalid inputs are handled.
-   Security-sensitive behavior has been reviewed.
-   Logs or audit events are present where required.
-   The implementation is integrated with the intended interfaces.
-   Verification commands have been run and their results reported.
-   Any known limitations are documented.

For an attack scenario specifically:

-   The target and prerequisites are explicit.
-   The scenario is bounded to the local simulator.
-   Success and failure criteria are defined.
-   The outcome is derived from observed behavior.
-   Evidence and applicable metrics are recorded.
-   Both successful and unsuccessful executions are represented
    honestly.

------------------------------------------------------------------------

## 19. Final System Vision

BankSec Lab should become a reproducible, modular research environment
in which a researcher can:

1.  Operate a synthetic banking system.
2.  Select a documented security configuration.
3.  Execute a bounded attack experiment against the local simulator.
4.  Observe system behavior, defensive responses, and audit evidence.
5.  Compare vulnerable and hardened configurations.
6.  Measure and export actual experimental outcomes.
7.  Reproduce the experiment using recorded inputs and configuration.

The project's credibility depends on sound experimental design, honest
measurement, clear separation between educational simulations and real
cryptographic implementations, and strict containment within the local
synthetic environment.
