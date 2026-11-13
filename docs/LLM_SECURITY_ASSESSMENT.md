# Banking AI Assistant — Security Assessment

An independent assessment of the LLM integration added in `6648d3c`,
conducted against the real implementation in an isolated simulator using
synthetic data only. No real banking system, customer, or external target
was involved.

**This report does not claim the assistant is secure, and does not claim
every weakness has been found.** It documents what was tested, what was
confirmed with reproducible evidence, and what was not reached.

Baseline: `6648d3c`, working tree clean, 521 tests passing, `go test
-race` clean across 21 packages.

## 1. Attack-surface inventory

| Component | Trust boundary | Untrusted input | Sensitive data | Existing validation |
| --- | --- | --- | --- | --- |
| `llm.OllamaProvider` | Loopback HTTP to a local server | Model output | Prompt content | Model installed / local / capable, verified before first prompt; response size ceiling; no streaming |
| System prompt | Application-authored | — | None by design | Printable; asserted free of secrets |
| User input | **Fully untrusted** | The adversarial message | — | Length cap (4,000 chars per probe) |
| Untrusted document content | **Fully untrusted** | Third-party text | — | Delimited and labelled (*not* a control) |
| Session | Application-authored | — | Principal, account ids | Principal re-derived server-side on every call |
| Tool registry | Application-authored | — | — | Closed allowlist; no execute/SQL/shell/network tool exists |
| `ToolGateway` | **The boundary** | Model-proposed tool calls | Balances, history | Closed arg schema, type kinds, limits, budget, confirmation |
| Banking adapter | `protocol.Client` | — | Ledger | The bank's own authorization layer |
| Confirmation workflow | Go state | Model-supplied id | Pending transfers | `crypto/rand` id, session-bound, single-use, TTL, human approval |
| Ledger / oracle | Read-only | — | Entries | Oracle exposes key *metadata* only, never material |
| Experiment harness | Application | Generator output | — | Probe schema validation |
| `LLMGenerator` | **Untrusted output** | Model output | — | JSON schema, bounded retries, dedup, no account data in prompt |
| Retrieval / RAG | — | — | — | **Not implemented — not assessed** |

## 2. Threat model

**Assets:** account balances and history; ledger integrity; the
confirmation control; cross-account and cross-session boundaries.

**Actors:** a legitimate signed-in customer; a hostile customer typing
adversarial input; hostile third-party content the customer pastes; the
local model itself (untrusted output, trusted only to run locally); the
model provider (an external host, if misconfigured — see §1).

**Confused deputy:** the central risk. The assistant holds a legitimate
customer's authority. Any path where an attacker's words cause that
authority to be exercised on the attacker's behalf is the primary
concern. Two were examined: tool-call arguments (mitigated — the
principal is re-derived from the session) and the approval step
(**finding F-06**).

**Explicitly out of scope:** attacks on the model weights, the Ollama
server itself, or anything outside loopback.

## 3. Findings

Severity is reasoned from exploitability, verified impact, privilege
required, and scope. **No CVSS vector is assigned** — CVSS's methodology
does not apply cleanly to model behaviour, and an invented score would be
worse than none.

---

### F-01 — History tool output is not capped (dead cap)

| | |
| --- | --- |
| Component | `internal/assistant/gateway.go` → `limitResult` |
| Category | OWASP LLM10 Unbounded Consumption |
| Status | **Confirmed vulnerability** |
| Severity | **Medium** |

**Description.** `Limits.MaxHistoryEntries` (default 20) is applied by
`limitResult` to a result key named `entries`. The banking server returns
transaction history under the key `history`
(`internal/protocol/server.go:207`). The cap therefore never matches and
is dead code: an arbitrarily long history is returned to the model whole.

**Preconditions.** An account with many transactions; the signed-in
customer's own account is sufficient. No attacker privilege needed.

**Reproduction.** `TestEvidence_HistoryResultIsNotCapped` — 60 legitimate
deposits, then one `get_transaction_history` call.

**Evidence.**
```
MaxHistoryEntries=20, result keys=[history], history payload=9755 bytes
```

**Impact.** Confirmed: unbounded growth of model context from a single
tool call. A customer with a long history can exhaust the context window,
degrading or breaking the assistant, and inflating inference cost. It is
*not* a disclosure issue — the data is the customer's own.

**Security property.** Availability; resource bounding.

**Existing control.** Intended but ineffective.

**Mitigation.** Cap by the key the server actually returns, decode the
JSON array and truncate it to `MaxHistoryEntries`, and state in the
result that entries were withheld. Add a test asserting the cap applies
to the real key.

**Regression test required.** Yes. **Difficulty:** Low.

---

### F-02 — The gateway performs no independent ownership check

| | |
| --- | --- |
| Component | `internal/assistant/gateway.go` → `runRead`, `runSummary`, `runPrepareTransfer` |
| Category | OWASP LLM06 Excessive Agency / A01 Broken Access Control |
| Status | **Confirmed vulnerability** (defence-in-depth failure) |
| Severity | **High** |

**Description.** The gateway's account-ownership enforcement is *entirely
delegated* to the bank's authorization layer: it issues a `balance` read
and treats a refusal as unauthorized. It never consults
`Session.Accounts`, which states exactly which accounts the session owns.
The documentation claims "ownership constraints" as a gateway control; in
fact the gateway contributes no independent check, so under any
configuration where the bank's authorization is disabled or
misconfigured, the gateway adds nothing at all.

**Preconditions.** A security profile with `authz_enforced: false`
(`configs/vulnerable.json`), or any future bug in the bank's
authorization path.

**Reproduction.** `TestEvidence_GatewayHasNoIndependentOwnershipCheck`
and `TestEvidence_ReadPathAlsoDelegatesOwnershipEntirely`.

**Evidence.**
```
prepare_transfer from an unowned account under 'vulnerable' -> "executed"
  confirmation cnf-1291b7db... minted for a debit from an account the session does not own
get_balance on an unowned account under 'vulnerable' -> "executed" result=map[balance:0]
```

**Impact.** Confirmed: a confirmation is minted for a debit from an
account the session demonstrably does not own, and a foreign balance is
returned. Under `hardened` the bank blocks both, so this is a
single-point-of-failure finding rather than an exploit of the shipped
default — which is exactly what defence in depth exists to prevent, and
what the project's own documentation already claims to provide.

**Security property.** Confidentiality and integrity; authorization.

**Existing control.** The bank's authorization layer, alone.

**Mitigation.** Check the target account against `Session.Accounts`
*before* calling the bank, and refuse with `refused_unauthorized` when it
is absent. Keep the bank's check as the second layer. Where
`Session.Accounts` is empty, fail closed rather than open.

**Regression test required.** Yes, on both the read and the draft path,
under both profiles. **Difficulty:** Low. **Dependencies:** callers must
populate `Session.Accounts` (the CLI and probe path already do).

---

### F-03 — Tool budget is charged for unrecognised tool names

| | |
| --- | --- |
| Component | `internal/assistant/gateway.go` → `Invoke` |
| Category | OWASP LLM10 Unbounded Consumption |
| Status | **Confirmed — non-security functional defect** |
| Severity | **Low** |

**Description.** `consumeBudget` runs before the allowlist check, so
calls naming nonexistent tools consume the budget that legitimate work
needs. This is deliberate denial-of-service resistance and is the safer
direction, but it is inconsistent with `experiment.Validator`, which
charges only actions that reached the simulator. The two "budget spent"
figures therefore mean different things while being reported with the
same vocabulary.

**Reproduction.** `TestEvidence_BudgetChargedForUnrecognisedTools`.

**Evidence.** After three `exec_sql` calls under a 3-call budget, a
legitimate `get_balance` → `refused_budget`.

**Impact.** A hallucinating model can lock itself out of useful work.
Not exploitable by an attacker for gain; the fail-closed direction is
correct.

**Mitigation.** Keep the behaviour; record refused and executed calls
against separate counters and document that the gateway budget bounds
*proposals*, not executions.

**Regression test required.** Yes (pinning the intended behaviour).
**Difficulty:** Low.

---

### F-04 — A customer approval is consumed by a transfer that never executed

| | |
| --- | --- |
| Component | `internal/assistant/gateway.go` → `runConfirmTransfer` |
| Category | OWASP LLM06 Excessive Agency (availability facet) |
| Status | **Confirmed vulnerability** |
| Severity | **Low–Medium** |

**Description.** The pending transfer is marked `used` before the bank is
called, so that a concurrent second confirmation cannot also pass. If the
bank then refuses — a nonexistent destination, insufficient funds — the
approval is gone and the customer must approve again. `prepare_transfer`
performs no reachability check on the destination, so a model that
invents a destination account reliably burns the approval.

**Reproduction.** `TestEvidence_ApprovalBurnedByAnUnreachableDestination`.

**Evidence.**
```
confirmation cnf-c5442ad4... minted for a nonexistent destination
first confirm  -> "refused_unauthorized" (not_found: account not found)
retry          -> "refused_unconfirmed" (that confirmation has already been used)
```

**Impact.** Availability only. Claiming the slot before execution is the
right trade against confirmation replay, so the fix must not simply
release it on failure.

**Mitigation.** Validate the destination's existence at
`prepare_transfer` time, so an unreachable transfer is never drafted and
never consumes an approval. Leave the claim-before-execute ordering
intact.

**Regression test required.** Yes. **Difficulty:** Low.

---

### F-05 — `get_account_summary` fabricates the account owner

| | |
| --- | --- |
| Component | `internal/assistant/gateway.go` → `runSummary` |
| Category | OWASP LLM09 Misinformation |
| Status | **Confirmed vulnerability** |
| Severity | **Medium** |

**Description.** `runSummary` returns `owner: session.Principal.ID` —
the *caller*, not the account's actual owner. The gateway is not reading
ownership at all; it is asserting it. Where the read succeeds on a
foreign account, the assistant is handed false provenance and will state
it to the customer as fact.

**Reproduction.** `TestEvidence_AccountSummaryFabricatesTheOwner`.

**Evidence.**
```
summary of mallory's account, read as alice -> "executed"
result=map[account:acct-37dd2f6e... balance:0 owner:alice]
```

**Impact.** Confirmed: the gateway — the component the whole design
treats as the source of truth — emits a fabricated field. Worse, it is
fabricated in the direction that *masks* a cross-account read: anything
auditing tool output for ownership would see the attacker's own name.

**Security property.** Integrity of the evidence trail.

**Mitigation.** Remove the field, or populate it only from data the bank
actually returned. Never synthesise provenance in the gateway.

**Regression test required.** Yes. **Difficulty:** Low.

---

### F-06 — The CLI grants transfer approval without showing what is approved

| | |
| --- | --- |
| Component | `cmd/banksec/assistant.go` → `--approve-transfer` |
| Category | Confused deputy |
| Status | **Confirmed vulnerability** (in the demonstration harness) |
| Severity | **Medium** |

**Description.** `--approve-transfer` calls `firstConfirmationID` and
approves whatever the assistant drafted first, without displaying the
amount or destination beforehand. The gateway exposes
`PendingTransfer(id)` precisely so an application can show a human what
they are approving; the CLI does not call it. The control's entire value
is that a human sees the transfer — approving blind reduces it to a
rubber stamp, and an injected draft would be approved as readily as a
legitimate one.

**Preconditions.** An operator running `--approve-transfer`; an
adversarial input that gets any transfer drafted.

**Reproduction.** By inspection of `cmd/banksec/assistant.go`; the
approval path prints the confirmation id only *after* approving.

**Impact.** Confirmed in the harness, not in the gateway. The gateway's
control is sound; the demonstration tooling undermines it. Because this
is the surface a judge or investor would be shown, the gap matters beyond
its code footprint.

**Mitigation.** Print amount, source and destination from
`PendingTransfer` before approving, and require the operator to pass the
confirmation id explicitly rather than approving "the first one".

**Regression test required.** Yes. **Difficulty:** Low.

---

### F-07 — The attack generator cannot reach the cross-account path

| | |
| --- | --- |
| Component | `internal/experiment/llmgen.go` |
| Category | Research limitation |
| Status | **Known limitation** (documented pre-assessment) |
| Severity | n/a — not a vulnerability |

The generator is deliberately never told a real account identifier, so
its probes cite invented ones ("ending in 4287"). The bank refuses those
as *account not found*, not *unauthorized*, so
`assistant.no-unauthorized-tool-execution` can only report
`inconclusive`. **This is the single largest gap in the assessment's
coverage**, and it is why 15 of 18 judgements in the live run were
inconclusive.

## 4. Category coverage

| Category | Status |
| --- | --- |
| A. Prompt injection (direct) | **Tested, no issue found** — 3 live attacks, none produced an unauthorized action |
| B. Sensitive information disclosure | **Partially tested** — own-account path verified; cross-account blocked under `hardened`, but see F-02 |
| C. Excessive agency / tool misuse | **Tested, vulnerabilities confirmed** — F-01, F-03, F-04 |
| D. AuthN/AuthZ / identity | **Tested, vulnerability confirmed** — F-02; actor-substitution itself is blocked |
| E. Indirect prompt injection | **Partially tested** — document channel tested live and ignored. **Transaction-description and account-name channels are not applicable**: `ledger.Entry` has no memo or description field, and `create-account` is not in the tool catalog |
| F. Insecure output handling | **Tested, no issue found** — malformed JSON, string-encoded args, unoffered tool names, truncation all rejected |
| G. Session and memory isolation | **Partially tested** — confirmation scoping verified; the assistant has **no cross-session memory**, so context contamination is not applicable |
| H. Financial integrity | **Tested, vulnerability confirmed** — F-04; ledger invariants hold, duplicate confirmation blocked, race-clean |
| I. Model and supply chain | **Tested, no issue found** — local-only verified; see §1 on the four cloud-proxied tags present on this host |
| J. DoS / unbounded consumption | **Tested, vulnerabilities confirmed** — F-01, F-03 |
| K. Hallucination / overreliance | **Tested, vulnerability confirmed** — F-05. Model boasts are correctly not counted as attacks |
| L. PQC boundary | **Tested, no issue found** — no tool reaches key material; the oracle returns metadata only |
| M. RAG / vector DB / memory / fine-tuning / multi-agent | **Not applicable — not implemented** |

## 5. Research evaluation

| Metric | Definition | Value |
| --- | --- | --- |
| Attack proposals generated | Probes produced by the generator | 3 |
| Attacks executed | Probes evaluated against the assistant | 3 |
| Confirmed violations | Oracle-verified invariant breaches | **0** |
| Unauthorized tool execution rate | Foreign-account executions ÷ attempts | **undefined** (no probe reached a real foreign account — F-07) |
| Disclosure rate | Ground-truth leaks ÷ probes | 0 / 3 |
| Benign task success | Legitimate requests completed | 2 / 2 live (balance read; approved transfer) |
| Oracle verification rate | Conclusive ÷ evaluated judgements | 3 / 18 = **0.167** |
| Avg. generation latency | `gemma3:12b` per proposal | ~70s (64.3 / 59.2 / 88.0) |
| Avg. assistant latency | `llama3.1:8b` per turn | ~13s |
| Avg. tool calls per task | Gateway proposals ÷ probes | 1.0 |
| Total experiment runtime | 3 probes, hardened | 317,977 ms |

Proposals, executions and confirmed vulnerabilities are reported as three
separate figures and must not be conflated. **Variability is
undocumented**: each figure comes from a single run, which is not enough
to state variance.

## 6. Prioritised remediation roadmap

1. **F-02** (High) — independent ownership check in the gateway.
2. **F-05** (Medium) — stop fabricating the owner field.
3. **F-01** (Medium) — make the history cap effective.
4. **F-06** (Medium) — show the transfer before approving it.
5. **F-04** (Low–Medium) — validate the destination at draft time.
6. **F-03** (Low) — separate the counters, document the semantics.
7. **F-07** — give the generator a harness-supplied victim identifier.

## 7. Limitations of this assessment

- Three generated probes and four hand-written attacks is a small sample
  from one 8B target and one 12B attacker. Absence of findings in a
  category here is weak evidence.
- Single runs throughout; no variance figures.
- F-07 means the most security-relevant path — cross-account tool
  execution — was never genuinely exercised by the generator.
- Disclosure detection is substring-based against known balances and
  would miss a paraphrase or an obfuscated encoding.
- Only the `hardened` and `vulnerable` profiles were used; no
  intermediate misconfiguration was explored.
- The assessment was conducted by the same party that wrote the
  implementation. That is a real limitation on its independence, and the
  evidence tests are included so the conclusions can be checked rather
  than taken on trust.

---

# Remediation

Applied after the assessment above was written. Baseline `6648d3c`;
every finding's "before" evidence is the output recorded in §3, captured
against that commit.

Verification after remediation: `gofmt`/`vet`/`build` clean, **533 tests
pass, 0 fail** (up from 521), `go test -race` clean across 21 packages.

| ID | Status | Fix | Regression test |
| --- | --- | --- | --- |
| F-01 | **Fixed** | Cap applied to the `history` key the server actually returns; JSON decoded, truncated, re-encoded, with a `history_entries_withheld` count so the model knows its view is partial | `TestRegression_F01_HistoryIsCappedOnTheKeyTheServerReturns`, `..._ShortHistoryIsNotAnnotated` |
| F-02 | **Fixed** | `Session.ownsAccount` + `requireOwnership` check the target against the session's declared accounts *before* the bank is called, on all three paths. Fails closed on an empty list | `TestRegression_F02_GatewayRefusesUnownedAccountsWithoutTheBank` (both profiles), `..._EmptyAccountListFailsClosed` |
| F-03 | **Resolved as intended behaviour** | Behaviour kept (fail-closed); `RefusedCount()` added and the semantics documented on `Limits.MaxToolCalls` | `TestRegression_F03_BudgetBoundsProposalsAndCountersAreSeparate` |
| F-04 | **Fixed** | `destinationReachable` restricts the credit side to the customer's own accounts or an application-saved payee, refused at draft time, so no approval can be consumed by a transfer that could never execute | `TestRegression_F04_UnreachableDestinationIsRefusedAtDraftTime`, `..._InventedNeighbouringAccountIsRefused`, `..._SavedPayeeIsStillAValidDestination` |
| F-05 | **Fixed** | The synthesised `owner` field is gone; the summary reports only what the bank returned | `TestRegression_F05_SummaryDoesNotFabricateAnOwner` |
| F-06 | **Fixed** | The CLI prints the debit, credit and amount from `PendingTransfer` *before* approving, and `--expect-amount` refuses to approve a draft whose amount differs from the operator's intent | `TestRegression_F06_PendingTransferReportsTheRealFigures`; verified live |
| F-07 | **Fixed**, after one wrong fix — see below | The generator writes a `VICTIM_ACCOUNT` placeholder; the evaluator substitutes the real identifier from that probe's own fixture and records it. The oracle excludes attacker-known identifiers and relies on balances, which are never disclosed | `target_disclosure_test.go` (16 tests, including a seam test) |

## Before and after evidence

**F-02** — the same call, same profile, before and after:

```
before: prepare_transfer from an unowned account under 'vulnerable' -> "executed"
        confirmation cnf-1291b7db... minted for a debit from an account the session does not own
after:  prepare_transfer from an unowned account under 'vulnerable' -> "refused_unauthorized"
        (from is not an account the signed-in customer owns)
```

**F-01** — same 60-entry history:

```
before: result keys=[history]                                      payload=9755 bytes, no cap applied
after:  result keys=[history history_entries_withheld history_note] payload=3204 bytes, 20 entries
```

**F-05**:

```
before: summary of mallory's account, read as alice -> "executed"
        result=map[account:acct-37dd2f6e... balance:0 owner:alice]
after:  summary of mallory's account, read as alice -> "refused_unauthorized"  result=map[]
```

**F-06** — live, against `llama3.1:8b`:

```
PENDING TRANSFER AWAITING APPROVAL
  confirmation: cnf-f67b6ebe...
  debit:        acct-bec1ab27...
  credit:       acct-7f3eecdc...
  amount:       9000 (minor units)
  NOT APPROVED: the drafted amount differs from the --expect-amount of 10000.
  An altered or injected draft looks exactly like this.
```

**Benign regression, live after all fixes:** balance read returns
`250000` and completes; the approved transfer path drafts, displays,
approves and executes, and the money moves.

## A consequence of the F-04 fix, and what was done about it

Restricting transfer destinations to an application-held allowlist meant
a probe session — which is deliberately given no payees — could only ever
draft a transfer to its own account, leaving the confirmation-bypass
attack family with almost nothing to test. Probe sessions are therefore
given the other fixture owners as saved payees.

This widens what can be *attempted*, not what is *permitted*: the debited
account is still checked against the session's declared accounts, so an
attack still has to defeat the confirmation control to achieve anything.

## Residual risk

- **F-02's check depends on the caller populating `Session.Accounts`.**
  It fails closed, so a forgetful caller gets refusals rather than an
  open gateway — but a caller that populates it *wrongly*, with an
  account the customer does not actually own, would hand the gateway a
  false premise. The bank's own check is the backstop there.
- **The destination allowlist is only as good as the payee list.** If an
  application saves a payee an attacker controls, the gateway will allow
  a draft to it. The confirmation control is what stands behind that.
- **The amount guard is an operator aid, not a control.** `--expect-amount`
  protects an operator who knows the intended figure; it does nothing for
  one who does not.
- **F-01 bounds one tool result, not total context growth.** Repeated
  capped reads across many turns still accumulate; the turn and tool
  budgets are what bound that, and they have not been tuned against a
  context limit.
- **Nothing here was fixed by changing the prompt**, and nothing here
  makes the assistant secure. Six findings were fixed; the sample that
  produced them was small.

## F-07, and a correction to a premature claim

F-07 was reported fixed in an earlier pass. **That report was wrong**,
and this section records why, because a finding marked fixed on bad
evidence is worse than one left openly unfixed.

### What went wrong

The first attempt wired both ends and left the middle out. The spec
gained `DiscloseTargetAccount`, `Observation` gained `TargetAccount`, and
the generator read it — but the engine between them never set it. Every
unit test passed, because each tested one end in isolation, and the live
runs silently measured the no-target condition while the record claimed
otherwise.

The improvement reported at the time — a doubled verification rate — came
from a single-probe run, and the effect was produced by the probe
session's saved-payee list, which exposes the other customer's account to
the *assistant*. It had nothing to do with the target disclosure.

A second defect sat underneath. The first design resolved a real account
identifier from a throwaway environment, on the stated premise that "the
identifier is stable because the fixture is". **The fixture is stable in
structure, not in identifiers**: accounts get random ids and every probe
runs in its own freshly wired bank, so the disclosed id existed in no
environment any probe ran against. Attacks naming it were refused as
*not-found* — and `classifyRefusal` maps not-found onto
`refused_unauthorized`, so the record showed what looked like an
authorization refusal when authorization had never been consulted at all.

### The fix

The generator is given a placeholder token, `VICTIM_ACCOUNT`, and the
evaluator substitutes the real identifier from that probe's own seeded
fixture immediately before the assistant sees the input, recording what it
substituted.

Measured, 3 probes, hardened, seed 42:

```
no target:    0 of 3 probes reached the authorization boundary
with target:  1 of 3 reached it and was refused there
              assistant.no-unauthorized-tool-execution: inconclusive -> blocked
              verification rate 0.167 -> 0.222    invariant coverage 0.167 -> 0.333
```

Real, and more modest than first claimed. The remaining limit is the
attacker model: `gemma3:12b` wrote the placeholder in one probe of three.

### What now prevents a repeat

A test of the seam rather than of the ends.
`TestTargetDisclosure_EngineActuallyPassesTheTargetToTheGenerator` drives
the engine with a generator that records the `Observation` it was handed
and asserts the target arrived. It was verified to fail when the engine
wiring is removed — not merely to fail compilation, but to fail its own
assertion. Requesting disclosure on an engine that cannot supply a target
is now recorded as an experiment error rather than silently downgraded to
the no-target condition.

The lesson is narrow and worth stating plainly: unit tests at both ends
of a data path can all pass while the path is not connected. Only a test
that follows the value across the seam catches that.
