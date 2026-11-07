# BankSec Lab — Future LLM-Based Agent Integration

This document is the user's explicit Milestone 10 deliverable: how a
future LLM-based agent could integrate with `internal/agent`
**without compromising simulation isolation**. No such integration
exists in this codebase today — `internal/agent` has no mandatory (or
optional) external LLM API dependency anywhere, and this document does
not propose adding one now. It exists so that *if* one is wanted later,
the extension point and its safety boundary are already thought through,
not improvised under pressure.

## 1. What exists today, and why it's already the right extension point

`DeterministicPolicy` (`policy_deterministic.go`) is this package's one
required baseline: a rule-based, non-learning agent, explicitly **not**
presented as an advanced AI agent — see its own doc comment and
`docs/IMPLEMENTATION_PLAN.md`'s infeasibility note, which scoped Milestone
10's "adaptive execution" as *reactive* (branches on its current
`Observation`), never *learning* (improves across runs).

The entire framework around it — `Agent`, `Observation`, `Action`,
`AgentReport` — was built against one interface, deliberately kept as
narrow as it already needs to be:

```go
type Policy interface {
    Decide(obs Observation) (Action, error)
}
```

**This is already the correct seam for an LLM-backed policy.** A future
`LLMPolicy` would just be another implementation of this same interface:

```go
type LLMPolicy struct {
    client LLMClient // whatever the future integration uses
    kinds  []ActionKind
}

func (p *LLMPolicy) Decide(obs Observation) (Action, error) {
    prompt := renderObservation(obs, p.kinds) // obs -> text/JSON, nothing more
    choice, err := p.client.Complete(prompt)   // the ONLY place an external call would ever happen
    if err != nil {
        return Action{}, err
    }
    return parseAction(choice, p.kinds)        // validates choice against p.kinds before returning
}
```

Nothing in `Agent`, `agent.go`'s loop, `harness.Registry`, `harness.Runner`,
or `harness.Environment` would need to change at all. `Agent.Run` doesn't
know or care whether its `Policy` is `DeterministicPolicy`,
`LLMPolicy`, or anything else — it only ever calls `Policy.Decide(obs)`
and validates the returned `Action` exactly the same way regardless.

## 2. The isolation boundary an LLM integration must not cross

Everything below is already true of `DeterministicPolicy`, and would
need to stay true of any `LLMPolicy` too — not new rules invented for
this document, but the existing guarantees this package already
provides, restated as the constraints a future implementation must
preserve:

1. **`Decide` receives only an `Observation` value — never the `Agent`,
   `*harness.Environment`, `harness.Registry`, or `harness.Runner`
   themselves.** An `LLMPolicy` has no path to call `env.Client`,
   `env.Priv`, or anything else directly; it can only return an `Action`
   value and let `Agent.Run` decide what to do with it. This is already
   enforced by `Policy`'s own method signature, not by convention.
2. **`Agent.Run` validates every returned `Action.Kind` against its own
   fixed `ActionKinds` list before resolving it via `Registry.ByID`.**
   An `LLMPolicy` that "hallucinates" an `ActionKind` naming a scenario
   that isn't registered, or isn't in the `Agent`'s own bounded list,
   gets a clean error from `Agent.Run` (`TestAgent_PropagatesUnknownActionKindAsError`),
   never a silent fallback to "do something else instead." The LLM
   cannot expand its own action space.
3. **The LLM call itself (if one exists) happens entirely inside
   `Decide`, synchronously, with no network access to anything the
   Observation/Action boundary doesn't already describe.** Whatever
   `LLMClient` a future implementation uses should be constructed
   explicitly by the caller that builds the `Agent` (dependency
   injection, not a global or auto-discovered client) — this keeps "no
   mandatory external LLM API" literally true of `internal/agent`
   itself: nothing in this package imports or references any such client
   type at all today, and even after an `LLMPolicy` existed,
   `DeterministicPolicy` and the rest of `Agent`/`agent.go` would remain
   completely unaffected and still fully offline.
4. **`Budget` still bounds the number of `Policy.Decide` calls per
   `Agent.Run`, regardless of what kind of Policy is plugged in.** An
   LLM that wants to "keep trying" has no way to extend its own budget —
   that is `Agent.Run`'s loop, not the `Policy`'s to control. "No
   uncontrolled autonomous execution" holds exactly as it does today.
5. **`DecisionLog` would record an `LLMPolicy`'s decisions exactly like
   a `DeterministicPolicy`'s** — the `Observation` it saw, the `Action`
   it chose, and a `Timestamp`, nothing about *how* the decision was
   reached (no prompt, no raw model output) is part of the `Decision`
   schema today. If a future integration wants that for auditability, it
   is a disclosed, additive schema change to `Decision` — not something
   to bolt on silently.
6. **Determinism would be explicitly NOT preserved by an `LLMPolicy`**,
   and that must be documented honestly, not glossed over: an LLM's
   output is not guaranteed reproducible the way `DeterministicPolicy`'s
   is (`TestAgent_SameSeed_SameActionSequence`). A future
   `LLMPolicy`-driven `Agent.Run` would need its own, separately-scoped
   reproducibility story (e.g. recording and replaying the LLM's actual
   responses for a given `Observation` sequence, rather than claiming
   the live model call itself is reproducible) — never presented as
   satisfying the same "same seed → same action sequence" guarantee
   `DeterministicPolicy` provides today.

## 3. What would still need its own design pass (deliberately not solved here)

Per `docs/IMPLEMENTATION_PLAN.md`'s own infeasibility note: "a learning
agent is out of scope for this plan and would need its own brainstorming
pass if wanted later." This document is not that pass — it only answers
the one question the user's instructions asked: *how could it integrate
without compromising isolation*. Separate, later decisions this
document deliberately leaves open:

- How `Observation` should be serialized into an LLM prompt (full JSON?
  a natural-language summary? how much of `RecentAudit` to include,
  given context-window limits?).
- Whether an `LLMPolicy` should be allowed multiple LLM calls per
  `Decide` (e.g. a reasoning/tool-use loop) — if so, that internal loop
  would need its OWN bounded budget, separate from and nested inside
  `Agent.Run`'s own `Budget`, so the outer isolation guarantee in §2.4
  still holds even if the LLM "reasons" for a while before answering.
- Cost/rate-limit handling for a real LLM API call, and what `Decide`
  should return on a timeout or API error (propagate as an error, same
  as any other `Policy.Decide` failure today — likely the right default,
  but worth an explicit decision when the time comes).
- Whether evaluating an `LLMPolicy` needs new `AgentReport` fields (e.g.
  LLM API cost, token counts) alongside the existing
  `Attempts`/`SuccessfulCompromises`/`TimeToCompromiseMS`/
  `ObservationCount`/`ActionCallCount`/`ComputationalCostMS` -- a natural
  extension of the existing struct, not a redesign.

None of the above requires touching `Agent`, `agent.go`'s loop, or
anything in `internal/harness` — they are all decisions local to a new
`Policy` implementation and its own supporting code, which is exactly
what makes `Policy` the right, already-in-place seam for this future
work.
