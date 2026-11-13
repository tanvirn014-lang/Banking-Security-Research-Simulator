package experiment

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"sync"

	"banksec-lab/internal/domain"
	"banksec-lab/internal/harness"
)

// SeedPlan is a named, legitimate banking workflow that the mutation
// generator derives variations from.
//
// These are authored here rather than extracted from the registered
// scenarios, and that distinction is deliberate and important: a
// registered scenario's implementation is a Go closure, so there is no
// action sequence inside it to read out. What these plans reproduce is
// the application-layer *workflow* those scenarios exercise -- account
// creation, funding, and value movement between owners -- expressed as
// actions so that it can be varied. A mutation of one of these is
// genuinely a new action sequence, not a renamed static scenario, and
// every candidate records exactly how it differs from its seed.
type SeedPlan struct {
	ID   string
	Plan ActionPlan
	// Principals names the actors this workflow involves, which the
	// actor-swap mutation draws substitutes from.
	Principals []domain.PrincipalID
}

func principal(id domain.PrincipalID) domain.Principal {
	return domain.Principal{ID: id, Role: domain.RoleAccountOwner}
}

// SeedPlans returns the baseline workflows available for mutation.
func SeedPlans() []SeedPlan {
	alice, bob := domain.PrincipalID("alice"), domain.PrincipalID("bob")

	fundedTransfer := ActionPlan{Actions: []Action{
		{Op: OpCreateAccount, Actor: principal(alice), Params: map[string]string{"owner": "alice"}, Label: "seed"},
		{Op: OpCreateAccount, Actor: principal(bob), Params: map[string]string{"owner": "bob"}, Label: "seed"},
		{Op: OpDeposit, Actor: principal(alice), Params: map[string]string{"account": AccountPlaceholder("alice"), "amount": "1000"}, Label: "seed"},
		{Op: OpTransfer, Actor: principal(alice), Params: map[string]string{"from": AccountPlaceholder("alice"), "to": AccountPlaceholder("bob"), "amount": "300"}, Label: "seed"},
		{Op: OpBalance, Actor: principal(alice), Params: map[string]string{"account": AccountPlaceholder("alice")}, Label: "seed"},
	}}

	fundedWithdrawal := ActionPlan{Actions: []Action{
		{Op: OpCreateAccount, Actor: principal(alice), Params: map[string]string{"owner": "alice"}, Label: "seed"},
		{Op: OpDeposit, Actor: principal(alice), Params: map[string]string{"account": AccountPlaceholder("alice"), "amount": "500"}, Label: "seed"},
		{Op: OpWithdraw, Actor: principal(alice), Params: map[string]string{"account": AccountPlaceholder("alice"), "amount": "200"}, Label: "seed"},
		{Op: OpHistory, Actor: principal(alice), Params: map[string]string{"account": AccountPlaceholder("alice")}, Label: "seed"},
	}}

	return []SeedPlan{
		{ID: "workflow-funded-transfer", Plan: fundedTransfer, Principals: []domain.PrincipalID{alice, bob, "mallory"}},
		{ID: "workflow-funded-withdrawal", Plan: fundedWithdrawal, Principals: []domain.PrincipalID{alice, "mallory"}},
	}
}

// MutationKind names one bounded transformation.
type MutationKind string

const (
	// MutateActorSwap replaces a debiting action's actor with a
	// different principal, probing the authorization boundary.
	MutateActorSwap MutationKind = "actor-swap"
	// MutateAmountBoundary replaces an amount with a boundary value
	// (zero, negative, or the safety ceiling).
	MutateAmountBoundary MutationKind = "amount-boundary"
	// MutateReorder swaps two adjacent actions, probing whether the
	// system depends on an ordering it does not enforce.
	MutateReorder MutationKind = "reorder"
	// MutateRepeat duplicates one action, probing idempotency and
	// replay handling at the application layer.
	MutateRepeat MutationKind = "repeat"
	// MutateDropPrecondition removes a funding step, so a later
	// withdrawal or transfer runs against an unfunded account.
	MutateDropPrecondition MutationKind = "drop-precondition"
	// MutateTargetSwap points a debiting action at a different owner's
	// account without changing the actor.
	MutateTargetSwap MutationKind = "target-swap"
)

// MutationKinds returns every transformation the generator can apply, in
// a fixed order so that a seeded run is reproducible.
func MutationKinds() []MutationKind {
	return []MutationKind{
		MutateActorSwap,
		MutateAmountBoundary,
		MutateTargetSwap,
		MutateDropPrecondition,
		MutateRepeat,
		MutateReorder,
	}
}

// MutationGenerator produces bounded variations of the seed workflows.
//
// It is deterministic given the experiment's seed: the same seed
// produces the same candidates in the same order. It never bypasses the
// validation boundary -- it only produces Actions, which planScenario
// puts through Validator.Validate like any other -- and it records, per
// candidate, exactly which transformation was applied to which seed, so
// a reader can confirm that a candidate really is a variation rather
// than a rename.
type MutationGenerator struct {
	seeds     []SeedPlan
	kinds     []MutationKind
	maxAmount int64
	rnd       *rand.Rand

	mu       sync.Mutex
	produced int
	// emitted deduplicates identical candidates: two different
	// transformations can coincide on the same action sequence, and
	// running the same sequence twice adds cost without adding evidence.
	emitted map[string]struct{}
	// exhausted is set once every seed/kind pairing has been tried.
	cursor int
}

// NewMutationGenerator builds a mutation generator for spec. The spec's
// SeedScenarios names which seed workflows to draw from; a name that is
// neither a seed workflow nor a registered scenario is rejected rather
// than silently skipped.
func NewMutationGenerator(reg harness.Registry, spec ExperimentSpec) (*MutationGenerator, error) {
	eff := spec.Effective()

	available := make(map[string]SeedPlan)
	for _, sp := range SeedPlans() {
		available[sp.ID] = sp
	}

	var chosen []SeedPlan
	for _, name := range eff.SeedScenarios {
		sp, ok := available[name]
		if !ok {
			return nil, fmt.Errorf("mutation generator: %q is not a seed workflow (available: %s)",
				name, seedPlanIDs())
		}
		chosen = append(chosen, sp)
	}
	if len(chosen) == 0 {
		return nil, fmt.Errorf("mutation generator: no seed workflows selected")
	}

	return &MutationGenerator{
		seeds:     chosen,
		kinds:     MutationKinds(),
		maxAmount: eff.Safety.MaxAmount,
		rnd:       rand.New(rand.NewSource(eff.Seed)),
		emitted:   make(map[string]struct{}),
	}, nil
}

func seedPlanIDs() string {
	var ids []string
	for _, sp := range SeedPlans() {
		ids = append(ids, sp.ID)
	}
	sort.Strings(ids)
	return fmt.Sprintf("%v", ids)
}

// ID identifies this generator in experiment records.
func (g *MutationGenerator) ID() string { return string(GeneratorMutation) }

// Selected returns the seed workflow IDs this generator draws from.
func (g *MutationGenerator) Selected() []string {
	out := make([]string, 0, len(g.seeds))
	for _, sp := range g.seeds {
		out = append(out, sp.ID)
	}
	return out
}

// Next produces the next variation, or ErrNoMoreCandidates once every
// seed/transformation pairing has been tried.
//
// It respects the remaining action budget it is given: a plan longer
// than the budget left would be truncated by the validator mid-run,
// which would make the candidate's own record misleading, so the
// generator stops instead.
func (g *MutationGenerator) Next(_ context.Context, obs Observation) (Candidate, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	total := len(g.seeds) * len(g.kinds)
	for g.cursor < total {
		seedIdx := g.cursor / len(g.kinds)
		kindIdx := g.cursor % len(g.kinds)
		g.cursor++

		seed := g.seeds[seedIdx]
		kind := g.kinds[kindIdx]

		plan, applied, ok := g.apply(seed, kind)
		if !ok {
			continue // this transformation does not apply to this seed
		}
		if plan.Len() > obs.ActionsRemaining {
			// Not an error and not an exhaustion: this candidate simply
			// does not fit the budget that is left.
			return Candidate{}, ErrNoMoreCandidates
		}

		fingerprint := planFingerprint(plan)
		if _, dup := g.emitted[fingerprint]; dup {
			continue
		}
		g.emitted[fingerprint] = struct{}{}
		g.produced++

		return Candidate{
			TestID:           fmt.Sprintf("%s/%s/%d", seed.ID, kind, g.produced),
			GeneratorID:      g.ID(),
			SourceScenarioID: seed.ID,
			Seed:             obs.Spec.Seed,
			Mutations:        applied,
			Plan:             &plan,
		}, nil
	}

	return Candidate{}, ErrNoMoreCandidates
}

// apply performs one transformation. ok is false when the
// transformation does not apply to this seed, which is not an error.
func (g *MutationGenerator) apply(seed SeedPlan, kind MutationKind) (ActionPlan, []string, bool) {
	plan := seed.Plan.Clone()

	switch kind {
	case MutateActorSwap:
		idx, ok := firstDebitingIndex(plan)
		if !ok {
			return ActionPlan{}, nil, false
		}
		intruder := g.intruderFor(seed)
		was := plan.Actions[idx].Actor.ID
		plan.Actions[idx].Actor = principal(intruder)
		plan.Actions[idx].Label = string(MutateActorSwap)
		return plan, []string{fmt.Sprintf("actor-swap: action %d actor %s -> %s", idx, was, intruder)}, true

	case MutateAmountBoundary:
		idx, ok := firstAmountIndex(plan)
		if !ok {
			return ActionPlan{}, nil, false
		}
		was := plan.Actions[idx].Params["amount"]
		now := g.boundaryAmount()
		plan.Actions[idx].Params["amount"] = now
		plan.Actions[idx].Label = string(MutateAmountBoundary)
		return plan, []string{fmt.Sprintf("amount-boundary: action %d amount %s -> %s", idx, was, now)}, true

	case MutateTargetSwap:
		idx, ok := firstDebitingIndex(plan)
		if !ok {
			return ActionPlan{}, nil, false
		}
		key := "account"
		if plan.Actions[idx].Op == OpTransfer {
			key = "from"
		}
		victim, ok := g.otherOwner(seed, plan.Actions[idx].Actor.ID)
		if !ok {
			return ActionPlan{}, nil, false
		}
		was := plan.Actions[idx].Params[key]
		now := AccountPlaceholder(string(victim))
		if was == now {
			return ActionPlan{}, nil, false
		}
		plan.Actions[idx].Params[key] = now
		plan.Actions[idx].Label = string(MutateTargetSwap)
		return plan, []string{fmt.Sprintf("target-swap: action %d %s %s -> %s", idx, key, was, now)}, true

	case MutateDropPrecondition:
		idx, ok := firstIndexOfOp(plan, OpDeposit)
		if !ok {
			return ActionPlan{}, nil, false
		}
		dropped := plan.Actions[idx].String()
		plan.Actions = append(plan.Actions[:idx], plan.Actions[idx+1:]...)
		return plan, []string{fmt.Sprintf("drop-precondition: removed action %d (%s)", idx, dropped)}, true

	case MutateRepeat:
		idx, ok := firstDebitingIndex(plan)
		if !ok {
			return ActionPlan{}, nil, false
		}
		dup := plan.Actions[idx].Clone()
		dup.Label = string(MutateRepeat)
		rest := append([]Action{dup}, plan.Actions[idx+1:]...)
		plan.Actions = append(plan.Actions[:idx+1:idx+1], rest...)
		return plan, []string{fmt.Sprintf("repeat: action %d duplicated (%s)", idx, dup.String())}, true

	case MutateReorder:
		idx, ok := firstDebitingIndex(plan)
		if !ok || idx == 0 {
			return ActionPlan{}, nil, false
		}
		plan.Actions[idx-1], plan.Actions[idx] = plan.Actions[idx], plan.Actions[idx-1]
		plan.Actions[idx-1].Label = string(MutateReorder)
		plan.Actions[idx].Label = string(MutateReorder)
		return plan, []string{fmt.Sprintf("reorder: actions %d and %d swapped", idx-1, idx)}, true
	}

	return ActionPlan{}, nil, false
}

// intruderFor picks the principal in this seed's cast who owns no
// account in it, falling back to the last listed principal.
func (g *MutationGenerator) intruderFor(seed SeedPlan) domain.PrincipalID {
	owners := map[string]bool{}
	for _, a := range seed.Plan.Actions {
		if a.Op == OpCreateAccount {
			owners[a.Params["owner"]] = true
		}
	}
	for _, p := range seed.Principals {
		if !owners[string(p)] {
			return p
		}
	}
	return seed.Principals[len(seed.Principals)-1]
}

// otherOwner picks an account owner in this seed other than actor.
func (g *MutationGenerator) otherOwner(seed SeedPlan, actor domain.PrincipalID) (domain.PrincipalID, bool) {
	for _, a := range seed.Plan.Actions {
		if a.Op != OpCreateAccount {
			continue
		}
		if ownerName := a.Params["owner"]; ownerName != string(actor) {
			return domain.PrincipalID(ownerName), true
		}
	}
	return "", false
}

// boundaryAmount picks a boundary value, always within the safety
// ceiling so the validator admits it and the simulator -- not the
// validator -- is what decides.
func (g *MutationGenerator) boundaryAmount() string {
	candidates := []int64{0, -1, 1, g.maxAmount}
	return strconv.FormatInt(candidates[g.rnd.Intn(len(candidates))], 10)
}

func firstDebitingIndex(p ActionPlan) (int, bool) {
	for i, a := range p.Actions {
		if a.Op == OpWithdraw || a.Op == OpTransfer {
			return i, true
		}
	}
	return 0, false
}

func firstAmountIndex(p ActionPlan) (int, bool) {
	for i, a := range p.Actions {
		if _, ok := a.Params["amount"]; ok {
			return i, true
		}
	}
	return 0, false
}

func firstIndexOfOp(p ActionPlan, op string) (int, bool) {
	for i, a := range p.Actions {
		if a.Op == op {
			return i, true
		}
	}
	return 0, false
}

// planFingerprint renders a plan to a stable string, for deduplicating
// candidates whose action sequences coincide.
func planFingerprint(p ActionPlan) string {
	s := ""
	for _, a := range p.Actions {
		s += a.String() + "\n"
	}
	return s
}
