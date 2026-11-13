package experiment

import (
	"fmt"
	"strconv"
	"sync"

	"banksec-lab/internal/domain"
)

// Decision is the validation boundary's verdict on one proposed action.
// The five values are deliberately distinct: an experiment record that
// collapsed them would make "the generator produced nonsense" and "the
// banking system refused a legitimate attack" look the same, and only
// the second one is a result.
type Decision string

const (
	// DecisionAllow means the action is well-formed, permitted by the
	// experiment's safety policy, and within budget. It will be
	// submitted to the simulator, which remains free to reject it --
	// that rejection is a result, not a validation failure.
	DecisionAllow Decision = "allow"
	// DecisionMalformed means the action could not be formed into a
	// request at all: a missing required parameter, an unparseable
	// amount, an empty actor, an unknown role.
	DecisionMalformed Decision = "malformed"
	// DecisionUnsupported means the operation is not one the simulator
	// can dispatch.
	DecisionUnsupported Decision = "unsupported"
	// DecisionDisallowedByPolicy means the action is well-formed and
	// supported, but this experiment's Safety settings exclude it.
	DecisionDisallowedByPolicy Decision = "disallowed_by_policy"
	// DecisionBudgetExhausted means the experiment's action budget is
	// spent. Returned in place of any other verdict once that happens.
	DecisionBudgetExhausted Decision = "budget_exhausted"
)

// ValidationResult is one Validate call's verdict plus the reason behind
// it, which goes into the experiment record verbatim.
type ValidationResult struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason,omitempty"`
}

// knownRoles is the closed set of actor roles domain defines. A
// generator naming anything else is proposing an actor the
// authorization layer has no rule for, which is malformed rather than
// interesting.
var knownRoles = map[domain.Role]struct{}{
	domain.RoleAccountOwner:       {},
	domain.RolePrivilegedOperator: {},
}

// requiredParams lists, per operation, the parameters protocol/server.go
// reads out of Request.Params. An action missing one of these cannot
// become a meaningful request.
var requiredParams = map[string][]string{
	OpCreateAccount: {"owner"},
	OpDeposit:       {"account", "amount"},
	OpWithdraw:      {"account", "amount"},
	OpTransfer:      {"from", "to", "amount"},
	OpBalance:       {"account"},
	OpHistory:       {"account"},
}

// amountParam names the parameter holding a money amount, per operation.
var amountParam = map[string]string{
	OpDeposit:  "amount",
	OpWithdraw: "amount",
	OpTransfer: "amount",
}

// Validator is the single boundary between every generator and the
// simulated banking system. Nothing a generator proposes reaches
// env.Client except through a Validate call that returned
// DecisionAllow (see planScenario).
//
// What it enforces is safety, policy, and budget -- not correctness.
// It deliberately does not reproduce the banking application's own input
// validation: a negative or zero amount, a transfer to the same account,
// a withdrawal by someone else's actor are all well-formed proposals
// that the simulator itself must decide about. Pre-rejecting them here
// would do the system-under-test's job for it and would hide exactly the
// weaknesses an experiment exists to find.
//
// A Validator is bound to one experiment run, holds that run's action
// budget, and is safe for concurrent use.
type Validator struct {
	allowedOps map[string]struct{}
	maxAmount  int64

	mu         sync.Mutex
	spent      int
	maxActions int
}

// NewValidator builds the validation boundary for one experiment run.
// It takes an effective spec (see ExperimentSpec.Effective) and rejects
// any spec that would not pass Validate, so an unchecked configuration
// can never become a validator that permits everything.
func NewValidator(spec ExperimentSpec) (*Validator, error) {
	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("build validator: %w", err)
	}
	eff := spec.Effective()

	allowed := make(map[string]struct{}, len(eff.Safety.AllowedOps))
	for _, op := range eff.Safety.AllowedOps {
		allowed[op] = struct{}{}
	}

	return &Validator{
		allowedOps: allowed,
		maxAmount:  eff.Safety.MaxAmount,
		maxActions: eff.Budget.MaxActions,
	}, nil
}

// Validate decides whether a may be submitted to the simulator, and
// charges the action budget when it may. Budget is charged only for
// allowed actions: a refused action never reached the simulator, so
// charging for it would make two generators' "actions spent" figures
// mean different things and break every per-budget comparison.
func (v *Validator) Validate(a Action) ValidationResult {
	if res, ok := v.checkShape(a); !ok {
		return res
	}
	if res, ok := v.checkPolicy(a); !ok {
		return res
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.spent >= v.maxActions {
		return ValidationResult{
			Decision: DecisionBudgetExhausted,
			Reason:   fmt.Sprintf("action budget of %d is spent", v.maxActions),
		}
	}
	v.spent++
	return ValidationResult{Decision: DecisionAllow}
}

// checkShape reports whether a could become a request at all. ok is
// false when it could not, in which case the returned result holds the
// verdict.
func (v *Validator) checkShape(a Action) (ValidationResult, bool) {
	if !IsSupportedOp(a.Op) {
		return ValidationResult{
			Decision: DecisionUnsupported,
			Reason:   fmt.Sprintf("operation %q is not one the simulator dispatches", a.Op),
		}, false
	}
	if a.Actor.ID == "" {
		return ValidationResult{
			Decision: DecisionMalformed,
			Reason:   "actor id must not be empty",
		}, false
	}
	if _, ok := knownRoles[a.Actor.Role]; !ok {
		return ValidationResult{
			Decision: DecisionMalformed,
			Reason:   fmt.Sprintf("actor role %q is not a role the authorization layer defines", a.Actor.Role),
		}, false
	}
	for _, p := range requiredParams[a.Op] {
		if a.Params[p] == "" {
			return ValidationResult{
				Decision: DecisionMalformed,
				Reason:   fmt.Sprintf("operation %q requires a non-empty %q parameter", a.Op, p),
			}, false
		}
	}
	if key, ok := amountParam[a.Op]; ok {
		if _, err := strconv.ParseInt(a.Params[key], 10, 64); err != nil {
			return ValidationResult{
				Decision: DecisionMalformed,
				Reason:   fmt.Sprintf("parameter %q = %q is not an integer amount", key, a.Params[key]),
			}, false
		}
	}
	return ValidationResult{}, true
}

// checkPolicy reports whether this experiment's Safety settings permit
// a. ok is false when they do not.
func (v *Validator) checkPolicy(a Action) (ValidationResult, bool) {
	if _, ok := v.allowedOps[a.Op]; !ok {
		return ValidationResult{
			Decision: DecisionDisallowedByPolicy,
			Reason:   fmt.Sprintf("operation %q is not in this experiment's allowed_ops", a.Op),
		}, false
	}
	if key, ok := amountParam[a.Op]; ok {
		amount, err := strconv.ParseInt(a.Params[key], 10, 64)
		if err != nil {
			// Unreachable via Validate (checkShape ran first), but a
			// policy check that silently passed an unparseable amount if
			// it were ever called alone would be worse than one that
			// states the problem.
			return ValidationResult{
				Decision: DecisionMalformed,
				Reason:   fmt.Sprintf("parameter %q = %q is not an integer amount", key, a.Params[key]),
			}, false
		}
		if magnitude(amount) > v.maxAmount {
			return ValidationResult{
				Decision: DecisionDisallowedByPolicy,
				Reason: fmt.Sprintf("amount %d exceeds this experiment's max_amount of %d in magnitude",
					amount, v.maxAmount),
			}, false
		}
	}
	return ValidationResult{}, true
}

// Spent reports how many actions this run has submitted to the
// simulator.
func (v *Validator) Spent() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.spent
}

// Remaining reports how much of the action budget is left.
func (v *Validator) Remaining() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.spent >= v.maxActions {
		return 0
	}
	return v.maxActions - v.spent
}

// magnitude returns n's absolute value, saturating at MaxInt64 rather
// than wrapping to a negative on MinInt64 -- a mutation generator
// probing boundary values will reach MinInt64 eventually, and a
// magnitude check that returned a negative there would wave the most
// extreme value in the space straight past the safety bound.
func magnitude(n int64) int64 {
	if n == -1<<63 {
		return 1<<63 - 1
	}
	if n < 0 {
		return -n
	}
	return n
}
