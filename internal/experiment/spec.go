package experiment

import (
	"errors"
	"fmt"
	"time"

	"banksec-lab/internal/domain"
)

// ErrInvalidSpec wraps every rejection Validate reports, so a caller can
// distinguish "this configuration is not acceptable" from an execution
// failure later on. An invalid configuration is always rejected
// explicitly; it is never silently repaired.
var ErrInvalidSpec = errors.New("invalid experiment spec")

// GeneratorType selects which attack generator an experiment runs.
type GeneratorType string

const (
	// GeneratorStatic replays the existing registered attack corpus
	// unchanged -- the reproducible research baseline.
	GeneratorStatic GeneratorType = "static"
	// GeneratorMutation derives bounded variations of baseline
	// scenarios' action sequences.
	GeneratorMutation GeneratorType = "mutation"
)

// GeneratorLLM is declared in llmgen.go, alongside the generator it
// names.

// knownGenerators is the closed set of generator types this package
// implements. An adaptive generator is a documented extension point
// (see Generator's doc comment), deliberately not a value here: naming
// a generator that does not exist would let a spec validate and then
// fail at run time.
var knownGenerators = map[GeneratorType]struct{}{
	GeneratorStatic:   {},
	GeneratorMutation: {},
	GeneratorLLM:      {},
}

// StopCondition names a reason an experiment should halt before its
// budget is exhausted.
type StopCondition string

const (
	// StopOnConfirmedViolation halts as soon as the oracle confirms one
	// security-invariant violation.
	StopOnConfirmedViolation StopCondition = "on_confirmed_violation"
	// StopOnFirstError halts as soon as any candidate fails to be
	// evaluated correctly. Without it, errors are recorded and the
	// experiment continues.
	StopOnFirstError StopCondition = "on_first_error"
)

var knownStopConditions = map[StopCondition]struct{}{
	StopOnConfirmedViolation: {},
	StopOnFirstError:         {},
}

// knownCryptoProfiles is the closed set of cryptographic profiles
// internal/crypto implements.
var knownCryptoProfiles = map[domain.CryptoProfileName]struct{}{
	"weak-educational": {},
	"standard":         {},
	"pqc":              {},
}

// Budget bounds one experiment's execution. Every limit is enforced by
// the engine, not merely advisory: comparing two generators is only
// meaningful if both actually ran under the same ceiling.
type Budget struct {
	// MaxActions caps the total number of actions the experiment may
	// submit to the simulator, summed across every candidate. This is
	// the budget comparative metrics are normalised against.
	MaxActions int `json:"max_actions"`
	// MaxTests caps how many candidates the generator may produce.
	MaxTests int `json:"max_tests"`
	// MaxDuration caps total wall-clock time. Zero means no time limit,
	// leaving MaxActions and MaxTests as the only bounds.
	MaxDuration time.Duration `json:"max_duration"`
}

// defaultMaxAmount bounds a single generated money operation. It exists
// so a mutation generator exploring boundary values cannot propose an
// amount so large that an overflow, rather than the control under test,
// becomes what the experiment measures.
const defaultMaxAmount = 1_000_000_00 // 1,000,000.00 in minor units

// Safety declares what an experiment's generators are permitted to
// propose. It is the policy half of the validation boundary: the
// validator refuses anything outside it before the simulator ever sees
// it (see Validator).
type Safety struct {
	// AllowedOps restricts which supported operations generators may
	// propose. Empty means every supported operation.
	AllowedOps []string `json:"allowed_ops,omitempty"`
	// MaxAmount caps the amount parameter of a single money operation,
	// in minor units. Zero means defaultMaxAmount.
	MaxAmount int64 `json:"max_amount"`
	// AllowPrivileged permits candidates that use the harness's
	// insider-style bypass (harness.PrivilegedAccess). Only the reviewed
	// static scenarios can ever use it -- no generated ActionPlan can
	// express it -- so this gates the static corpus's privileged
	// scenarios, not a capability granted to a generator.
	AllowPrivileged bool `json:"allow_privileged"`
}

// ExperimentSpec is one experiment's complete, typed configuration.
// Everything that determines what an experiment does lives here, so the
// record of a run can state exactly what produced it.
type ExperimentSpec struct {
	ExperimentID string `json:"experiment_id"`
	// Objective states the research question this run investigates, for
	// the experiment record. Free text, but required: an experiment
	// whose purpose was never written down is not reproducible research.
	Objective string `json:"objective"`
	// TargetProfile names the security profile to run against, matching
	// a config.SecurityProfile's Name (e.g. "hardened", "vulnerable").
	TargetProfile string `json:"target_profile"`
	// CryptoProfile optionally pins the cryptographic profile. Empty
	// means "whatever TargetProfile's own configuration selects", which
	// is the normal case; set it only when an experiment deliberately
	// isolates the cryptographic variable.
	CryptoProfile domain.CryptoProfileName `json:"crypto_profile,omitempty"`
	Generator     GeneratorType            `json:"generator"`
	Budget        Budget                   `json:"budget"`
	// Seed makes a run reproducible wherever the generator and the
	// scenarios it draws from are themselves deterministic. See
	// Record.Reproducibility for what that does and does not guarantee.
	Seed           int64           `json:"seed"`
	StopConditions []StopCondition `json:"stop_conditions,omitempty"`
	Safety         Safety          `json:"safety"`
	// DiscloseTargetAccount gives an adaptive generator the account
	// identifier of another customer in the fixture.
	//
	// This is a research condition, not a convenience. Without it a
	// generated probe can only cite an account number it invented, which
	// the bank refuses as nonexistent rather than unauthorized, so the
	// cross-account authorization path is never actually reached and
	// every verdict about it is inconclusive.
	//
	// Disclosing the identifier is defensible because a real attacker can
	// obtain an account number from a cheque, a statement or a prior
	// transfer; knowing one is a precondition of the attack, not the
	// attack. The victim's *balance* is never disclosed, so a leaked
	// balance remains genuine evidence of disclosure. Identifiers handed
	// over this way are recorded and excluded from the disclosure check,
	// since the assistant cannot leak what the attacker was already
	// given.
	DiscloseTargetAccount bool `json:"disclose_target_account"`
	// SeedScenarios names the registered scenario IDs a derivative
	// generator draws from. Required for GeneratorMutation, which has
	// nothing to mutate without one. Empty under GeneratorStatic means
	// the whole registry.
	SeedScenarios []string `json:"seed_scenarios,omitempty"`
}

// Validate reports every way s is unacceptable, as one error naming the
// offending field. It never repairs a value; defaults are applied
// separately and visibly by Effective.
func (s ExperimentSpec) Validate() error {
	var problems []string

	if s.ExperimentID == "" {
		problems = append(problems, "experiment_id must not be empty")
	}
	if s.Objective == "" {
		problems = append(problems, "objective must not be empty")
	}
	if s.TargetProfile == "" {
		problems = append(problems, "target_profile must not be empty")
	}
	if _, ok := knownGenerators[s.Generator]; !ok {
		problems = append(problems, fmt.Sprintf("generator %q is not implemented", s.Generator))
	}
	if s.CryptoProfile != "" {
		if _, ok := knownCryptoProfiles[s.CryptoProfile]; !ok {
			problems = append(problems, fmt.Sprintf("crypto_profile %q is not implemented", s.CryptoProfile))
		}
	}
	if s.Budget.MaxActions <= 0 {
		problems = append(problems, fmt.Sprintf("budget.max_actions must be positive, got %d", s.Budget.MaxActions))
	}
	if s.Budget.MaxTests <= 0 {
		problems = append(problems, fmt.Sprintf("budget.max_tests must be positive, got %d", s.Budget.MaxTests))
	}
	if s.Budget.MaxDuration < 0 {
		problems = append(problems, fmt.Sprintf("budget.max_duration must not be negative, got %s", s.Budget.MaxDuration))
	}
	if s.Safety.MaxAmount < 0 {
		problems = append(problems, fmt.Sprintf("safety.max_amount must not be negative, got %d", s.Safety.MaxAmount))
	}
	for _, op := range s.Safety.AllowedOps {
		if !IsSupportedOp(op) {
			problems = append(problems, fmt.Sprintf("safety.allowed_ops names unsupported operation %q", op))
		}
	}
	for _, sc := range s.StopConditions {
		if _, ok := knownStopConditions[sc]; !ok {
			problems = append(problems, fmt.Sprintf("stop_condition %q is not implemented", sc))
		}
	}
	if s.Generator == GeneratorMutation && len(s.SeedScenarios) == 0 {
		problems = append(problems, "seed_scenarios must name at least one registered scenario for a mutation experiment")
	}

	if len(problems) > 0 {
		return fmt.Errorf("%w: %v", ErrInvalidSpec, problems)
	}
	return nil
}

// Effective returns a copy of s with defaults filled in -- the
// configuration a run actually uses, which is what belongs in the
// experiment record. It never mutates the receiver, so the spec as
// written and the spec as run stay separately inspectable, and it is
// idempotent, so recording an already-effective spec changes nothing.
func (s ExperimentSpec) Effective() ExperimentSpec {
	eff := s

	if len(s.Safety.AllowedOps) == 0 {
		eff.Safety.AllowedOps = SupportedOps()
	} else {
		eff.Safety.AllowedOps = append([]string(nil), s.Safety.AllowedOps...)
	}
	if s.Safety.MaxAmount == 0 {
		eff.Safety.MaxAmount = defaultMaxAmount
	}
	if len(s.StopConditions) > 0 {
		eff.StopConditions = append([]StopCondition(nil), s.StopConditions...)
	}
	if len(s.SeedScenarios) > 0 {
		eff.SeedScenarios = append([]string(nil), s.SeedScenarios...)
	}

	return eff
}

// HasStopCondition reports whether s declares sc.
func (s ExperimentSpec) HasStopCondition(sc StopCondition) bool {
	for _, have := range s.StopConditions {
		if have == sc {
			return true
		}
	}
	return false
}
