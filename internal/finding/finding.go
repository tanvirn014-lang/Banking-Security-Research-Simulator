// Package finding is BankSec Lab's structured security-finding
// vocabulary: the outcome taxonomy an experiment classifies a result
// into, the evidence and reproduction fields that make a result
// defensible, and conservative deduplication so that superficial
// variations of one underlying weakness do not inflate the number of
// unique vulnerabilities.
//
// It deliberately depends on nothing else in this project. A finding is
// a report about a result, not a result: whoever produced the result --
// the experiment engine, the benchmark runner, a future generator --
// maps it into a Context here. That keeps the classification rules
// independent of, and separately testable from, whatever executed the
// attack.
//
// Severity is derived from a documented rule, not scored. There is no
// CVSS here: assigning a CVSS vector requires evidence this simulator
// does not produce, and an invented score is worse than none.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Outcome is what an experiment concluded about one attempt. These four
// values are the whole taxonomy, and keeping them apart is the point:
// an attack the system prevented, a verified violation, insufficient
// evidence, and a broken evaluation are four different research results
// that a single success/failure boolean would collapse into noise.
type Outcome string

const (
	// OutcomeBlocked means the attempted action was prevented. The
	// control under test worked. This is not a vulnerability.
	OutcomeBlocked Outcome = "blocked"
	// OutcomeConfirmedViolation means the oracle independently verified
	// that a named security invariant was violated. This is the only
	// outcome that counts as a vulnerability.
	OutcomeConfirmedViolation Outcome = "confirmed_violation"
	// OutcomeInconclusive means the evidence was insufficient or
	// contradictory. Reported honestly rather than resolved by
	// assumption in either direction.
	OutcomeInconclusive Outcome = "inconclusive"
	// OutcomeError means the attempt could not be evaluated correctly --
	// the harness errored, a generator failed, an invariant check could
	// not read the state it needed. Never silently treated as either a
	// secure outcome or a violation.
	OutcomeError Outcome = "error"
)

// Severity is a coarse, derived impact band. It is a property of the
// violated invariant, not of the attack that happened to trip it, and
// only a confirmed violation carries it -- see New.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	// SeverityInfo is what every non-violation outcome gets: a blocked
	// attack, an inconclusive result, or an evaluation error has no
	// demonstrated impact to band.
	SeverityInfo Severity = "info"
)

// sensitiveEvidenceKeys are substrings that mark an evidence key as
// carrying material that must never be written into a report. Matching
// is on the key, not the value: a value-based heuristic would both miss
// encodings and redact innocent data, whereas a producer naming a field
// "private_key" has told us exactly what it is.
var sensitiveEvidenceKeys = []string{
	"private_key", "privatekey", "secret", "password", "passphrase",
	"credential", "key_material", "keymaterial", "token", "seed_phrase",
}

// Reproduction is what a reader needs to attempt this finding again.
// Steps are rendered actions rather than structured ones so that this
// package stays independent of whatever action representation produced
// them.
type Reproduction struct {
	ExperimentID string `json:"experiment_id,omitempty"`
	TestID       string `json:"test_id,omitempty"`
	Seed         int64  `json:"seed"`
	// Steps is the ordered action trace, one rendered action per entry.
	Steps []string `json:"steps,omitempty"`
	// Note records anything that limits reproducibility -- for example
	// that the generator is nondeterministic, so re-execution may take a
	// different path even under the same seed.
	Note string `json:"note,omitempty"`
}

// Context is everything a producer knows about one evaluated attempt.
// New turns it into a Finding.
type Context struct {
	// Invariant names the security property that was evaluated, e.g.
	// "ledger.double-entry". Required: a finding that cannot name the
	// property it is about cannot be classified, and New reports that
	// rather than guessing.
	Invariant           string
	InvariantDesc       string
	InvariantSeverity   Severity
	Component           string
	AttackID            string
	GeneratorID         string
	TargetConfiguration string
	CryptoProfile       string
	Outcome             Outcome
	Impact              string
	Remediation         string
	Evidence            map[string]any
	Reproduction        Reproduction
	Related             []string
}

// Finding is one classified, evidence-backed research result.
type Finding struct {
	// ID is a deterministic digest of the underlying weakness --
	// invariant, component, configuration, and outcome -- so the same
	// weakness found twice carries the same ID and Dedupe can collapse
	// it.
	ID                  string         `json:"id"`
	Invariant           string         `json:"invariant"`
	InvariantDesc       string         `json:"invariant_description,omitempty"`
	Component           string         `json:"component,omitempty"`
	AttackID            string         `json:"attack_id,omitempty"`
	GeneratorID         string         `json:"generator_id,omitempty"`
	TargetConfiguration string         `json:"target_configuration,omitempty"`
	CryptoProfile       string         `json:"crypto_profile,omitempty"`
	Outcome             Outcome        `json:"outcome"`
	Severity            Severity       `json:"severity"`
	Impact              string         `json:"impact,omitempty"`
	Remediation         string         `json:"remediation,omitempty"`
	Evidence            map[string]any `json:"evidence,omitempty"`
	// Redacted names evidence keys that were withheld, so a reader can
	// tell withheld data from absent data.
	Redacted     []string     `json:"redacted,omitempty"`
	Reproduction Reproduction `json:"reproduction"`
	Related      []string     `json:"related,omitempty"`
	// Occurrences is how many raw attempts collapsed into this finding.
	// Set by Dedupe; 1 on a freshly constructed finding.
	Occurrences int `json:"occurrences"`
}

// New classifies one attempt into a Finding.
//
// Severity derivation, in full: a confirmed violation carries the
// violated invariant's own severity; every other outcome carries
// SeverityInfo. That is the whole rule. A blocked attack is a control
// working as designed, and an inconclusive result or an evaluation
// error has demonstrated nothing, so none of them can carry impact.
func New(c Context) Finding {
	outcome := c.Outcome
	impact := c.Impact

	if c.Invariant == "" {
		// Reported as an error rather than classified: a result whose
		// security property was never named cannot be adjudicated, and
		// guessing one would fabricate the research result.
		outcome = OutcomeError
		impact = "cannot classify: no security invariant was named for this attempt"
	}

	severity := SeverityInfo
	if outcome == OutcomeConfirmedViolation {
		severity = c.InvariantSeverity
		if severity == "" {
			severity = SeverityMedium
		}
	}

	evidence, redacted := redact(c.Evidence)

	f := Finding{
		Invariant:           c.Invariant,
		InvariantDesc:       c.InvariantDesc,
		Component:           c.Component,
		AttackID:            c.AttackID,
		GeneratorID:         c.GeneratorID,
		TargetConfiguration: c.TargetConfiguration,
		CryptoProfile:       c.CryptoProfile,
		Outcome:             outcome,
		Severity:            severity,
		Impact:              impact,
		Remediation:         c.Remediation,
		Evidence:            evidence,
		Redacted:            redacted,
		Reproduction:        cloneReproduction(c.Reproduction),
		Occurrences:         1,
	}
	if len(c.Related) > 0 {
		f.Related = append([]string(nil), c.Related...)
	}
	f.ID = f.dedupeKey()
	return f
}

// IsVulnerability reports whether this finding demonstrates a real
// security weakness. Exactly one outcome qualifies.
func (f Finding) IsVulnerability() bool {
	return f.Outcome == OutcomeConfirmedViolation
}

// dedupeKey is the identity of the underlying weakness: the invariant
// that was evaluated, the component it was evaluated on, the
// configuration it was evaluated under, and what was concluded.
// Deliberately excluded: the attack ID, the generator, the seed, the
// action trace. Two generators tripping the same invariant on the same
// component under the same configuration have found one weakness, and
// counting that twice is how a finding count gets inflated.
func (f Finding) dedupeKey() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		f.Invariant, f.Component, f.TargetConfiguration, string(f.Outcome),
	}, "\x00")))
	return "fnd-" + hex.EncodeToString(sum[:8])
}

// Set is one experiment's findings: the raw attempt counts and the
// deduplicated unique findings, kept as separate concepts so a report
// can never present one as the other.
type Set struct {
	// RawAttempts is how many evaluated attempts went into this set,
	// before any deduplication.
	RawAttempts int `json:"raw_attempts"`
	// ConfirmedViolations, Blocked, Inconclusive and Errors count raw
	// attempts by outcome, not unique findings.
	ConfirmedViolations int `json:"confirmed_violations"`
	Blocked             int `json:"blocked"`
	Inconclusive        int `json:"inconclusive"`
	Errors              int `json:"errors"`
	// Unique holds the deduplicated findings, each with its Occurrences
	// count, in a stable order.
	Unique []Finding `json:"unique"`
}

// UniqueConfirmedViolations is the figure a comparative metric should
// use for "how many distinct security violations did this experiment
// find" -- distinct weaknesses, not raw attempts.
func (s Set) UniqueConfirmedViolations() int {
	n := 0
	for _, f := range s.Unique {
		if f.IsVulnerability() {
			n++
		}
	}
	return n
}

// Dedupe collapses findings that describe the same underlying weakness
// and returns both the raw counts and the unique set. The order of
// Unique is stable (by ID) so two reports of the same experiment compare
// equal.
func Dedupe(raw []Finding) Set {
	set := Set{RawAttempts: len(raw)}

	byID := make(map[string]*Finding, len(raw))
	for _, f := range raw {
		switch f.Outcome {
		case OutcomeConfirmedViolation:
			set.ConfirmedViolations++
		case OutcomeBlocked:
			set.Blocked++
		case OutcomeInconclusive:
			set.Inconclusive++
		case OutcomeError:
			set.Errors++
		}

		if existing, ok := byID[f.ID]; ok {
			existing.Occurrences++
			// Keep the first attempt's reproduction: it is the one with
			// the shortest path to the weakness in practice, and a
			// stable choice keeps reports comparable.
			continue
		}
		clone := f
		clone.Occurrences = 1
		clone.Evidence = copyEvidence(f.Evidence)
		byID[f.ID] = &clone
	}

	set.Unique = make([]Finding, 0, len(byID))
	for _, f := range byID {
		set.Unique = append(set.Unique, *f)
	}
	sort.Slice(set.Unique, func(i, j int) bool { return set.Unique[i].ID < set.Unique[j].ID })

	return set
}

// redact copies evidence, dropping any key that names sensitive
// material and reporting which keys were dropped.
func redact(in map[string]any) (map[string]any, []string) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(in))
	var dropped []string
	for k, v := range in {
		if isSensitiveKey(k) {
			dropped = append(dropped, k)
			continue
		}
		out[k] = v
	}
	sort.Strings(dropped)
	if len(out) == 0 {
		out = nil
	}
	return out, dropped
}

func isSensitiveKey(k string) bool {
	lower := strings.ToLower(k)
	for _, marker := range sensitiveEvidenceKeys {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func copyEvidence(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneReproduction(r Reproduction) Reproduction {
	clone := r
	if r.Steps != nil {
		clone.Steps = append([]string(nil), r.Steps...)
	}
	return clone
}

// String renders a finding as one compact line, for a terminal report.
func (f Finding) String() string {
	return fmt.Sprintf("[%s/%s] %s on %s (%s) x%d",
		f.Outcome, f.Severity, f.Invariant, f.Component, f.TargetConfiguration, f.Occurrences)
}
