package finding

import (
	"encoding/json"
	"strings"
	"testing"
)

func confirmedContext() Context {
	return Context{
		Invariant:           "ledger.double-entry",
		InvariantDesc:       "every transaction's entries sum to zero",
		InvariantSeverity:   SeverityCritical,
		Component:           "ledger",
		AttackID:            "ledger-tamper",
		GeneratorID:         "static",
		TargetConfiguration: "vulnerable",
		CryptoProfile:       "standard",
		Outcome:             OutcomeConfirmedViolation,
		Impact:              "a tampered entry left the ledger unbalanced and undetected",
		Remediation:         "enable audit hash chaining and the ledger-integrity detection rule",
		Evidence: map[string]any{
			"violating_tx_ids": []string{"tx-1"},
			"invariant_ok":     false,
		},
		Reproduction: Reproduction{
			ExperimentID: "exp-001",
			TestID:       "test-1",
			Seed:         42,
			Steps:        []string{"deposit actor=alice/account-owner account=acct-1 amount=100"},
		},
	}
}

func TestFinding_ConfirmedViolationInheritsTheInvariantSeverity(t *testing.T) {
	f := New(confirmedContext())

	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %q, want the invariant's own severity %q", f.Severity, SeverityCritical)
	}
	if f.Outcome != OutcomeConfirmedViolation {
		t.Fatalf("outcome = %q, want confirmed_violation", f.Outcome)
	}
}

// The single most important rule in this package: an attack the system
// successfully prevented is not a vulnerability. If a blocked attempt
// could carry a non-informational severity, every run of the hardened
// profile would report critical findings for controls that worked.
func TestFinding_BlockedAttemptIsNeverScoredAsImpactful(t *testing.T) {
	c := confirmedContext()
	c.Outcome = OutcomeBlocked

	f := New(c)

	if f.Severity != SeverityInfo {
		t.Fatalf("severity = %q, want info -- a blocked attack is not a vulnerability", f.Severity)
	}
	if f.IsVulnerability() {
		t.Fatal("a blocked attempt must not report itself as a vulnerability")
	}
}

func TestFinding_InconclusiveAndErrorAreNotVulnerabilities(t *testing.T) {
	for _, outcome := range []Outcome{OutcomeInconclusive, OutcomeError} {
		t.Run(string(outcome), func(t *testing.T) {
			c := confirmedContext()
			c.Outcome = outcome

			f := New(c)
			if f.IsVulnerability() {
				t.Fatalf("%s must not report itself as a vulnerability", outcome)
			}
			if f.Severity != SeverityInfo {
				t.Fatalf("severity = %q, want info", f.Severity)
			}
		})
	}
}

func TestFinding_OnlyConfirmedViolationIsAVulnerability(t *testing.T) {
	c := confirmedContext()
	f := New(c)

	if !f.IsVulnerability() {
		t.Fatal("a confirmed violation is the one outcome that is a vulnerability")
	}
}

func TestFinding_IDIsDeterministicAndDistinguishesUnderlyingWeaknesses(t *testing.T) {
	a := New(confirmedContext())
	b := New(confirmedContext())
	if a.ID != b.ID {
		t.Fatalf("the same weakness must get the same ID: %q != %q", a.ID, b.ID)
	}

	other := confirmedContext()
	other.Invariant = "authz.restricted-operations"
	c := New(other)
	if c.ID == a.ID {
		t.Fatal("two different invariants must not collapse to the same finding ID")
	}
}

// Superficial variation -- a different seed, a different generated test,
// a different attack that trips the same invariant on the same component
// -- is one weakness, not many. Inflating the unique-finding count is
// the easiest way to make a research result look better than it is.
func TestFinding_DedupeCollapsesSuperficialVariationsOfOneWeakness(t *testing.T) {
	var raw []Finding
	for i, attack := range []string{"ledger-tamper", "ledger-tamper-mutated-1", "ledger-tamper-mutated-2"} {
		c := confirmedContext()
		c.AttackID = attack
		c.Reproduction.Seed = int64(i)
		c.Reproduction.TestID = attack
		raw = append(raw, New(c))
	}

	set := Dedupe(raw)

	if set.RawAttempts != 3 {
		t.Fatalf("raw attempts = %d, want 3 -- raw attempts and unique findings are separate counts", set.RawAttempts)
	}
	if len(set.Unique) != 1 {
		t.Fatalf("unique findings = %d, want 1 -- three variations of one weakness", len(set.Unique))
	}
	if set.Unique[0].Occurrences != 3 {
		t.Fatalf("occurrences = %d, want 3", set.Unique[0].Occurrences)
	}
}

func TestFinding_DedupeKeepsGenuinelyDistinctWeaknessesApart(t *testing.T) {
	first := confirmedContext()
	second := confirmedContext()
	second.Invariant = "authz.restricted-operations"
	second.Component = "backend"
	third := confirmedContext()
	third.TargetConfiguration = "hardened"

	set := Dedupe([]Finding{New(first), New(second), New(third)})

	if len(set.Unique) != 3 {
		t.Fatalf("unique findings = %d, want 3 -- different invariant, component, or configuration are different results", len(set.Unique))
	}
}

func TestFinding_DedupeSeparatesOutcomesOfTheSameInvariant(t *testing.T) {
	blocked := confirmedContext()
	blocked.Outcome = OutcomeBlocked
	violated := confirmedContext()

	set := Dedupe([]Finding{New(blocked), New(violated)})

	if len(set.Unique) != 2 {
		t.Fatalf("unique findings = %d, want 2 -- the same invariant blocked in one run and violated in another are different results", len(set.Unique))
	}
}

func TestFinding_DedupeCountsConfirmedViolationsSeparatelyFromEverythingElse(t *testing.T) {
	violated := New(confirmedContext())
	blockedCtx := confirmedContext()
	blockedCtx.Outcome = OutcomeBlocked
	blocked := New(blockedCtx)
	errCtx := confirmedContext()
	errCtx.Outcome = OutcomeError
	errored := New(errCtx)

	set := Dedupe([]Finding{violated, blocked, errored, blocked})

	if set.ConfirmedViolations != 1 {
		t.Fatalf("confirmed violations = %d, want 1", set.ConfirmedViolations)
	}
	if set.Blocked != 2 {
		t.Fatalf("blocked = %d, want 2 (raw, not deduped)", set.Blocked)
	}
	if set.Errors != 1 {
		t.Fatalf("errors = %d, want 1", set.Errors)
	}
}

func TestFinding_DedupeOfNothingIsAnEmptySetNotAnError(t *testing.T) {
	set := Dedupe(nil)

	if set.RawAttempts != 0 || len(set.Unique) != 0 || set.ConfirmedViolations != 0 {
		t.Fatalf("an empty experiment must produce an empty set, got %+v", set)
	}
}

func TestFinding_DedupeIsOrderStable(t *testing.T) {
	a := confirmedContext()
	b := confirmedContext()
	b.Invariant = "authz.restricted-operations"
	c := confirmedContext()
	c.Invariant = "audit.chain-intact"

	first := Dedupe([]Finding{New(a), New(b), New(c)})
	for i := 0; i < 10; i++ {
		again := Dedupe([]Finding{New(a), New(b), New(c)})
		for j := range first.Unique {
			if first.Unique[j].ID != again.Unique[j].ID {
				t.Fatal("Dedupe must return a stable order, or two identical reports will not compare equal")
			}
		}
	}
}

func TestFinding_CarriesEvidenceAndReproductionIntoJSON(t *testing.T) {
	f := New(confirmedContext())

	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)

	for _, want := range []string{"ledger.double-entry", "confirmed_violation", "exp-001", "violating_tx_ids", "deposit actor=alice"} {
		if !strings.Contains(s, want) {
			t.Fatalf("serialized finding is missing %q: %s", want, s)
		}
	}
}

// Keys and credentials must never reach an experiment report.
func TestFinding_RejectsEvidenceThatLooksLikeKeyMaterial(t *testing.T) {
	c := confirmedContext()
	c.Evidence = map[string]any{
		"private_key":  "deadbeef",
		"invariant_ok": false,
	}

	f := New(c)

	if _, present := f.Evidence["private_key"]; present {
		t.Fatal("evidence that names key material must be redacted, not written into the report")
	}
	if _, present := f.Evidence["invariant_ok"]; !present {
		t.Fatal("redaction must drop only the sensitive key, not the whole evidence map")
	}
	if len(f.Redacted) == 0 {
		t.Fatal("a redaction must be recorded, so a reader knows something was withheld rather than absent")
	}
}

func TestFinding_EvidenceIsCopiedNotAliased(t *testing.T) {
	c := confirmedContext()
	f := New(c)

	c.Evidence["invariant_ok"] = true

	if f.Evidence["invariant_ok"] == true {
		t.Fatal("New aliased the caller's evidence map -- a later change rewrote a recorded finding")
	}
}

func TestFinding_RequiresAnInvariantAndReportsSoRatherThanGuessing(t *testing.T) {
	c := confirmedContext()
	c.Invariant = ""

	f := New(c)

	if f.Outcome != OutcomeError {
		t.Fatalf("outcome = %q, want error -- a finding with no named invariant cannot be classified", f.Outcome)
	}
	if !strings.Contains(f.Impact, "invariant") {
		t.Fatalf("the finding should say why it could not be classified, got %q", f.Impact)
	}
}
