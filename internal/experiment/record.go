package experiment

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"banksec-lab/internal/assistant"
	"banksec-lab/internal/finding"
	"banksec-lab/internal/harness"
)

// StopReason names why an experiment ended. Recording it matters because
// "the generator ran out of ideas" and "the budget ran out" mean very
// different things when comparing two generators at the same budget.
type StopReason string

const (
	StopReasonGeneratorExhausted StopReason = "generator_exhausted"
	StopReasonActionBudget       StopReason = "action_budget_exhausted"
	StopReasonTestBudget         StopReason = "test_budget_exhausted"
	StopReasonTimeBudget         StopReason = "time_budget_exhausted"
	StopReasonConfirmedViolation StopReason = "confirmed_violation"
	StopReasonError              StopReason = "error"
	StopReasonCancelled          StopReason = "cancelled"
)

// VerdictRecord is an InvariantVerdict flattened for serialization,
// with the invariant it belongs to named alongside it.
type VerdictRecord struct {
	Invariant string          `json:"invariant"`
	Outcome   finding.Outcome `json:"outcome"`
	Detail    string          `json:"detail,omitempty"`
	Evidence  map[string]any  `json:"evidence,omitempty"`
}

// ResultRecord is harness.Result reduced to the fields that mean
// something for an experiment, with explicit JSON names. harness.Result
// itself is not serialized directly so that this package's record format
// does not silently change whenever that struct does.
type ResultRecord struct {
	AttackID            string `json:"attack_id"`
	TargetConfiguration string `json:"target_configuration"`
	AttackType          string `json:"attack_type"`
	Success             bool   `json:"success"`
	ExecutionTimeMS     int64  `json:"execution_time_ms"`
	Attempts            int    `json:"attempts"`
	RecordsCompromised  *int64 `json:"records_compromised,omitempty"`
	DetectionLatencyMS  *int64 `json:"detection_latency_ms,omitempty"`
	Seed                *int64 `json:"seed,omitempty"`
}

func resultRecordOf(r harness.Result) ResultRecord {
	return ResultRecord{
		AttackID:            r.AttackID,
		TargetConfiguration: r.TargetConfiguration,
		AttackType:          r.AttackType,
		Success:             r.Success,
		ExecutionTimeMS:     r.ExecutionTimeMS,
		Attempts:            r.Attempts,
		RecordsCompromised:  r.RecordsCompromised,
		DetectionLatencyMS:  r.DetectionLatencyMS,
		Seed:                r.Seed,
	}
}

// Attempt is the complete record of one evaluated candidate: what was
// proposed, how it differed from its source, what the validation
// boundary decided about each action, what the simulator answered, what
// the oracle observed before and after, and what each invariant
// concluded.
//
// It is deliberately verbose. An experiment whose attempts cannot be
// read back in this much detail cannot be defended when someone asks how
// a finding was reached.
type Attempt struct {
	TestID           string   `json:"test_id"`
	GeneratorID      string   `json:"generator_id"`
	SourceScenarioID string   `json:"source_scenario_id,omitempty"`
	Mutations        []string `json:"mutations,omitempty"`
	// Plan is the declarative action sequence, present for generated
	// candidates and absent for baseline scenarios, whose
	// implementations are Go closures rather than action sequences.
	Plan  *ActionPlan `json:"plan,omitempty"`
	Steps []Step      `json:"steps,omitempty"`
	// Probe is the adversarial input, present for an assistant
	// candidate. Recorded verbatim: the exact text is the test.
	Probe *Probe `json:"probe,omitempty"`
	// Transcript is what the assistant said and what the gateway did
	// with its proposals.
	Transcript *assistant.Transcript `json:"transcript,omitempty"`
	// ToolsAttempted and ToolsExecuted are kept apart for the same
	// reason the gateway keeps them apart: a proposal is not an action.
	ToolsAttempted int `json:"tools_attempted,omitempty"`
	ToolsExecuted  int `json:"tools_executed,omitempty"`
	// SnapshotBefore and SnapshotAfter are the oracle-observed state the
	// verdicts were drawn from.
	SnapshotBefore Snapshot        `json:"snapshot_before"`
	SnapshotAfter  Snapshot        `json:"snapshot_after"`
	Result         ResultRecord    `json:"result"`
	Verdicts       []VerdictRecord `json:"verdicts"`
	// Error records a failure to evaluate this candidate at all. An
	// attempt with an error is never counted as a security result.
	Error      string `json:"error,omitempty"`
	StopReason string `json:"stop_reason,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// ActionsExecuted counts how many of this attempt's actions actually
// reached the simulator.
func (a Attempt) ActionsExecuted() int {
	n := 0
	for _, s := range a.Steps {
		if s.Executed {
			n++
		}
	}
	return n
}

// Outcomes reduces the attempt's verdicts to an invariant-to-outcome
// map, which is what a generator's Observation carries.
func (a Attempt) Outcomes() map[string]finding.Outcome {
	out := make(map[string]finding.Outcome, len(a.Verdicts))
	for _, v := range a.Verdicts {
		out[v.Invariant] = v.Outcome
	}
	return out
}

// Reproducibility states what replaying this experiment can and cannot
// be expected to produce. The distinction matters: a deterministic
// generator at a fixed seed can be replayed exactly, whereas a
// nondeterministic one may take a different path on a new run even with
// the same seed and configuration, so reproducing a *finding* and
// reproducing a *run* are not the same claim.
type Reproducibility struct {
	// ExactReplaySupported is true when every candidate in this record
	// is a declarative plan, which can be re-executed verbatim.
	ExactReplaySupported bool `json:"exact_replay_supported"`
	// Note explains any limitation on replay.
	Note string `json:"note,omitempty"`
}

// Record is one experiment run's complete, machine-readable result.
type Record struct {
	// Spec is the effective configuration this run actually used, after
	// defaults were applied -- not necessarily the spec as written.
	Spec        ExperimentSpec `json:"spec"`
	GeneratorID string         `json:"generator_id"`
	// SourceRevision identifies the code under test, when the caller
	// knows it. Empty rather than guessed.
	SourceRevision string    `json:"source_revision,omitempty"`
	StartedAt      time.Time `json:"started_at"`
	FinishedAt     time.Time `json:"finished_at"`
	DurationMS     int64     `json:"duration_ms"`
	// SelectedScenarios names the baseline corpus this run covered,
	// where the generator draws from one.
	SelectedScenarios []string        `json:"selected_scenarios,omitempty"`
	Attempts          []Attempt       `json:"attempts"`
	Findings          finding.Set     `json:"findings"`
	ActionsSpent      int             `json:"actions_spent"`
	TestsProduced     int             `json:"tests_produced"`
	StopReason        StopReason      `json:"stop_reason"`
	Reproducibility   Reproducibility `json:"reproducibility"`
	// Errors collects evaluation failures. A non-empty Errors with a
	// stop reason other than error means the experiment continued past
	// them, which is the default.
	Errors []string `json:"errors,omitempty"`
}

// ConfirmedViolations is the count of raw attempts that produced an
// oracle-confirmed violation. Distinct from
// Findings.UniqueConfirmedViolations, which counts weaknesses.
func (r Record) ConfirmedViolations() int { return r.Findings.ConfirmedViolations }

// WriteJSON serializes the record. Indented, because an experiment
// record is read by people as often as by programs.
func (r Record) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("write experiment record: %w", err)
	}
	return nil
}
