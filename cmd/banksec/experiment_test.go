package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func experimentEnv(t *testing.T) cliEnv {
	t.Helper()
	return cliEnv{DataDir: t.TempDir(), ProfilePath: "../../configs/hardened.json"}
}

func TestExperiment_ListsWhatIsAvailable(t *testing.T) {
	out, err := runCLI(experimentEnv(t), []string{"experiment", "--list"})
	if err != nil {
		t.Fatalf("experiment --list: %v", err)
	}

	for _, want := range []string{
		"application-authz-bypass",               // a registered scenario
		"workflow-funded-transfer",               // a mutation seed workflow
		"authz.no-unauthorized-value-extraction", // an invariant
		"static",
		"mutation",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("--list output does not mention %q:\n%s", want, out)
		}
	}
}

func TestExperiment_ListDoesNotRunAnything(t *testing.T) {
	out, err := runCLI(experimentEnv(t), []string{"experiment", "--list"})
	if err != nil {
		t.Fatalf("experiment --list: %v", err)
	}
	if strings.Contains(out, "unique confirmed") {
		t.Fatalf("--list should only list, not run an experiment:\n%s", out)
	}
}

func TestExperiment_DefaultRunIsStaticAgainstHardened(t *testing.T) {
	out, err := runCLI(experimentEnv(t), []string{"experiment", "--tests", "2"})
	if err != nil {
		t.Fatalf("experiment: %v", err)
	}

	if !strings.Contains(out, "generator=static") {
		t.Fatalf("expected the default generator to be static:\n%s", out)
	}
	if !strings.Contains(out, "profile=hardened") {
		t.Fatalf("expected the default profile to be hardened:\n%s", out)
	}
	if !strings.Contains(out, "unique confirmed") {
		t.Fatalf("expected a result summary:\n%s", out)
	}
}

func TestExperiment_MutationGeneratorRuns(t *testing.T) {
	out, err := runCLI(experimentEnv(t), []string{
		"experiment", "--generator", "mutation", "--tests", "2", "--actions", "20",
	})
	if err != nil {
		t.Fatalf("experiment --generator mutation: %v", err)
	}

	if !strings.Contains(out, "generator=mutation") {
		t.Fatalf("expected the mutation generator to be reported:\n%s", out)
	}
	if !strings.Contains(out, "actions spent") {
		t.Fatalf("expected the action spend to be reported:\n%s", out)
	}
}

// Rule: the vulnerable configuration must never be reachable silently.
// The banking commands cannot reach it at all; an experiment can, and
// must say so loudly.
func TestExperiment_VulnerableProfileIsAnnouncedNotSilent(t *testing.T) {
	out, err := runCLI(experimentEnv(t), []string{
		"experiment", "--profile", "vulnerable", "--tests", "1",
	})
	if err != nil {
		t.Fatalf("experiment --profile vulnerable: %v", err)
	}

	upper := strings.ToUpper(out)
	if !strings.Contains(upper, "WARNING") {
		t.Fatalf("running against the vulnerable profile must be announced:\n%s", out)
	}
	if !strings.Contains(out, "profile=vulnerable") {
		t.Fatalf("expected the profile to be named in the summary:\n%s", out)
	}
}

func TestExperiment_DefaultProfileIsNotVulnerable(t *testing.T) {
	out, err := runCLI(experimentEnv(t), []string{"experiment", "--tests", "1"})
	if err != nil {
		t.Fatalf("experiment: %v", err)
	}
	if strings.Contains(out, "profile=vulnerable") {
		t.Fatal("the default experiment posture must not be the vulnerable configuration")
	}
}

func TestExperiment_RejectsAnUnknownGenerator(t *testing.T) {
	_, err := runCLI(experimentEnv(t), []string{"experiment", "--generator", "psychic"})
	if err == nil {
		t.Fatal("expected an unknown generator to be rejected")
	}
	if !strings.Contains(err.Error(), "psychic") {
		t.Fatalf("the error should name the offending generator, got %v", err)
	}
}

func TestExperiment_RejectsAnUnknownProfile(t *testing.T) {
	_, err := runCLI(experimentEnv(t), []string{"experiment", "--profile", "wide-open"})
	if err == nil {
		t.Fatal("expected an unknown profile to be rejected")
	}
}

func TestExperiment_RejectsAnInvalidBudget(t *testing.T) {
	for _, args := range [][]string{
		{"experiment", "--actions", "0"},
		{"experiment", "--tests", "0"},
		{"experiment", "--actions", "-5"},
	} {
		t.Run(strings.Join(args[1:], " "), func(t *testing.T) {
			if _, err := runCLI(experimentEnv(t), args); err == nil {
				t.Fatalf("expected %v to be rejected", args)
			}
		})
	}
}

func TestExperiment_RejectsAnUnknownFlag(t *testing.T) {
	if _, err := runCLI(experimentEnv(t), []string{"experiment", "--turbo"}); err == nil {
		t.Fatal("expected an unknown flag to be rejected")
	}
}

func TestExperiment_WritesAReadableRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")

	if _, err := runCLI(experimentEnv(t), []string{
		"experiment", "--tests", "2", "--out", path,
	}); err != nil {
		t.Fatalf("experiment --out: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}

	var rec struct {
		Spec struct {
			ExperimentID string `json:"experiment_id"`
			Generator    string `json:"generator"`
		} `json:"spec"`
		StopReason string `json:"stop_reason"`
		Attempts   []struct {
			TestID   string `json:"test_id"`
			Verdicts []struct {
				Invariant string `json:"invariant"`
				Outcome   string `json:"outcome"`
			} `json:"verdicts"`
		} `json:"attempts"`
		Findings struct {
			RawAttempts int `json:"raw_attempts"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("the written record is not valid JSON: %v", err)
	}

	if rec.Spec.Generator != "static" {
		t.Fatalf("record generator = %q, want static", rec.Spec.Generator)
	}
	if rec.StopReason == "" {
		t.Fatal("the record must state why the experiment stopped")
	}
	if len(rec.Attempts) == 0 {
		t.Fatal("the record must contain the attempts")
	}
	if len(rec.Attempts[0].Verdicts) == 0 {
		t.Fatal("each attempt must record its invariant verdicts")
	}
}

func TestExperiment_RecordPathMustBeWritable(t *testing.T) {
	_, err := runCLI(experimentEnv(t), []string{
		"experiment", "--tests", "1", "--out", filepath.Join(t.TempDir(), "no", "such", "dir", "r.json"),
	})
	if err == nil {
		t.Fatal("expected an unwritable record path to be reported")
	}
}

// The comparison must run both generators at the same budget and report
// the comparability caveats rather than presenting the figures bare.
func TestExperiment_CompareRunsBothGeneratorsAndReportsCaveats(t *testing.T) {
	out, err := runCLI(experimentEnv(t), []string{
		"experiment", "--compare", "--tests", "2", "--actions", "20",
	})
	if err != nil {
		t.Fatalf("experiment --compare: %v", err)
	}

	if !strings.Contains(out, "static") || !strings.Contains(out, "mutation") {
		t.Fatalf("a comparison must report both conditions:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "caveat") {
		t.Fatalf("a comparison must report its caveats:\n%s", out)
	}
	// The known caveat: a baseline run spends no actions, so per-action
	// metrics are not comparable.
	if !strings.Contains(out, "per-action") {
		t.Fatalf("the per-action comparability caveat must be shown:\n%s", out)
	}
}

func TestExperiment_CompareRejectsAnExplicitGenerator(t *testing.T) {
	_, err := runCLI(experimentEnv(t), []string{"experiment", "--compare", "--generator", "mutation"})
	if err == nil {
		t.Fatal("expected --compare and --generator together to be rejected as contradictory")
	}
}

func TestExperiment_UndefinedRatiosArePrintedAsUndefined(t *testing.T) {
	// A static run spends no actions, so its finding yield is undefined.
	// Printing 0.0000 there would make the worst case look like the best.
	out, err := runCLI(experimentEnv(t), []string{"experiment", "--tests", "1"})
	if err != nil {
		t.Fatalf("experiment: %v", err)
	}
	if !strings.Contains(out, "undefined") {
		t.Fatalf("an undefined ratio must print as undefined, not as a number:\n%s", out)
	}
}

func TestExperiment_SeedIsReportedForReproducibility(t *testing.T) {
	out, err := runCLI(experimentEnv(t), []string{"experiment", "--tests", "1", "--seed", "1234"})
	if err != nil {
		t.Fatalf("experiment: %v", err)
	}
	if !strings.Contains(out, "1234") {
		t.Fatalf("the seed must be reported so a run can be repeated:\n%s", out)
	}
}

func TestExperiment_RestrictsToNamedScenarios(t *testing.T) {
	out, err := runCLI(experimentEnv(t), []string{
		"experiment", "--scenarios", "application-authz-bypass", "--allow-privileged",
	})
	if err != nil {
		t.Fatalf("experiment --scenarios: %v", err)
	}
	if !strings.Contains(out, "tests=1") {
		t.Fatalf("expected exactly the one named scenario to run:\n%s", out)
	}
}

func TestExperiment_RejectsAnUnregisteredScenario(t *testing.T) {
	_, err := runCLI(experimentEnv(t), []string{"experiment", "--scenarios", "no-such-attack"})
	if err == nil {
		t.Fatal("expected an unregistered scenario name to be rejected rather than skipped")
	}
}

// Backward compatibility: adding this subcommand must not change how any
// banking command behaves, including the error for an unknown one.
func TestExperiment_DoesNotDisturbTheBankingCommands(t *testing.T) {
	env := experimentEnv(t)

	out, err := runCLI(env, []string{"create-account", "--owner", "owner-1"})
	if err != nil {
		t.Fatalf("create-account still works: %v", err)
	}
	if !strings.Contains(out, "account=") {
		t.Fatalf("create-account output changed: %s", out)
	}

	if _, err := runCLI(env, []string{"nonsense"}); err == nil {
		t.Fatal("an unknown command must still be an error")
	} else if !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("the unknown-command error changed: %v", err)
	}
}

func TestExperiment_CompareRejectsEvenTheDefaultGeneratorWhenSetExplicitly(t *testing.T) {
	if _, err := runCLI(experimentEnv(t), []string{"experiment", "--compare", "--generator", "static"}); err == nil {
		t.Fatal("--compare with an explicitly set --generator is contradictory regardless of which generator it names")
	}
}
