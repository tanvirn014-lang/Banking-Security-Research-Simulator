package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"banksec-lab/internal/config"
	"banksec-lab/internal/experiment"
	"banksec-lab/internal/harness"
)

// experimentDefaults are the budget a bare `banksec experiment` runs
// under. Small enough to finish while someone is watching, large enough
// that the static generator covers the whole registered corpus.
const (
	defaultActionBudget = 60
	defaultTestBudget   = 12
	defaultSeed         = 42
)

// runExperiment implements the `experiment` subcommand: it runs one
// research experiment against the simulator and prints a summary, or
// with --compare runs both generators at the same budget and prints the
// comparison.
//
// It deliberately shares no code path with the banking commands. Those
// keep running under configs/hardened.json exactly as before; nothing
// here changes their behaviour, their flags, or their errors.
func runExperiment(env cliEnv, args []string) (string, error) {
	fs := flag.NewFlagSet("experiment", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	generator := fs.String("generator", string(experiment.GeneratorStatic), "attack generator: static or mutation")
	profileName := fs.String("profile", "hardened", "security profile to run against")
	actions := fs.Int("actions", defaultActionBudget, "maximum actions submitted to the simulator")
	tests := fs.Int("tests", defaultTestBudget, "maximum candidates the generator may produce")
	seed := fs.Int64("seed", defaultSeed, "random seed, for reproducible runs")
	id := fs.String("id", "", "experiment ID recorded in the result (defaults to one derived from the generator and seed)")
	objective := fs.String("objective", "", "the research question this run investigates")
	scenarios := fs.String("scenarios", "", "comma-separated scenario IDs (static) or seed workflow IDs (mutation); empty means all")
	allowPrivileged := fs.Bool("allow-privileged", false, "include scenarios that use the harness insider bypass")
	stopOnViolation := fs.Bool("stop-on-violation", false, "halt at the first oracle-confirmed violation")
	out := fs.String("out", "", "write the full machine-readable record to this path")
	list := fs.Bool("list", false, "list the available scenarios, seed workflows and invariants, and run nothing")
	compare := fs.Bool("compare", false, "run both generators at the same budget and compare them")

	if err := fs.Parse(args); err != nil {
		return "", fmt.Errorf("parse flags for experiment: %w", err)
	}
	if fs.NArg() > 0 {
		return "", fmt.Errorf("experiment takes no positional arguments, got %q", fs.Arg(0))
	}

	if *list {
		return listResearchSurface(), nil
	}
	// Checked via Visit rather than by comparing against the default:
	// `--compare --generator static` is just as contradictory as
	// `--compare --generator mutation`, and only Visit can tell a flag
	// the caller set from one that merely holds its default.
	generatorWasSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "generator" {
			generatorWasSet = true
		}
	})
	if *compare && generatorWasSet {
		return "", fmt.Errorf("--compare runs both generators, so it cannot be combined with --generator")
	}

	profile, err := loadNamedProfile(env, *profileName)
	if err != nil {
		return "", err
	}

	reg := harness.NewRegistry()
	if err := harness.RegisterAllScenarios(reg); err != nil {
		return "", fmt.Errorf("register scenarios: %w", err)
	}
	eng, err := experiment.NewEngine(reg, profile)
	if err != nil {
		return "", err
	}

	var report strings.Builder
	if profile.Name != "hardened" {
		// Never silent: the banking commands cannot reach a weakened
		// configuration at all, and an experiment that does says so
		// before it prints a single number.
		fmt.Fprintf(&report, "WARNING: running against the %q security profile, which deliberately disables controls.\n", profile.Name)
		fmt.Fprintf(&report, "         These results describe a research configuration, not a defensible deployment.\n\n")
	}

	opts := specOptions{
		profile:         profile,
		actions:         *actions,
		tests:           *tests,
		seed:            *seed,
		id:              *id,
		objective:       *objective,
		scenarios:       splitList(*scenarios),
		allowPrivileged: *allowPrivileged,
		stopOnViolation: *stopOnViolation,
	}

	if *compare {
		text, err := runComparison(eng, opts, *out)
		if err != nil {
			return "", err
		}
		report.WriteString(text)
		return report.String(), nil
	}

	spec, err := opts.build(experiment.GeneratorType(*generator))
	if err != nil {
		return "", err
	}

	rec, err := eng.Run(context.Background(), spec)
	if err != nil {
		return "", err
	}
	if *out != "" {
		if err := writeRecord(*out, rec); err != nil {
			return "", err
		}
		fmt.Fprintf(&report, "record written to %s\n\n", *out)
	}

	report.WriteString(summarize(rec))
	return report.String(), nil
}

// specOptions carries the flag values a spec is built from, so a
// comparison can build two specs that differ only by generator.
type specOptions struct {
	profile         config.SecurityProfile
	actions, tests  int
	seed            int64
	id, objective   string
	scenarios       []string
	allowPrivileged bool
	stopOnViolation bool
}

func (o specOptions) build(gen experiment.GeneratorType) (experiment.ExperimentSpec, error) {
	experimentID := o.id
	if experimentID == "" {
		experimentID = fmt.Sprintf("exp-%s-%s-%d", gen, o.profile.Name, o.seed)
	}
	objective := o.objective
	if objective == "" {
		objective = fmt.Sprintf("evaluate the %s generator against the %s configuration", gen, o.profile.Name)
	}

	// The mutation generator mutates seed workflows, not registered
	// scenarios, so an unqualified --scenarios list is only meaningful
	// for the static generator. With no list, mutation needs its
	// defaults supplied explicitly because its spec requires them.
	seeds := o.scenarios
	if gen == experiment.GeneratorMutation && len(seeds) == 0 {
		for _, sp := range experiment.SeedPlans() {
			seeds = append(seeds, sp.ID)
		}
	}

	spec := experiment.ExperimentSpec{
		ExperimentID:  experimentID,
		Objective:     objective,
		TargetProfile: o.profile.Name,
		Generator:     gen,
		Budget:        experiment.Budget{MaxActions: o.actions, MaxTests: o.tests},
		Seed:          o.seed,
		Safety: experiment.Safety{
			AllowPrivileged: o.allowPrivileged,
		},
		SeedScenarios: seeds,
	}
	if o.stopOnViolation {
		spec.StopConditions = []experiment.StopCondition{experiment.StopOnConfirmedViolation}
	}

	if err := spec.Validate(); err != nil {
		return experiment.ExperimentSpec{}, err
	}
	return spec, nil
}

// runComparison runs both generators under identical budgets and prints
// the comparison, including whether the conditions really are
// comparable.
func runComparison(eng *experiment.Engine, opts specOptions, outPath string) (string, error) {
	var records []experiment.Record

	for _, gen := range []experiment.GeneratorType{experiment.GeneratorStatic, experiment.GeneratorMutation} {
		spec, err := opts.build(gen)
		if err != nil {
			return "", err
		}
		rec, err := eng.Run(context.Background(), spec)
		if err != nil {
			return "", fmt.Errorf("%s condition: %w", gen, err)
		}
		records = append(records, rec)
	}

	cmp := experiment.Compare(records...)

	var b strings.Builder
	fmt.Fprintf(&b, "comparison  profile=%s seed=%d action budget=%d test budget=%d\n",
		opts.profile.Name, opts.seed, opts.actions, opts.tests)
	fmt.Fprintf(&b, "comparable=%t\n\n", cmp.Comparable)

	for _, m := range cmp.Conditions {
		fmt.Fprintf(&b, "  generator=%-9s tests=%-3d actions spent=%-3d unique confirmed=%-3d blocked=%-3d inconclusive=%-3d errors=%d\n",
			m.GeneratorID, m.TestsProduced, m.ActionsSpent, m.UniqueConfirmedFindings, m.Blocked, m.Inconclusive, m.Errors)
		fmt.Fprintf(&b, "    finding yield/action=%-10s verification rate=%-10s invariant coverage=%-10s benign task rate=%s\n",
			ratioText(m.FindingYieldPerAction), ratioText(m.VerificationRate),
			ratioText(m.InvariantCoverage), ratioText(m.BenignTaskSuccessRate))
		fmt.Fprintf(&b, "    runtime=%dms cost/confirmed finding=%s stop=%s\n\n",
			m.RuntimeMS, ratioText(m.CostPerConfirmedFindingMS), m.StopReason)
	}

	if len(cmp.Caveats) == 0 {
		b.WriteString("caveats: none\n")
	} else {
		b.WriteString("caveats:\n")
		for _, c := range cmp.Caveats {
			fmt.Fprintf(&b, "  - %s\n", c)
		}
	}

	if outPath != "" {
		for i, rec := range records {
			path := comparisonRecordPath(outPath, string(rec.Spec.Generator))
			if err := writeRecord(path, records[i]); err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "\nrecord written to %s", path)
		}
		b.WriteString("\n")
	}

	return b.String(), nil
}

// comparisonRecordPath derives a per-condition path from the single
// --out path, so a comparison does not silently overwrite one record
// with the other.
func comparisonRecordPath(base, generator string) string {
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if ext == "" {
		ext = ".json"
	}
	return stem + "-" + generator + ext
}

// summarize renders one run's outcome for a reader.
func summarize(rec experiment.Record) string {
	m := experiment.MetricsOf(rec)

	var b strings.Builder
	fmt.Fprintf(&b, "experiment=%s generator=%s profile=%s seed=%d\n",
		rec.Spec.ExperimentID, rec.GeneratorID, rec.Spec.TargetProfile, rec.Spec.Seed)
	fmt.Fprintf(&b, "objective: %s\n\n", rec.Spec.Objective)

	fmt.Fprintf(&b, "tests=%d  actions spent=%d of %d  runtime=%dms  stop=%s\n",
		m.TestsProduced, m.ActionsSpent, m.ActionBudget, m.RuntimeMS, m.StopReason)
	fmt.Fprintf(&b, "raw judgements=%d  confirmed=%d  blocked=%d  inconclusive=%d  errors=%d\n",
		m.RawAttempts, m.ConfirmedViolations, m.Blocked, m.Inconclusive, m.Errors)
	fmt.Fprintf(&b, "unique confirmed findings=%d\n\n", m.UniqueConfirmedFindings)

	fmt.Fprintf(&b, "finding yield/action      %s\n", ratioText(m.FindingYieldPerAction))
	fmt.Fprintf(&b, "verification rate         %s\n", ratioText(m.VerificationRate))
	fmt.Fprintf(&b, "invariant coverage        %s\n", ratioText(m.InvariantCoverage))
	fmt.Fprintf(&b, "benign task success rate  %s\n", ratioText(m.BenignTaskSuccessRate))
	fmt.Fprintf(&b, "cost per confirmed find   %s\n", ratioText(m.CostPerConfirmedFindingMS))

	if len(rec.Findings.Unique) > 0 {
		b.WriteString("\nfindings:\n")
		for _, f := range rec.Findings.Unique {
			fmt.Fprintf(&b, "  %s\n", f.String())
		}
	}
	if len(rec.Errors) > 0 {
		b.WriteString("\nevaluation errors:\n")
		for _, e := range rec.Errors {
			fmt.Fprintf(&b, "  %s\n", e)
		}
	}
	if rec.Reproducibility.Note != "" {
		fmt.Fprintf(&b, "\nreproducibility: %s\n", rec.Reproducibility.Note)
	}

	return b.String()
}

// ratioText prints an undefined ratio as "undefined" rather than as a
// number. A zero denominator means the figure does not exist; printing
// 0.0000 would make the worst possible result look like the best.
func ratioText(p *float64) string {
	if p == nil {
		return "undefined"
	}
	return fmt.Sprintf("%.4f", *p)
}

// listResearchSurface prints what an experiment can be built from,
// without running anything.
func listResearchSurface() string {
	var b strings.Builder

	b.WriteString("generators:\n")
	b.WriteString("  static    replays the registered attack corpus unchanged (the research baseline)\n")
	b.WriteString("  mutation  derives bounded variations of the seed workflows below\n")

	b.WriteString("\nregistered scenarios (static generator):\n")
	reg := harness.NewRegistry()
	if err := harness.RegisterAllScenarios(reg); err != nil {
		fmt.Fprintf(&b, "  unavailable: %v\n", err)
	} else {
		for _, s := range reg.All() {
			note := ""
			if experiment.IsPrivilegedScenario(s.ID) {
				note = "  [uses the insider bypass; needs --allow-privileged]"
			}
			fmt.Fprintf(&b, "  %-40s %-16s %s%s\n", s.ID, s.Category, s.TargetComponent, note)
		}
	}

	b.WriteString("\nseed workflows (mutation generator):\n")
	for _, sp := range experiment.SeedPlans() {
		fmt.Fprintf(&b, "  %-40s %d actions\n", sp.ID, sp.Plan.Len())
	}

	b.WriteString("\nmutations applied:\n")
	for _, k := range experiment.MutationKinds() {
		fmt.Fprintf(&b, "  %s\n", k)
	}

	b.WriteString("\nsecurity invariants (independent verification):\n")
	for _, inv := range experiment.CoreInvariants() {
		fmt.Fprintf(&b, "  %-40s %-9s %s\n", inv.ID, inv.Severity, inv.Component)
	}

	b.WriteString("\noperations a generated action may propose:\n")
	fmt.Fprintf(&b, "  %s\n", strings.Join(experiment.SupportedOps(), ", "))

	return b.String()
}

// loadNamedProfile resolves a profile by name against the directory the
// CLI's configured profile lives in, so a test pointing elsewhere keeps
// working.
func loadNamedProfile(env cliEnv, name string) (config.SecurityProfile, error) {
	if name == "" {
		return config.SecurityProfile{}, fmt.Errorf("--profile must not be empty")
	}
	dir := filepath.Dir(env.ProfilePath)
	path := filepath.Join(dir, name+".json")

	profile, err := config.Load(path)
	if err != nil {
		available, listErr := availableProfiles(dir)
		if listErr != nil || len(available) == 0 {
			return config.SecurityProfile{}, fmt.Errorf("load profile %q: %w", name, err)
		}
		return config.SecurityProfile{}, fmt.Errorf("load profile %q: %w (available: %s)",
			name, err, strings.Join(available, ", "))
	}
	return profile, nil
}

func availableProfiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(names)
	return names, nil
}

// writeRecord writes the machine-readable experiment record. It never
// creates intermediate directories: a path the caller got wrong should
// be reported, not silently materialised somewhere unexpected.
func writeRecord(path string, rec experiment.Record) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	defer f.Close()

	if err := rec.WriteJSON(f); err != nil {
		return err
	}
	return f.Close()
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
