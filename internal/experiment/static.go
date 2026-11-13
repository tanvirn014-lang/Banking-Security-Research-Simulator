package experiment

import (
	"context"
	"fmt"
	"sync"

	"banksec-lab/internal/harness"
)

// privilegedScenarios names the registered scenarios whose Exec uses the
// harness's insider bypass (harness.PrivilegedAccess) rather than only
// the banking application's front door. Safety.AllowPrivileged gates
// these, so an experiment can be configured to exercise only attacks a
// remote client could actually mount.
//
// This list is maintained by hand because harness.Scenario does not
// declare its own capability use, and inferring it would mean either
// trusting a scenario's self-description or not knowing at all. A
// scenario added to the registry that uses env.Priv must be added here;
// TestStaticGenerator_PrivilegedListMatchesTheRegistry is the guard that
// notices when the registry grows.
var privilegedScenarios = map[string]struct{}{
	harness.LedgerTamperScenarioID: {},
	harness.AuditTamperScenarioID:  {},
	harness.KeyExposureScenarioID:  {},
}

// IsPrivilegedScenario reports whether a registered scenario uses the
// insider bypass.
func IsPrivilegedScenario(id string) bool {
	_, ok := privilegedScenarios[id]
	return ok
}

// StaticGenerator replays the registered attack corpus unchanged. It is
// the reproducible research baseline every other generator is compared
// against, so it deliberately does nothing clever: it hands back each
// selected scenario exactly as registered, in a fixed order, with no
// mutations recorded because there are none.
//
// Each Next fetches the scenario from the registry afresh rather than
// caching a value, because this project's scenarios capture per-run
// state in closures -- a cached Scenario value would share that state
// between candidates.
type StaticGenerator struct {
	registry harness.Registry
	ids      []string

	mu   sync.Mutex
	next int
}

// NewStaticGenerator selects scenarios from reg. only restricts the
// selection to the named scenario IDs, in the order given; empty means
// every registered scenario in registration order. allowPrivileged
// admits scenarios that use the insider bypass.
func NewStaticGenerator(reg harness.Registry, only []string, allowPrivileged bool) (*StaticGenerator, error) {
	if reg == nil {
		return nil, fmt.Errorf("static generator: registry must not be nil")
	}

	var ids []string
	if len(only) > 0 {
		for _, id := range only {
			if _, ok := reg.ByID(id); !ok {
				return nil, fmt.Errorf("static generator: scenario %q is not registered", id)
			}
			ids = append(ids, id)
		}
	} else {
		for _, s := range reg.All() {
			ids = append(ids, s.ID)
		}
	}

	if !allowPrivileged {
		kept := ids[:0:0]
		for _, id := range ids {
			if !IsPrivilegedScenario(id) {
				kept = append(kept, id)
			}
		}
		ids = kept
	}

	if len(ids) == 0 {
		return nil, fmt.Errorf("static generator: no scenarios selected (privileged scenarios allowed: %t)", allowPrivileged)
	}
	return &StaticGenerator{registry: reg, ids: ids}, nil
}

// ID identifies this generator in experiment records.
func (g *StaticGenerator) ID() string { return string(GeneratorStatic) }

// Selected returns the scenario IDs this generator will produce, in
// order. Recorded in the experiment record so a baseline run states
// exactly which corpus it covered.
func (g *StaticGenerator) Selected() []string {
	return append([]string(nil), g.ids...)
}

// Next returns the next baseline scenario, or ErrNoMoreCandidates once
// the selection is exhausted.
func (g *StaticGenerator) Next(_ context.Context, obs Observation) (Candidate, error) {
	g.mu.Lock()
	if g.next >= len(g.ids) {
		g.mu.Unlock()
		return Candidate{}, ErrNoMoreCandidates
	}
	id := g.ids[g.next]
	g.next++
	g.mu.Unlock()

	s, ok := g.registry.ByID(id)
	if !ok {
		// Only reachable if the registry changed under us, which this
		// project's registry does not allow -- but a baseline that
		// silently skipped a scenario would quietly weaken the
		// comparison it exists to anchor.
		return Candidate{}, fmt.Errorf("static generator: scenario %q vanished from the registry", id)
	}

	return Candidate{
		TestID:           id,
		GeneratorID:      g.ID(),
		SourceScenarioID: id,
		Seed:             obs.Spec.Seed,
		Scenario:         &s,
	}, nil
}
