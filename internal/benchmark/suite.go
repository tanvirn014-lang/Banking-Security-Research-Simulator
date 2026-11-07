package benchmark

import (
	"context"
	"fmt"

	"banksec-lab/internal/config"
	"banksec-lab/internal/harness"
)

// RunSuite is this package's "full attack-suite execution" entry point
// -- an addendum beyond docs/TASK_BREAKDOWN.md's own Tasks 46-49, which
// only ever cover running ONE Scenario comparatively. RunSuite calls
// RunComparative once per Scenario currently in reg (reg.All(), so the
// caller controls exactly which scenarios are "in the suite" by what
// they registered beforehand), keyed by each Scenario's own ID.
//
// Every scenario in the suite uses the SAME reps/seed/vulnerable/hardened
// parameters -- a single controlled experiment configuration applied
// across the whole registered attack surface, not a per-scenario
// bespoke setup. If any one scenario's RunComparative call fails
// outright (as opposed to an individual run within it failing, which
// RunComparative itself already preserves as a RawRun.RunErr), RunSuite
// stops and returns what it collected so far PLUS that error -- security
// review finding M7: an earlier version of this code claimed this in its
// own doc comment but didn't actually do it, discarding the failing
// scenario's partial raw results (everything RunComparative collected
// before it hit the error) instead of storing them under that
// scenario's own ID like every other entry in the map.
func RunSuite(ctx context.Context, h harness.Runner, reg harness.Registry, vulnerable, hardened config.SecurityProfile, reps int, seed int64) (map[string]RawResults, error) {
	results := make(map[string]RawResults)
	for _, scenario := range reg.All() {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		id := scenario.ID
		newScenario := func() harness.Scenario {
			s, _ := reg.ByID(id) // guaranteed present: id came from this same reg.All() call
			return s
		}
		raw, err := RunComparative(ctx, h, newScenario, vulnerable, hardened, reps, seed)
		results[id] = raw // store whatever was collected, even if err != nil (partial results)
		if err != nil {
			return results, fmt.Errorf("benchmark: RunSuite: scenario %s: %w", id, err)
		}
	}
	return results, nil
}
