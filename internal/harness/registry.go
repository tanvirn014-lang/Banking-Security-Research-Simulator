package harness

import (
	"fmt"
	"sync"
)

// Registry implements the user's "attack registration" and "attack
// discovery" requirements: a place every Scenario is registered once,
// by a unique ID, and can later be listed or looked up by ID/category
// without needing to know about it any other way.
//
// Register takes a factory (func() Scenario), not a Scenario value, and
// All/ByID/ByCategory call the stored factory fresh every time rather
// than returning a cached value. This matters because every real
// Scenario in this package (every NewXxxScenario constructor) captures
// its own per-run state (account IDs, captured frames, observed bytes)
// in closures -- a Scenario value by itself is not independent of other
// copies of "the same" scenario the way the factory that produced it is.
// Storing and returning plain Scenario values previously meant every
// lookup of the same registered ID shared the *same* underlying
// closures: running it once left stale results for the next lookup to
// inherit, and running it concurrently from two lookups was a data race
// on that shared state (security review finding I2).
type Registry interface {
	// Register adds factory, keyed by the ID the Scenario it produces
	// reports. Returns an error if that ID is empty or already
	// registered -- exactly one registry entry per attack ID. factory is
	// called once immediately, to learn the ID and validate it; every
	// later All/ByID/ByCategory call invokes it again, fresh.
	Register(factory func() Scenario) error
	// All returns a freshly-constructed Scenario per registered factory,
	// in registration order.
	All() []Scenario
	ByID(id string) (Scenario, bool)
	ByCategory(category string) []Scenario
}

type registry struct {
	mu        sync.Mutex
	factories map[string]func() Scenario
	order     []string
}

// NewRegistry constructs an empty Registry.
func NewRegistry() Registry {
	return &registry{factories: make(map[string]func() Scenario)}
}

func (r *registry) Register(factory func() Scenario) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	s := factory()
	if s.ID == "" {
		return fmt.Errorf("cannot register a scenario with an empty ID")
	}
	if _, exists := r.factories[s.ID]; exists {
		return fmt.Errorf("scenario ID %q already registered", s.ID)
	}
	r.factories[s.ID] = factory
	r.order = append(r.order, s.ID)
	return nil
}

func (r *registry) All() []Scenario {
	r.mu.Lock()
	factories := make([]func() Scenario, len(r.order))
	for i, id := range r.order {
		factories[i] = r.factories[id]
	}
	r.mu.Unlock()

	out := make([]Scenario, 0, len(factories))
	for _, factory := range factories {
		out = append(out, cloneScenario(factory()))
	}
	return out
}

func (r *registry) ByID(id string) (Scenario, bool) {
	r.mu.Lock()
	factory, ok := r.factories[id]
	r.mu.Unlock()
	if !ok {
		return Scenario{}, false
	}
	return cloneScenario(factory()), true
}

func (r *registry) ByCategory(category string) []Scenario {
	r.mu.Lock()
	factories := make([]func() Scenario, len(r.order))
	for i, id := range r.order {
		factories[i] = r.factories[id]
	}
	r.mu.Unlock()

	var out []Scenario
	for _, factory := range factories {
		s := factory()
		if s.Category == category {
			out = append(out, cloneScenario(s))
		}
	}
	return out
}

// cloneScenario deep-copies s's RequiredConfig map -- a Scenario value
// copy still aliases the original map (a reference type), so without
// this, mutating a map a caller's factory happens to close over would
// silently corrupt what a different reader sees (security review
// finding M5). This is defense in depth on top of the per-call factory
// invocation above: every one of this package's own factories builds
// RequiredConfig fresh (when it sets it at all), but a factory that
// didn't would still be protected here.
func cloneScenario(s Scenario) Scenario {
	if s.RequiredConfig == nil {
		return s
	}
	clone := s
	clone.RequiredConfig = make(map[string]string, len(s.RequiredConfig))
	for k, v := range s.RequiredConfig {
		clone.RequiredConfig[k] = v
	}
	return clone
}
