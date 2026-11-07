package harness

import (
	"fmt"
	"sync"
)

// Registry implements the user's "attack registration" and "attack
// discovery" requirements: a place every Scenario is registered once,
// by a unique ID, and can later be listed or looked up by ID/category
// without needing to know about it any other way.
type Registry interface {
	// Register adds s. Returns an error if s.ID is empty or already
	// registered -- exactly one registry entry per attack ID.
	Register(s Scenario) error
	// All returns every registered Scenario, in registration order.
	All() []Scenario
	ByID(id string) (Scenario, bool)
	ByCategory(category string) []Scenario
}

type registry struct {
	mu        sync.Mutex
	scenarios map[string]Scenario
	order     []string
}

// NewRegistry constructs an empty Registry.
func NewRegistry() Registry {
	return &registry{scenarios: make(map[string]Scenario)}
}

func (r *registry) Register(s Scenario) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.ID == "" {
		return fmt.Errorf("cannot register a scenario with an empty ID")
	}
	if _, exists := r.scenarios[s.ID]; exists {
		return fmt.Errorf("scenario ID %q already registered", s.ID)
	}
	r.scenarios[s.ID] = cloneScenario(s)
	r.order = append(r.order, s.ID)
	return nil
}

func (r *registry) All() []Scenario {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Scenario, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, cloneScenario(r.scenarios[id]))
	}
	return out
}

func (r *registry) ByID(id string) (Scenario, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.scenarios[id]
	return cloneScenario(s), ok
}

func (r *registry) ByCategory(category string) []Scenario {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Scenario
	for _, id := range r.order {
		if r.scenarios[id].Category == category {
			out = append(out, cloneScenario(r.scenarios[id]))
		}
	}
	return out
}

// cloneScenario deep-copies s's RequiredConfig map -- a Scenario value
// copy still aliases the original map (a reference type), so without
// this, mutating a map a caller passed to Register, or one returned by
// All/ByID/ByCategory, would silently corrupt the registry's own stored
// copy or vice versa (security review finding M5).
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
