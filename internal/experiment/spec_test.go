package experiment

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func validSpec() ExperimentSpec {
	return ExperimentSpec{
		ExperimentID:   "exp-001",
		Objective:      "test_authorization_integrity",
		TargetProfile:  "hardened",
		Generator:      GeneratorStatic,
		Budget:         Budget{MaxActions: 20, MaxTests: 5},
		Seed:           42,
		StopConditions: []StopCondition{StopOnConfirmedViolation},
		Safety:         Safety{MaxAmount: 100_000},
	}
}

func TestSpec_ValidSpecAccepted(t *testing.T) {
	if err := validSpec().Validate(); err != nil {
		t.Fatalf("expected a valid spec to pass validation, got %v", err)
	}
}

func TestSpec_RejectsInvalidConfigurationsExplicitly(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*ExperimentSpec)
		wantSub string
	}{
		{"empty experiment id", func(s *ExperimentSpec) { s.ExperimentID = "" }, "experiment_id"},
		{"empty objective", func(s *ExperimentSpec) { s.Objective = "" }, "objective"},
		{"empty target profile", func(s *ExperimentSpec) { s.TargetProfile = "" }, "target_profile"},
		{"unknown generator", func(s *ExperimentSpec) { s.Generator = "psychic" }, "generator"},
		{"empty generator", func(s *ExperimentSpec) { s.Generator = "" }, "generator"},
		{"zero action budget", func(s *ExperimentSpec) { s.Budget.MaxActions = 0 }, "max_actions"},
		{"negative action budget", func(s *ExperimentSpec) { s.Budget.MaxActions = -1 }, "max_actions"},
		{"zero test budget", func(s *ExperimentSpec) { s.Budget.MaxTests = 0 }, "max_tests"},
		{"negative duration", func(s *ExperimentSpec) { s.Budget.MaxDuration = -time.Second }, "max_duration"},
		{"negative max amount", func(s *ExperimentSpec) { s.Safety.MaxAmount = -5 }, "max_amount"},
		{"unknown stop condition", func(s *ExperimentSpec) {
			s.StopConditions = []StopCondition{"when_bored"}
		}, "stop_condition"},
		{"unknown allowed op", func(s *ExperimentSpec) {
			s.Safety.AllowedOps = []string{"drop-database"}
		}, "allowed_ops"},
		{"unknown crypto profile", func(s *ExperimentSpec) { s.CryptoProfile = "rot13" }, "crypto_profile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := validSpec()
			tt.mutate(&s)
			err := s.Validate()
			if err == nil {
				t.Fatalf("expected %s to be rejected, got no error", tt.name)
			}
			if !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("expected ErrInvalidSpec, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("expected the error to name %q, got %q", tt.wantSub, err.Error())
			}
		})
	}
}

func TestSpec_MutationGeneratorRequiresSeedScenarios(t *testing.T) {
	s := validSpec()
	s.Generator = GeneratorMutation
	s.SeedScenarios = nil

	err := s.Validate()
	if err == nil {
		t.Fatal("expected a mutation experiment with no seed scenarios to be rejected")
	}
	if !strings.Contains(err.Error(), "seed_scenarios") {
		t.Fatalf("expected the error to name seed_scenarios, got %q", err.Error())
	}
}

func TestSpec_StaticGeneratorDoesNotRequireSeedScenarios(t *testing.T) {
	s := validSpec()
	s.Generator = GeneratorStatic
	s.SeedScenarios = nil

	if err := s.Validate(); err != nil {
		t.Fatalf("a static experiment should run the whole registry by default: %v", err)
	}
}

func TestSpec_EffectiveAppliesDefaultsWithoutMutatingReceiver(t *testing.T) {
	s := validSpec()
	s.Safety.AllowedOps = nil
	s.Safety.MaxAmount = 0

	eff := s.Effective()

	if len(eff.Safety.AllowedOps) == 0 {
		t.Fatal("Effective should fill in the default op allowlist")
	}
	if eff.Safety.MaxAmount <= 0 {
		t.Fatal("Effective should fill in a default max amount")
	}
	if s.Safety.AllowedOps != nil || s.Safety.MaxAmount != 0 {
		t.Fatal("Effective must not mutate its receiver -- the recorded spec and the written spec must stay distinguishable")
	}
}

func TestSpec_EffectiveIsIdempotent(t *testing.T) {
	once := validSpec().Effective()
	twice := once.Effective()

	if len(once.Safety.AllowedOps) != len(twice.Safety.AllowedOps) {
		t.Fatalf("Effective applied twice changed the allowlist: %v vs %v", once.Safety.AllowedOps, twice.Safety.AllowedOps)
	}
	if once.Safety.MaxAmount != twice.Safety.MaxAmount {
		t.Fatalf("Effective applied twice changed max amount: %d vs %d", once.Safety.MaxAmount, twice.Safety.MaxAmount)
	}
}

func TestSpec_EffectiveDoesNotAliasCallerSlices(t *testing.T) {
	s := validSpec()
	s.Safety.AllowedOps = []string{"balance", "deposit"}

	eff := s.Effective()
	eff.Safety.AllowedOps[0] = "transfer"

	if s.Safety.AllowedOps[0] != "balance" {
		t.Fatal("Effective aliased the caller's AllowedOps slice -- mutating the effective spec corrupted the original")
	}
}

func TestSpec_HasStopCondition(t *testing.T) {
	s := validSpec()
	if !s.HasStopCondition(StopOnConfirmedViolation) {
		t.Fatal("expected the spec to report its own stop condition")
	}
	if s.HasStopCondition(StopOnFirstError) {
		t.Fatal("expected the spec not to report a stop condition it does not declare")
	}
}
