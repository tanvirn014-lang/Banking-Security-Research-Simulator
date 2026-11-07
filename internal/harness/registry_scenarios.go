package harness

import "fmt"

// RegisterAllScenarios registers every attack Scenario implemented
// across Milestone 8's five groups into reg, for attack discovery (e.g.
// a future CLI command or benchmarking harness that wants to enumerate
// every available attack rather than hardcoding a list). Each
// NewXxxScenario constructor is itself passed as the factory -- Register
// calls it fresh for every later lookup (security review finding I2),
// so every run of a given attack ID gets its own independent closure
// state, never shared with or contaminated by another lookup of the
// same ID.
func RegisterAllScenarios(reg Registry) error {
	factories := []func() Scenario{
		NewConcurrentOverdraftScenario,
		NewAuthzBypassScenario,
		NewReplayScenario,
		NewTamperScenario,
		NewDowngradeScenario,
		NewLedgerTamperScenario,
		NewAuditTamperScenario,
		NewKeyExposureScenario,
		NewKeyRevocationScenario,
		NewToyRSAFactorAndForgeScenario,
		NewECBPatternLeakageScenario,
		NewDiffieHellmanDiscreteLogScenario,
	}
	for _, factory := range factories {
		if err := reg.Register(factory); err != nil {
			return fmt.Errorf("register scenario: %w", err)
		}
	}
	return nil
}
