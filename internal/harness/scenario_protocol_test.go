package harness

import (
	"context"
	"testing"
)

func runProtocolScenarioBothProfiles(t *testing.T, newScenario func() Scenario) {
	t.Helper()
	cases := []struct {
		name        string
		configPath  string
		wantSuccess bool
	}{
		{"hardened", "../../configs/hardened.json", false},
		{"vulnerable", "../../configs/vulnerable.json", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnvironment(t, tc.configPath)
			r := NewRunner()
			s := newScenario()

			result, err := r.Run(context.Background(), s, env, 1)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if result.Success != tc.wantSuccess {
				t.Fatalf("profile %q: expected Success=%v, got %v (result=%+v)", tc.name, tc.wantSuccess, result.Success, result)
			}
		})
	}
}

func TestScenario_Replay_SucceedsVulnerable_FailsHardened(t *testing.T) {
	runProtocolScenarioBothProfiles(t, NewReplayScenario)
}

func TestScenario_Tamper_SucceedsVulnerable_FailsHardened(t *testing.T) {
	runProtocolScenarioBothProfiles(t, NewTamperScenario)
}

func TestScenario_Downgrade_SucceedsVulnerable_FailsHardened(t *testing.T) {
	runProtocolScenarioBothProfiles(t, NewDowngradeScenario)
}
