package harness

import (
	"context"
	"testing"
)

func TestScenario_ConcurrentOverdraft_SucceedsVulnerable_FailsHardened(t *testing.T) {
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
			s := NewConcurrentOverdraftScenario()

			result, err := r.Run(context.Background(), s, env, 1)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if result.Success != tc.wantSuccess {
				t.Fatalf("profile %q: expected Success=%v, got %v (result=%+v)", tc.name, tc.wantSuccess, result.Success, result)
			}
			if tc.wantSuccess && (result.RecordsCompromised == nil || *result.RecordsCompromised <= 0) {
				t.Fatalf("expected a positive RecordsCompromised on a successful overdraft, got %v", result.RecordsCompromised)
			}
		})
	}
}

func TestScenario_AuthzBypass_SucceedsVulnerable_FailsHardened(t *testing.T) {
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
			s := NewAuthzBypassScenario()

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
