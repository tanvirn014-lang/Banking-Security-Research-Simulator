package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// DefaultBaseURL is the local Ollama endpoint. Loopback by default and
// configurable, but never silently pointed elsewhere.
const DefaultBaseURL = "http://127.0.0.1:11434"

// Config is one model role's provider configuration. The assistant under
// test and the attack generator each get their own, so the target's
// model can never be changed by editing the attacker's settings or the
// other way round.
type Config struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"base_url"`
	Model    string `json:"model"`

	TimeoutSeconds  int     `json:"timeout_seconds"`
	Temperature     float64 `json:"temperature"`
	MaxOutputTokens int     `json:"max_output_tokens"`
	// MaxInputChars bounds how much text is sent in one request, as a
	// crude but effective stand-in for a token budget. Zero means
	// defaultMaxInputChars.
	MaxInputChars int `json:"max_input_chars"`
	// PromptVersion is recorded with every response, so a result can be
	// traced to the prompt that produced it.
	PromptVersion string `json:"prompt_version"`

	// RequireLocalModel is a pointer so that an absent field is an error
	// rather than a silent false. This follows the convention
	// config.Load already uses for the security profile's enforcement
	// flags, for the same reason: a safety control that can be disabled
	// by forgetting to mention it is not a control. Set it to false only
	// deliberately, and expect the provider to announce that it is
	// reaching an external host.
	RequireLocalModel *bool `json:"require_local_model"`
}

const (
	defaultTimeoutSeconds = 120
	defaultMaxOutputChars = 8192
	defaultMaxInputChars  = 24000
)

// Validate reports every way the configuration is unusable, as one
// error. It never repairs a value except through Effective.
func (c Config) Validate() error {
	var problems []string

	switch c.Provider {
	case ProviderOllama, ProviderMock:
	case "":
		problems = append(problems, "provider must be set")
	default:
		problems = append(problems, fmt.Sprintf("provider %q is not implemented", c.Provider))
	}
	if c.Model == "" {
		problems = append(problems, "model must be set -- no model tag is assumed")
	}
	if c.Provider == ProviderOllama && c.BaseURL == "" {
		problems = append(problems, "base_url must be set for the ollama provider")
	}
	if c.TimeoutSeconds < 0 {
		problems = append(problems, fmt.Sprintf("timeout_seconds must not be negative, got %d", c.TimeoutSeconds))
	}
	if c.Temperature < 0 || c.Temperature > 2 {
		problems = append(problems, fmt.Sprintf("temperature must be within [0, 2], got %v", c.Temperature))
	}
	if c.MaxOutputTokens < 0 {
		problems = append(problems, fmt.Sprintf("max_output_tokens must not be negative, got %d", c.MaxOutputTokens))
	}
	if c.MaxInputChars < 0 {
		problems = append(problems, fmt.Sprintf("max_input_chars must not be negative, got %d", c.MaxInputChars))
	}
	if c.RequireLocalModel == nil {
		problems = append(problems,
			"require_local_model must be stated explicitly (true or false) -- an absent value would leave the "+
				"local-only check off by omission, and this installation has models that proxy to an external host")
	}

	if len(problems) > 0 {
		return fmt.Errorf("llm config: %v", problems)
	}
	return nil
}

// Effective returns a copy with defaults applied.
func (c Config) Effective() Config {
	eff := c
	if eff.BaseURL == "" && eff.Provider == ProviderOllama {
		eff.BaseURL = DefaultBaseURL
	}
	if eff.TimeoutSeconds == 0 {
		eff.TimeoutSeconds = defaultTimeoutSeconds
	}
	if eff.MaxInputChars == 0 {
		eff.MaxInputChars = defaultMaxInputChars
	}
	return eff
}

// Timeout returns the configured per-request timeout.
func (c Config) Timeout() time.Duration {
	return time.Duration(c.Effective().TimeoutSeconds) * time.Second
}

// LocalOnly reports whether this configuration demands a genuinely local
// model. Safe to call on an unvalidated config: an absent value reads as
// "yes", so the stricter behaviour is the one a mistake produces.
func (c Config) LocalOnly() bool {
	return c.RequireLocalModel == nil || *c.RequireLocalModel
}

// Settings is the whole LLM configuration file: one provider
// configuration per role, kept separate on purpose.
type Settings struct {
	// Assistant configures the banking assistant under test. It needs a
	// tool-capable model.
	Assistant Config `json:"assistant"`
	// Generator configures the adversarial test generator. It needs
	// structured JSON output, not tools.
	Generator Config `json:"generator"`
	// ExperimentMode labels what this configuration is for, and is
	// recorded in experiment records.
	ExperimentMode string `json:"experiment_mode"`
}

// LoadSettings reads the LLM configuration from a JSON file. Unknown
// fields are rejected rather than ignored, matching config.Load: a
// misspelled safety setting must fail loudly, not be silently dropped.
func LoadSettings(path string) (Settings, error) {
	var empty Settings

	data, err := os.ReadFile(path)
	if err != nil {
		return empty, fmt.Errorf("read llm settings %s: %w", path, err)
	}

	var s Settings
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return empty, fmt.Errorf("decode llm settings %s: %w", path, err)
	}

	if err := s.Assistant.Validate(); err != nil {
		return empty, fmt.Errorf("llm settings %s: assistant: %w", path, err)
	}
	if err := s.Generator.Validate(); err != nil {
		return empty, fmt.Errorf("llm settings %s: generator: %w", path, err)
	}

	return s, nil
}
