package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// OllamaProvider talks to a local Ollama server over its chat API.
//
// Construction verifies the model before any prompt is ever sent: that
// the server is reachable, that the exact tag is installed, that it is
// not proxied to an external host, and that it has the capabilities the
// role requires. Nothing is downloaded and nothing is substituted -- an
// unavailable model is an error, because quietly answering from a
// different model would invalidate every experiment record that named
// the first one.
type OllamaProvider struct {
	cfg        Config
	http       *http.Client
	remote     bool
	remoteHost string
}

// modelInfo is the subset of /api/tags this package reads.
type modelInfo struct {
	Name string `json:"name"`
	// RemoteHost is non-empty for a model Ollama proxies to someone
	// else's server. These appear in /api/tags looking exactly like
	// local tags, so this field is the only thing distinguishing a model
	// that runs on this machine from one that receives a copy of every
	// prompt.
	RemoteHost   string   `json:"remote_host"`
	Capabilities []string `json:"capabilities"`
}

// NewOllamaProvider verifies the configured model and returns a provider
// bound to it. required names capabilities the calling role depends on.
func NewOllamaProvider(ctx context.Context, cfg Config, required ...Capability) (*OllamaProvider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	eff := cfg.Effective()

	client := &http.Client{Timeout: eff.Timeout()}

	info, installed, err := fetchModelInfo(ctx, client, eff.BaseURL, eff.Model)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, fmt.Errorf("%w: %q is not installed on %s (installed: %s); install it yourself with the ollama CLI -- this provider never fetches a model",
			ErrModelUnavailable, eff.Model, eff.BaseURL, strings.Join(installed, ", "))
	}

	if info.RemoteHost != "" && eff.LocalOnly() {
		return nil, fmt.Errorf("%w: %q is proxied to %s, so using it would send prompt content off this machine; "+
			"choose a local model, or set require_local_model to false deliberately",
			ErrRemoteModel, eff.Model, info.RemoteHost)
	}

	for _, want := range required {
		if !hasCapability(info.Capabilities, want) {
			return nil, fmt.Errorf("%w: %q reports capabilities %v, which does not include %q",
				ErrMissingCapability, eff.Model, info.Capabilities, want)
		}
	}

	return &OllamaProvider{
		cfg:        eff,
		http:       client,
		remote:     info.RemoteHost != "",
		remoteHost: info.RemoteHost,
	}, nil
}

// Name reports the provider kind.
func (p *OllamaProvider) Name() string { return ProviderOllama }

// Model reports the exact model tag in use.
func (p *OllamaProvider) Model() string { return p.cfg.Model }

// IsRemote reports whether this provider is bound to an externally
// proxied model. True only when the operator explicitly disabled the
// local-only check.
func (p *OllamaProvider) IsRemote() bool { return p.remote }

// RemoteHost names the external host, if any.
func (p *OllamaProvider) RemoteHost() string { return p.remoteHost }

// BaseURL reports the endpoint in use.
func (p *OllamaProvider) BaseURL() string { return p.cfg.BaseURL }

// fetchModelInfo reads /api/tags and returns the entry for model, plus
// the list of everything installed for a useful error message. A nil
// info with a nil error means the server answered but does not have that
// model.
func fetchModelInfo(ctx context.Context, client *http.Client, baseURL, model string) (*modelInfo, []string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/api/tags", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: build tags request: %v", ErrProviderUnavailable, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: cannot reach %s: %v", ErrProviderUnavailable, baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, nil, fmt.Errorf("%w: %s returned %s listing models: %s",
			ErrProviderUnavailable, baseURL, resp.Status, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Models []modelInfo `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, nil, fmt.Errorf("%w: decoding the model list from %s: %v", ErrProviderUnavailable, baseURL, err)
	}

	installed := make([]string, 0, len(payload.Models))
	var found *modelInfo
	for i := range payload.Models {
		installed = append(installed, payload.Models[i].Name)
		if payload.Models[i].Name == model {
			found = &payload.Models[i]
		}
	}
	sort.Strings(installed)

	return found, installed, nil
}

func hasCapability(have []string, want Capability) bool {
	for _, c := range have {
		if Capability(c) == want {
			return true
		}
	}
	return false
}

// ollamaChatRequest mirrors the fields of Ollama's /api/chat this
// package sends. stream is always false: a streamed reply would have to
// be reassembled before it could be validated, and partial tool calls
// must never be acted on.
type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Tools    []ollamaTool    `json:"tools,omitempty"`
	Stream   bool            `json:"stream"`
	Format   string          `json:"format,omitempty"`
	Options  map[string]any  `json:"options,omitempty"`
}

type ollamaMessage struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	ToolCalls []ollamaToolCall `json:"tool_calls,omitempty"`
	ToolName  string           `json:"tool_name,omitempty"`
}

type ollamaTool struct {
	Type     string         `json:"type"`
	Function ollamaFunction `json:"function"`
}

type ollamaFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type ollamaToolCall struct {
	ID       string `json:"id"`
	Function struct {
		Name string `json:"name"`
		// Arguments is json.RawMessage because Ollama has been observed
		// to send it both as an object and as a JSON-encoded string,
		// depending on model and version. Both are accepted; anything
		// else is an error rather than an empty-argument call.
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type ollamaChatResponse struct {
	Model      string        `json:"model"`
	Message    ollamaMessage `json:"-"`
	RawMessage struct {
		Role      string           `json:"role"`
		Content   string           `json:"content"`
		ToolCalls []ollamaToolCall `json:"tool_calls"`
	} `json:"message"`
	DoneReason      string `json:"done_reason"`
	PromptEvalCount int    `json:"prompt_eval_count"`
	EvalCount       int    `json:"eval_count"`
	Error           string `json:"error"`
}

// Chat sends one request to the local model.
//
// On any failure it returns a zero ChatResponse alongside the error:
// there is deliberately no fallback, no retry with a different model,
// and no partial content, because a caller that received usable-looking
// content from a failed request could not tell the difference.
func (p *OllamaProvider) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	if len(req.Messages) == 0 {
		return ChatResponse{}, fmt.Errorf("llm: chat request has no messages")
	}
	if err := p.checkInputSize(req); err != nil {
		return ChatResponse{}, err
	}

	body := ollamaChatRequest{
		Model:    p.cfg.Model,
		Messages: toOllamaMessages(req.Messages),
		Stream:   false,
		Options: map[string]any{
			"temperature": p.cfg.Temperature,
		},
	}
	if p.cfg.MaxOutputTokens > 0 {
		body.Options["num_predict"] = p.cfg.MaxOutputTokens
	}
	if req.JSONOutput {
		body.Format = "json"
	}
	for _, t := range req.Tools {
		body.Tools = append(body.Tools, ollamaTool{
			Type:     "function",
			Function: ollamaFunction{Name: t.Name, Description: t.Description, Parameters: t.Parameters},
		})
	}

	raw, err := json.Marshal(body)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("llm: encode chat request: %w", err)
	}

	start := time.Now()
	httpResp, err := p.post(ctx, "/api/chat", raw)
	if err != nil {
		return ChatResponse{}, err
	}
	defer httpResp.Body.Close()

	payloadBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, int64(p.maxResponseBytes())))
	if err != nil {
		return ChatResponse{}, fmt.Errorf("%w: reading the response body: %v", ErrInvalidResponse, err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return ChatResponse{}, fmt.Errorf("llm: %s returned %s: %s",
			p.cfg.BaseURL, httpResp.Status, strings.TrimSpace(string(payloadBytes)))
	}

	var payload ollamaChatResponse
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return ChatResponse{}, fmt.Errorf("%w: decoding the chat response: %v", ErrInvalidResponse, err)
	}
	if payload.Error != "" {
		return ChatResponse{}, fmt.Errorf("llm: model server reported an error: %s", payload.Error)
	}

	calls, err := p.parseToolCalls(payload.RawMessage.ToolCalls, req.Tools)
	if err != nil {
		return ChatResponse{}, err
	}

	return ChatResponse{
		Message: Message{
			Role:      RoleAssistant,
			Content:   payload.RawMessage.Content,
			ToolCalls: calls,
		},
		Meta: ResponseMeta{
			Provider:         ProviderOllama,
			Model:            p.cfg.Model,
			PromptVersion:    p.cfg.PromptVersion,
			Remote:           p.remote,
			RemoteHost:       p.remoteHost,
			DurationMS:       time.Since(start).Milliseconds(),
			PromptTokens:     payload.PromptEvalCount,
			CompletionTokens: payload.EvalCount,
			DoneReason:       payload.DoneReason,
			Truncated:        payload.DoneReason == "length",
		},
	}, nil
}

func (p *OllamaProvider) post(ctx context.Context, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(p.cfg.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrProviderUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrProviderUnavailable, p.cfg.BaseURL, err)
	}
	return resp, nil
}

// checkInputSize refuses an oversized prompt rather than letting the
// server silently truncate it, which would make the recorded prompt and
// the prompt actually evaluated two different things.
func (p *OllamaProvider) checkInputSize(req ChatRequest) error {
	total := 0
	for _, m := range req.Messages {
		total += len(m.Content)
	}
	if limit := p.cfg.MaxInputChars; limit > 0 && total > limit {
		return fmt.Errorf("llm: request of %d characters exceeds max_input_chars of %d", total, limit)
	}
	return nil
}

func (p *OllamaProvider) maxResponseBytes() int {
	if p.cfg.MaxOutputTokens > 0 {
		// A generous bytes-per-token margin; the point is a hard ceiling,
		// not a precise one.
		return p.cfg.MaxOutputTokens * 32
	}
	return defaultMaxOutputChars * 4
}

// parseToolCalls converts the wire form into ToolCalls, rejecting
// anything unusable.
//
// A call naming a tool that was never offered is refused here, at the
// provider edge, even though the gateway would refuse it again. Two
// independent refusals is the point: this one keeps an unoffered name
// out of the conversation entirely, and the gateway's keeps it out of
// the banking system.
func (p *OllamaProvider) parseToolCalls(in []ollamaToolCall, offered []ToolSpec) ([]ToolCall, error) {
	if len(in) == 0 {
		return nil, nil
	}

	allowed := make(map[string]bool, len(offered))
	for _, t := range offered {
		allowed[t.Name] = true
	}

	out := make([]ToolCall, 0, len(in))
	for i, c := range in {
		name := c.Function.Name
		if name == "" {
			return nil, fmt.Errorf("%w: tool call %d has no name", ErrInvalidResponse, i)
		}
		if len(offered) > 0 && !allowed[name] {
			return nil, fmt.Errorf("%w: the model called %q, which was never offered to it", ErrInvalidResponse, name)
		}

		args, err := decodeToolArguments(c.Function.Arguments)
		if err != nil {
			return nil, fmt.Errorf("%w: tool call %d (%s): %v", ErrInvalidResponse, i, name, err)
		}

		out = append(out, ToolCall{ID: c.Function.Name + "-" + c.ID, Name: name, Arguments: args})
	}
	return out, nil
}

// decodeToolArguments accepts arguments as a JSON object or as a
// JSON-encoded string containing one. Anything else is an error: a tool
// call whose arguments could not be read is not a call with no
// arguments, and treating it as one would send an argument-free
// operation to the gateway as though the model had asked for it.
func decodeToolArguments(raw json.RawMessage) (map[string]any, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return map[string]any{}, nil
	}

	var asObject map[string]any
	if err := json.Unmarshal(trimmed, &asObject); err == nil {
		return asObject, nil
	}

	var asString string
	if err := json.Unmarshal(trimmed, &asString); err == nil {
		if strings.TrimSpace(asString) == "" {
			return map[string]any{}, nil
		}
		var nested map[string]any
		if err := json.Unmarshal([]byte(asString), &nested); err != nil {
			return nil, fmt.Errorf("arguments were a string but not JSON: %v", err)
		}
		return nested, nil
	}

	return nil, fmt.Errorf("arguments are neither a JSON object nor a JSON string")
}

func toOllamaMessages(in []Message) []ollamaMessage {
	out := make([]ollamaMessage, 0, len(in))
	for _, m := range in {
		om := ollamaMessage{Role: string(m.Role), Content: m.Content, ToolName: m.ToolName}
		for _, c := range m.ToolCalls {
			var tc ollamaToolCall
			tc.ID = c.ID
			tc.Function.Name = c.Name
			if c.Arguments != nil {
				if encoded, err := json.Marshal(c.Arguments); err == nil {
					tc.Function.Arguments = encoded
				}
			}
			om.ToolCalls = append(om.ToolCalls, tc)
		}
		out = append(out, om)
	}
	return out
}
