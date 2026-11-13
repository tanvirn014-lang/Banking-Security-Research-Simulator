package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// tagsHandler serves a /api/tags payload shaped like the real Ollama
// one, including the remote_host field that marks a cloud-proxied model.
func tagsHandler(models []map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": models})
	}
}

func localModel(name string, caps ...string) map[string]any {
	return map[string]any{"name": name, "model": name, "size": 4_900_000_000, "capabilities": caps}
}

func cloudModel(name string, caps ...string) map[string]any {
	return map[string]any{
		"name": name, "model": name, "size": 384,
		"remote_host":  "https://ollama.com:443",
		"capabilities": caps,
	}
}

func testServer(t *testing.T, mux *http.ServeMux) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func baseConfig(baseURL, model string) Config {
	yes := true
	return Config{
		Provider:          ProviderOllama,
		BaseURL:           baseURL,
		Model:             model,
		TimeoutSeconds:    30,
		Temperature:       0,
		MaxOutputTokens:   256,
		PromptVersion:     "test-v1",
		RequireLocalModel: &yes,
	}
}

// The control that matters most: a model that proxies to an external
// host must be refused, because sending a prompt to it would ship
// synthetic banking data off the machine. It looks like an ordinary
// local tag in /api/tags, so only remote_host distinguishes it.
func TestProvider_RefusesACloudProxiedModel(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", tagsHandler([]map[string]any{
		localModel("llama3.1:8b", "completion", "tools"),
		cloudModel("gpt-oss:120b-cloud", "completion", "tools"),
	}))
	srv := testServer(t, mux)

	_, err := NewOllamaProvider(context.Background(), baseConfig(srv.URL, "gpt-oss:120b-cloud"), CapabilityTools)
	if err == nil {
		t.Fatal("expected a cloud-proxied model to be refused")
	}
	if !errors.Is(err, ErrRemoteModel) {
		t.Fatalf("expected ErrRemoteModel, got %v", err)
	}
	if !strings.Contains(err.Error(), "ollama.com") {
		t.Fatalf("the error should name the external host it would have reached, got %v", err)
	}
}

func TestProvider_AcceptsAGenuinelyLocalModel(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", tagsHandler([]map[string]any{
		localModel("llama3.1:8b", "completion", "tools"),
	}))
	srv := testServer(t, mux)

	p, err := NewOllamaProvider(context.Background(), baseConfig(srv.URL, "llama3.1:8b"), CapabilityTools)
	if err != nil {
		t.Fatalf("NewOllamaProvider: %v", err)
	}
	if p.Model() != "llama3.1:8b" {
		t.Fatalf("Model() = %q", p.Model())
	}
	if p.Name() != ProviderOllama {
		t.Fatalf("Name() = %q", p.Name())
	}
}

// The local-only check must be impossible to disable by omission: an
// absent require_local_model is a hard error, following the same
// convention config.Load already uses for the security profile's
// enforcement flags.
func TestProvider_RequireLocalModelMustBeStatedExplicitly(t *testing.T) {
	cfg := baseConfig("http://127.0.0.1:1", "llama3.1:8b")
	cfg.RequireLocalModel = nil

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an absent require_local_model to be rejected rather than defaulting")
	}
}

// Turning the check off is permitted but must be deliberate and
// explicit, and the provider must then still report what it connected
// to rather than hiding it.
func TestProvider_RemoteModelAllowedOnlyWhenExplicitlyPermitted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", tagsHandler([]map[string]any{
		cloudModel("gpt-oss:120b-cloud", "completion", "tools"),
	}))
	srv := testServer(t, mux)

	cfg := baseConfig(srv.URL, "gpt-oss:120b-cloud")
	no := false
	cfg.RequireLocalModel = &no

	p, err := NewOllamaProvider(context.Background(), cfg, CapabilityTools)
	if err != nil {
		t.Fatalf("explicitly permitting a remote model should work: %v", err)
	}
	if !p.IsRemote() {
		t.Fatal("a provider bound to a cloud-proxied model must report itself as remote")
	}
	if p.RemoteHost() == "" {
		t.Fatal("a remote provider must name the host it reaches")
	}
}

func TestProvider_RefusesAModelMissingARequiredCapability(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", tagsHandler([]map[string]any{
		localModel("gemma3:12b", "completion"), // no "tools"
	}))
	srv := testServer(t, mux)

	_, err := NewOllamaProvider(context.Background(), baseConfig(srv.URL, "gemma3:12b"), CapabilityTools)
	if err == nil {
		t.Fatal("expected a model without the tools capability to be refused for a tool-calling role")
	}
	if !errors.Is(err, ErrMissingCapability) {
		t.Fatalf("expected ErrMissingCapability, got %v", err)
	}
}

func TestProvider_AcceptsACompletionOnlyModelWhenToolsAreNotRequired(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", tagsHandler([]map[string]any{
		localModel("gemma3:12b", "completion"),
	}))
	srv := testServer(t, mux)

	if _, err := NewOllamaProvider(context.Background(), baseConfig(srv.URL, "gemma3:12b")); err != nil {
		t.Fatalf("a completion-only model is fine for a role needing no tools: %v", err)
	}
}

func TestProvider_RefusesAnUninstalledModelAndListsWhatIsInstalled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", tagsHandler([]map[string]any{
		localModel("llama3.1:8b", "completion", "tools"),
	}))
	srv := testServer(t, mux)

	_, err := NewOllamaProvider(context.Background(), baseConfig(srv.URL, "mistral:7b"))
	if err == nil {
		t.Fatal("expected an uninstalled model to be refused")
	}
	if !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("expected ErrModelUnavailable, got %v", err)
	}
	// It must not offer to pull it, and it should say what is there.
	if !strings.Contains(err.Error(), "llama3.1:8b") {
		t.Fatalf("the error should list the installed models, got %v", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "pull") {
		t.Fatalf("the provider must never suggest or perform a model pull, got %v", err)
	}
}

func TestProvider_ReportsAnUnreachableServerClearly(t *testing.T) {
	cfg := baseConfig("http://127.0.0.1:1", "llama3.1:8b")
	cfg.TimeoutSeconds = 1

	_, err := NewOllamaProvider(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected an unreachable server to be reported")
	}
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected ErrProviderUnavailable, got %v", err)
	}
}

// chatMux serves /api/tags plus a scripted /api/chat.
func chatMux(t *testing.T, models []map[string]any, chat func(w http.ResponseWriter, r *http.Request)) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", tagsHandler(models))
	mux.HandleFunc("/api/chat", chat)
	return mux
}

func TestProvider_ParsesAToolCall(t *testing.T) {
	var gotBody map[string]any
	mux := chatMux(t, []map[string]any{localModel("llama3.1:8b", "completion", "tools")},
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"model": "llama3.1:8b",
				"message": map[string]any{
					"role": "assistant",
					"tool_calls": []map[string]any{{
						"id": "call_1",
						"function": map[string]any{
							"name":      "get_balance",
							"arguments": map[string]any{"account": "acct-1"},
						},
					}},
				},
				"done_reason":       "stop",
				"prompt_eval_count": 42,
				"eval_count":        7,
			})
		})
	srv := testServer(t, mux)

	p, err := NewOllamaProvider(context.Background(), baseConfig(srv.URL, "llama3.1:8b"), CapabilityTools)
	if err != nil {
		t.Fatalf("NewOllamaProvider: %v", err)
	}

	resp, err := p.Chat(context.Background(), ChatRequest{
		Messages: []Message{{Role: RoleUser, Content: "balance?"}},
		Tools: []ToolSpec{{
			Name:        "get_balance",
			Description: "get a balance",
			Parameters:  map[string]any{"type": "object"},
		}},
	})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}

	if len(resp.Message.ToolCalls) != 1 {
		t.Fatalf("tool calls = %d, want 1", len(resp.Message.ToolCalls))
	}
	tc := resp.Message.ToolCalls[0]
	if tc.Name != "get_balance" || tc.Arguments["account"] != "acct-1" {
		t.Fatalf("tool call = %+v", tc)
	}
	if resp.Meta.Model != "llama3.1:8b" || resp.Meta.PromptVersion != "test-v1" {
		t.Fatalf("meta = %+v, want the model and prompt version recorded", resp.Meta)
	}
	if resp.Meta.PromptTokens != 42 || resp.Meta.CompletionTokens != 7 {
		t.Fatalf("token counts not recorded: %+v", resp.Meta)
	}
	if gotBody["stream"] != false {
		t.Fatal("the provider must not request a streamed response")
	}
}

// Ollama has been observed to return tool-call arguments as a JSON
// string rather than an object. Both must parse, or the integration
// breaks on a model-version change.
func TestProvider_ParsesToolArgumentsGivenAsAJSONString(t *testing.T) {
	mux := chatMux(t, []map[string]any{localModel("llama3.1:8b", "completion", "tools")},
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"model":"llama3.1:8b","message":{"role":"assistant","tool_calls":[
				{"function":{"name":"get_balance","arguments":"{\"account\":\"acct-7\"}"}}]},"done_reason":"stop"}`))
		})
	srv := testServer(t, mux)

	p, _ := NewOllamaProvider(context.Background(), baseConfig(srv.URL, "llama3.1:8b"), CapabilityTools)
	resp, err := p.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if len(resp.Message.ToolCalls) != 1 || resp.Message.ToolCalls[0].Arguments["account"] != "acct-7" {
		t.Fatalf("string-encoded arguments were not parsed: %+v", resp.Message.ToolCalls)
	}
}

func TestProvider_MalformedToolArgumentsAreAnErrorNotASilentEmptyCall(t *testing.T) {
	mux := chatMux(t, []map[string]any{localModel("llama3.1:8b", "completion", "tools")},
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"model":"llama3.1:8b","message":{"role":"assistant","tool_calls":[
				{"function":{"name":"get_balance","arguments":"{not json"}}]},"done_reason":"stop"}`))
		})
	srv := testServer(t, mux)

	p, _ := NewOllamaProvider(context.Background(), baseConfig(srv.URL, "llama3.1:8b"), CapabilityTools)
	_, err := p.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if err == nil {
		t.Fatal("malformed tool arguments must be an error, not a call with empty arguments")
	}
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("expected ErrInvalidResponse, got %v", err)
	}
}

func TestProvider_RefusesAToolCallNamingAnUnofferedTool(t *testing.T) {
	mux := chatMux(t, []map[string]any{localModel("llama3.1:8b", "completion", "tools")},
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"model":"llama3.1:8b","message":{"role":"assistant","tool_calls":[
				{"function":{"name":"exec_sql","arguments":{}}}]},"done_reason":"stop"}`))
		})
	srv := testServer(t, mux)

	p, _ := NewOllamaProvider(context.Background(), baseConfig(srv.URL, "llama3.1:8b"), CapabilityTools)
	_, err := p.Chat(context.Background(), ChatRequest{
		Messages: []Message{{Role: RoleUser, Content: "x"}},
		Tools:    []ToolSpec{{Name: "get_balance", Parameters: map[string]any{"type": "object"}}},
	})
	if err == nil {
		t.Fatal("a tool call naming a tool that was never offered must be rejected at the provider edge")
	}
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("expected ErrInvalidResponse, got %v", err)
	}
}

func TestProvider_HTTPErrorIsReportedNotSwallowed(t *testing.T) {
	mux := chatMux(t, []map[string]any{localModel("llama3.1:8b", "completion", "tools")},
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":"model requires more system memory"}`, http.StatusInternalServerError)
		})
	srv := testServer(t, mux)

	p, _ := NewOllamaProvider(context.Background(), baseConfig(srv.URL, "llama3.1:8b"), CapabilityTools)
	_, err := p.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if err == nil {
		t.Fatal("an HTTP error from the model server must surface")
	}
	if !strings.Contains(err.Error(), "system memory") {
		t.Fatalf("the server's own error text should be preserved, got %v", err)
	}
}

func TestProvider_TimesOutRatherThanHanging(t *testing.T) {
	mux := chatMux(t, []map[string]any{localModel("llama3.1:8b", "completion", "tools")},
		func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(2 * time.Second)
		})
	srv := testServer(t, mux)

	cfg := baseConfig(srv.URL, "llama3.1:8b")
	cfg.TimeoutSeconds = 1
	p, _ := NewOllamaProvider(context.Background(), cfg, CapabilityTools)

	start := time.Now()
	if _, err := p.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}}); err == nil {
		t.Fatal("expected a timeout")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the configured timeout was not honoured: waited %s", elapsed)
	}
}

func TestProvider_MarksATruncatedResponse(t *testing.T) {
	mux := chatMux(t, []map[string]any{localModel("llama3.1:8b", "completion")},
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"model":"llama3.1:8b","message":{"role":"assistant","content":"partial"},"done_reason":"length"}`))
		})
	srv := testServer(t, mux)

	p, _ := NewOllamaProvider(context.Background(), baseConfig(srv.URL, "llama3.1:8b"))
	resp, err := p.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if !resp.Meta.Truncated {
		t.Fatal("a response cut off by the output limit must be marked truncated, not treated as complete")
	}
}

func TestProvider_SendsGenerationOptionsAndJSONFormat(t *testing.T) {
	var body map[string]any
	mux := chatMux(t, []map[string]any{localModel("gemma3:12b", "completion")},
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&body)
			_, _ = w.Write([]byte(`{"model":"gemma3:12b","message":{"role":"assistant","content":"{}"},"done_reason":"stop"}`))
		})
	srv := testServer(t, mux)

	cfg := baseConfig(srv.URL, "gemma3:12b")
	cfg.Temperature = 0.7
	cfg.MaxOutputTokens = 400
	p, _ := NewOllamaProvider(context.Background(), cfg)

	if _, err := p.Chat(context.Background(), ChatRequest{
		Messages:   []Message{{Role: RoleUser, Content: "x"}},
		JSONOutput: true,
	}); err != nil {
		t.Fatalf("Chat: %v", err)
	}

	if body["format"] != "json" {
		t.Fatalf("format = %v, want json", body["format"])
	}
	opts, _ := body["options"].(map[string]any)
	if opts["temperature"] != 0.7 {
		t.Fatalf("temperature = %v, want 0.7", opts["temperature"])
	}
	if opts["num_predict"] != float64(400) {
		t.Fatalf("num_predict = %v, want 400", opts["num_predict"])
	}
}

// A failed request must never become an unrelated answer.
func TestProvider_NoSilentFallbackOnFailure(t *testing.T) {
	mux := chatMux(t, []map[string]any{localModel("llama3.1:8b", "completion")},
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusBadGateway)
		})
	srv := testServer(t, mux)

	p, _ := NewOllamaProvider(context.Background(), baseConfig(srv.URL, "llama3.1:8b"))
	resp, err := p.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if resp.Message.Content != "" || len(resp.Message.ToolCalls) != 0 {
		t.Fatalf("a failed request must return no usable content, got %+v", resp.Message)
	}
}
