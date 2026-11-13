package llm

import (
	"context"
	"fmt"
	"sync"
)

// MockTurn is one scripted model reply.
type MockTurn struct {
	// Content is the assistant's text reply.
	Content string
	// ToolCalls are the tool invocations this turn proposes.
	ToolCalls []ToolCall
	// Err, when set, makes this turn fail instead of replying -- for
	// exercising model-unavailable and malformed-response handling
	// without a server.
	Err error
	// Truncated marks the reply as cut off by the output limit.
	Truncated bool
}

// MockProvider is a deterministic Provider for the ordinary test suite.
//
// It exists so that `go test ./...` never needs a running model server:
// the project's own correctness must be verifiable without one, and a
// test suite whose results depend on a 12-billion-parameter model's mood
// is not a test suite. Integration tests against a real local model live
// behind the `llmlive` build tag instead.
//
// A MockProvider replies from a fixed script, in order. When the script
// runs out it returns an error rather than repeating or inventing a
// reply, so a test that drives more turns than it scripted fails loudly
// instead of passing on an accident.
type MockProvider struct {
	model string

	mu    sync.Mutex
	turns []MockTurn
	next  int
	calls []ChatRequest
}

// NewMockProvider builds a provider that replies with the given turns in
// order.
func NewMockProvider(model string, turns ...MockTurn) *MockProvider {
	return &MockProvider{model: model, turns: turns}
}

// Name reports the provider kind.
func (m *MockProvider) Name() string { return ProviderMock }

// Model reports the configured model label.
func (m *MockProvider) Model() string { return m.model }

// Chat returns the next scripted turn.
func (m *MockProvider) Chat(_ context.Context, req ChatRequest) (ChatResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, req)

	if m.next >= len(m.turns) {
		return ChatResponse{}, fmt.Errorf("mock provider: no scripted turn %d (only %d were scripted)", m.next, len(m.turns))
	}
	turn := m.turns[m.next]
	m.next++

	if turn.Err != nil {
		// A failed turn returns no usable content, exactly as the real
		// provider does.
		return ChatResponse{}, turn.Err
	}

	doneReason := "stop"
	if turn.Truncated {
		doneReason = "length"
	}

	return ChatResponse{
		Message: Message{Role: RoleAssistant, Content: turn.Content, ToolCalls: turn.ToolCalls},
		Meta: ResponseMeta{
			Provider:      ProviderMock,
			Model:         m.model,
			PromptVersion: "mock",
			DoneReason:    doneReason,
			Truncated:     turn.Truncated,
		},
	}, nil
}

// Calls returns every request this provider received, so a test can
// assert what the assistant actually sent -- for example that a tool
// result was fed back, or that no system prompt leaked a secret.
func (m *MockProvider) Calls() []ChatRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]ChatRequest(nil), m.calls...)
}

// CallCount reports how many requests were made.
func (m *MockProvider) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// Remaining reports how many scripted turns are unused, so a test can
// assert that it exercised everything it set up.
func (m *MockProvider) Remaining() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.turns) - m.next
}
