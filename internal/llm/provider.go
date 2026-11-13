// Package llm is BankSec Lab's local model provider abstraction.
//
// It exists so the rest of the project can talk to a language model
// through one narrow interface, and so that every property the research
// design depends on -- that the model runs locally, that a failed
// request is an error rather than a degraded answer, that nothing is
// downloaded, that every response's provenance is recorded -- is
// enforced in one place rather than at each call site.
//
// All model output is untrusted input. Nothing in this package decides
// whether an action is permitted; it only transports requests and parses
// responses. Authorization lives in internal/assistant's tool gateway
// and in the banking application itself.
package llm

import (
	"context"
	"errors"
)

// Provider names.
const (
	ProviderOllama = "ollama"
	ProviderMock   = "mock"
)

// Sentinel errors, so a caller can distinguish "the model server is not
// there" from "the model said something unusable" from "this model would
// have sent your prompt to someone else's computer".
var (
	// ErrProviderUnavailable means the model server could not be
	// reached at all.
	ErrProviderUnavailable = errors.New("llm: model provider unavailable")
	// ErrModelUnavailable means the server is reachable but does not
	// have the requested model. Never resolved by downloading it.
	ErrModelUnavailable = errors.New("llm: model not installed")
	// ErrRemoteModel means the requested model proxies to an external
	// host, so using it would send prompt content off this machine.
	ErrRemoteModel = errors.New("llm: model is proxied to an external host")
	// ErrMissingCapability means the model cannot do something the role
	// requires, such as tool calling.
	ErrMissingCapability = errors.New("llm: model lacks a required capability")
	// ErrInvalidResponse means the model returned something that could
	// not be interpreted: malformed tool arguments, a tool that was
	// never offered, an unparseable body.
	ErrInvalidResponse = errors.New("llm: invalid model response")
)

// Capability names a model feature a role depends on. The values match
// what Ollama reports in /api/tags.
type Capability string

const (
	CapabilityCompletion Capability = "completion"
	CapabilityTools      Capability = "tools"
)

// Role identifies who a message is from.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// ToolCall is one tool invocation a model proposed.
//
// A proposal, never a decision: the gateway that receives it re-derives
// the acting principal from the session and ignores any actor, role,
// permission, or confirmation claim the model put in Arguments. See
// internal/assistant.ToolGateway.
type ToolCall struct {
	// ID is the model's own identifier for the call, used only to
	// correlate a tool result back to it. It is never treated as an
	// authorization or confirmation token.
	ID        string         `json:"id,omitempty"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// Message is one turn of a conversation.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content,omitempty"`
	// ToolCalls is set on an assistant message that proposed tools.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	// ToolName is set on a tool-result message, naming which tool
	// produced it.
	ToolName string `json:"tool_name,omitempty"`
}

// ToolSpec describes one tool offered to the model. Parameters is a JSON
// Schema object.
type ToolSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// ChatRequest is one model call.
type ChatRequest struct {
	Messages []Message
	// Tools, when non-empty, are the only tools the model may name. A
	// response naming anything else is rejected as invalid.
	Tools []ToolSpec
	// JSONOutput asks the provider for structured JSON. Used by the
	// attack generator, which needs a parseable candidate rather than
	// prose.
	JSONOutput bool
}

// ResponseMeta is everything about a response worth recording in an
// experiment: which model produced it, under which prompt version, how
// long it took, and whether it was cut short.
type ResponseMeta struct {
	Provider      string `json:"provider"`
	Model         string `json:"model"`
	PromptVersion string `json:"prompt_version,omitempty"`
	// Remote and RemoteHost record whether this response came from an
	// externally proxied model. Recorded rather than merely checked, so
	// a reader of an experiment record can tell where the inference
	// actually happened.
	Remote           bool   `json:"remote"`
	RemoteHost       string `json:"remote_host,omitempty"`
	DurationMS       int64  `json:"duration_ms"`
	PromptTokens     int    `json:"prompt_tokens,omitempty"`
	CompletionTokens int    `json:"completion_tokens,omitempty"`
	DoneReason       string `json:"done_reason,omitempty"`
	// Truncated is true when the response hit the output limit. A
	// truncated response is reported as such rather than treated as a
	// complete answer, because a tool call cut in half is not a smaller
	// tool call.
	Truncated bool `json:"truncated"`
}

// ChatResponse is one model reply.
type ChatResponse struct {
	Message Message
	Meta    ResponseMeta
}

// Provider is the narrow interface the rest of the project uses to
// reach a model. Implementations: OllamaProvider (a real local server)
// and MockProvider (deterministic, for the ordinary test suite).
//
// A Provider transports and parses. It never decides whether a proposed
// action is allowed.
type Provider interface {
	// Name is the provider kind, e.g. "ollama".
	Name() string
	// Model is the exact model tag in use, recorded in experiments.
	Model() string
	// Chat sends one request. A failure returns an error and a zero
	// response -- never partial or substituted content.
	Chat(ctx context.Context, req ChatRequest) (ChatResponse, error)
}
