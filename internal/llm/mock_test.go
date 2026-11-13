package llm

import (
	"context"
	"errors"
	"testing"
)

func TestMock_RepliesInOrder(t *testing.T) {
	p := NewMockProvider("mock:test",
		MockTurn{Content: "first"},
		MockTurn{Content: "second"},
	)

	for _, want := range []string{"first", "second"} {
		resp, err := p.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
		if err != nil {
			t.Fatalf("Chat: %v", err)
		}
		if resp.Message.Content != want {
			t.Fatalf("content = %q, want %q", resp.Message.Content, want)
		}
	}
	if p.Remaining() != 0 {
		t.Fatalf("remaining = %d, want 0", p.Remaining())
	}
}

// A test that drives more turns than it scripted must fail loudly, not
// quietly receive a repeat of the last reply.
func TestMock_ExhaustedScriptIsAnErrorNotARepeat(t *testing.T) {
	p := NewMockProvider("mock:test", MockTurn{Content: "only"})

	if _, err := p.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: RoleUser}}}); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if _, err := p.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: RoleUser}}}); err == nil {
		t.Fatal("expected an exhausted script to error rather than repeat")
	}
}

func TestMock_ScriptedFailureReturnsNoUsableContent(t *testing.T) {
	sentinel := errors.New("model unavailable")
	p := NewMockProvider("mock:test", MockTurn{Content: "ignored", Err: sentinel})

	resp, err := p.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: RoleUser}}})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected the scripted error, got %v", err)
	}
	if resp.Message.Content != "" || len(resp.Message.ToolCalls) != 0 {
		t.Fatalf("a failed turn must yield no content, got %+v", resp.Message)
	}
}

func TestMock_RecordsWhatItWasAsked(t *testing.T) {
	p := NewMockProvider("mock:test", MockTurn{Content: "ok"})

	_, _ = p.Chat(context.Background(), ChatRequest{
		Messages: []Message{{Role: RoleSystem, Content: "sys"}, {Role: RoleUser, Content: "hello"}},
		Tools:    []ToolSpec{{Name: "get_balance"}},
	})

	calls := p.Calls()
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	if len(calls[0].Messages) != 2 || calls[0].Messages[1].Content != "hello" {
		t.Fatalf("the request was not recorded faithfully: %+v", calls[0].Messages)
	}
	if len(calls[0].Tools) != 1 {
		t.Fatal("the offered tools were not recorded")
	}
}

func TestMock_TruncationIsReported(t *testing.T) {
	p := NewMockProvider("mock:test", MockTurn{Content: "half", Truncated: true})

	resp, _ := p.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: RoleUser}}})
	if !resp.Meta.Truncated || resp.Meta.DoneReason != "length" {
		t.Fatalf("truncation not reported: %+v", resp.Meta)
	}
}

func TestMock_SatisfiesTheProviderInterface(t *testing.T) {
	var _ Provider = NewMockProvider("mock:test")
	var _ Provider = (*OllamaProvider)(nil)
}
