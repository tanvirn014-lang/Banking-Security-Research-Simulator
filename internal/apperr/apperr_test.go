package apperr

import (
	"errors"
	"testing"
)

func TestWrap_PreservesIsChecks(t *testing.T) {
	sentinel := New(CodeNotFound, "account not found")
	wrapped := Wrap(CodeInternal, "while loading account", sentinel)

	if !errors.Is(wrapped, sentinel) {
		t.Fatalf("expected errors.Is(wrapped, sentinel) to be true")
	}
}

func TestCodeOf_UnknownError(t *testing.T) {
	plain := errors.New("something went wrong")

	if got := CodeOf(plain); got != CodeInternal {
		t.Fatalf("expected CodeInternal for a non-*apperr.Error, got %q", got)
	}
}

func TestCodeOf_KnownError(t *testing.T) {
	err := New(CodeUnauthorized, "not your account")

	if got := CodeOf(err); got != CodeUnauthorized {
		t.Fatalf("expected CodeUnauthorized, got %q", got)
	}
}

// Pins the documented contract (see CONVENTIONS.md): Wrap's own Code is
// what CodeOf reports, even when the wrapped cause carries a different
// Code. A caller who wants to preserve the cause's classification must
// pass apperr.CodeOf(err) to Wrap explicitly, not rely on it propagating.
func TestCodeOf_WrapOutermostCodeWins(t *testing.T) {
	cause := New(CodeNotFound, "account not found")
	wrapped := Wrap(CodeInternal, "while loading account", cause)

	if got := CodeOf(wrapped); got != CodeInternal {
		t.Fatalf("expected the wrapper's own CodeInternal to win, got %q", got)
	}
}
