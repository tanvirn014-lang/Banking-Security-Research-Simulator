// Package applog standardizes logger construction so every package's log
// lines are valid, uniformly-shaped JSON. It is not a logging abstraction:
// call sites use *slog.Logger directly and add their own "component",
// "actor", and "attack_id" fields via slog.With(...) as needed.
package applog

import (
	"io"
	"log/slog"
)

// New returns a *slog.Logger that writes one JSON object per line to w.
func New(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, nil))
}
