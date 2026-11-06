package applog

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNew_ProducesValidJSONLines(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)

	logger.Info("test message", "component", "test")

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("expected valid JSON line, got error: %v (line: %q)", err, buf.String())
	}
	if _, ok := decoded["time"]; !ok {
		t.Fatalf("expected a %q key in the logged line, got: %v", "time", decoded)
	}
}
