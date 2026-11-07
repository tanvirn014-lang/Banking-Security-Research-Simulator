package benchmark

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func sampleExportData() (RawResults, []Summary) {
	raw := RawResults{
		rawRun("s1", "vulnerable", true, 10, i64(100)),
		rawRun("s1", "hardened", false, 15, nil),
	}
	summary := Summarize(raw)
	return raw, summary
}

func TestExportJSON_RoundTrips(t *testing.T) {
	raw, summary := sampleExportData()
	var buf bytes.Buffer
	if err := ExportJSON(&buf, raw, summary); err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode exported JSON: %v (output=%s)", err, buf.String())
	}
	rawList, ok := doc["raw"].([]any)
	if !ok || len(rawList) != 2 {
		t.Fatalf("expected a 2-element \"raw\" array, got %v", doc["raw"])
	}
	first := rawList[0].(map[string]any)
	if first["attack_id"] != "s1" {
		t.Fatalf("expected attack_id=s1, got %v", first["attack_id"])
	}
	if first["time_to_compromise_ms"] != float64(100) {
		t.Fatalf("expected time_to_compromise_ms=100, got %v", first["time_to_compromise_ms"])
	}
	second := rawList[1].(map[string]any)
	if second["time_to_compromise_ms"] != nil {
		t.Fatalf("expected a nil TimeToCompromiseMS to serialize as JSON null, got %v", second["time_to_compromise_ms"])
	}

	summaryList, ok := doc["summary"].([]any)
	if !ok || len(summaryList) != 2 {
		t.Fatalf("expected a 2-element \"summary\" array, got %v", doc["summary"])
	}
}

func TestExportJSON_RunErrorIsRecorded(t *testing.T) {
	raw := RawResults{{RunID: "r1", Result: rawRun("s1", "vulnerable", false, 1, nil).Result, RunErr: errTestSentinel}}
	var buf bytes.Buffer
	if err := ExportJSON(&buf, raw, nil); err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}
	if !strings.Contains(buf.String(), "run_error") || !strings.Contains(buf.String(), "sentinel test error") {
		t.Fatalf("expected the run's error to appear in the exported JSON, got %s", buf.String())
	}
}

func TestExportCSV_ParsesBack(t *testing.T) {
	raw, summary := sampleExportData()
	var buf bytes.Buffer
	if err := ExportCSV(&buf, raw, summary); err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}

	sections := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n\n")
	if len(sections) != 2 {
		t.Fatalf("expected 2 CSV sections (raw, summary) separated by a blank line, got %d: %q", len(sections), buf.String())
	}

	rawReader := csv.NewReader(strings.NewReader(sections[0]))
	rawRows, err := rawReader.ReadAll()
	if err != nil {
		t.Fatalf("parse raw CSV section: %v", err)
	}
	if len(rawRows) != 3 { // header + 2 runs
		t.Fatalf("expected a header row plus 2 raw rows, got %d: %v", len(rawRows), rawRows)
	}
	header := rawRows[0]
	colIndex := func(name string) int {
		for i, h := range header {
			if h == name {
				return i
			}
		}
		t.Fatalf("expected a %q column in the raw CSV header, got %v", name, header)
		return -1
	}
	ttcCol := colIndex("time_to_compromise_ms")
	if rawRows[1][ttcCol] != "100" {
		t.Fatalf("expected row 1's time_to_compromise_ms=100, got %q", rawRows[1][ttcCol])
	}
	if rawRows[2][ttcCol] != "" {
		t.Fatalf("expected row 2's absent time_to_compromise_ms to be an EMPTY cell (not \"0\" or \"null\"), got %q", rawRows[2][ttcCol])
	}

	summaryReader := csv.NewReader(strings.NewReader(sections[1]))
	summaryRows, err := summaryReader.ReadAll()
	if err != nil {
		t.Fatalf("parse summary CSV section: %v", err)
	}
	if len(summaryRows) != 3 { // header + 2 (scenario,mode) groups
		t.Fatalf("expected a header row plus 2 summary rows, got %d: %v", len(summaryRows), summaryRows)
	}
}

func TestExportCSV_AbsentMetricIsEmptyCellNotZero(t *testing.T) {
	raw := RawResults{rawRun("s1", "hardened", false, 5, nil)} // no TimeToCompromiseMS anywhere in this group
	summary := Summarize(raw)
	var buf bytes.Buffer
	if err := ExportCSV(&buf, raw, summary); err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	sections := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n\n")
	summaryReader := csv.NewReader(strings.NewReader(sections[1]))
	rows, err := summaryReader.ReadAll()
	if err != nil {
		t.Fatalf("parse summary CSV: %v", err)
	}
	header := rows[0]
	meanCol := -1
	for i, h := range header {
		if h == "mean_"+string(MetricTimeToCompromiseMS) {
			meanCol = i
		}
	}
	if meanCol == -1 {
		t.Fatalf("expected a mean_time_to_compromise_ms column (always present, even when empty), got %v", header)
	}
	if rows[1][meanCol] != "" {
		t.Fatalf("expected an empty cell for a metric absent from every run in this group, got %q", rows[1][meanCol])
	}
}

var errTestSentinel = sentinelErr("sentinel test error")

type sentinelErr string

func (e sentinelErr) Error() string { return string(e) }

func TestExportCSV_NumericFieldsParseAsNumbers(t *testing.T) {
	raw, summary := sampleExportData()
	var buf bytes.Buffer
	if err := ExportCSV(&buf, raw, summary); err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	sections := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n\n")
	rawReader := csv.NewReader(strings.NewReader(sections[0]))
	rows, _ := rawReader.ReadAll()
	header := rows[0]
	execCol := -1
	for i, h := range header {
		if h == "execution_time_ms" {
			execCol = i
		}
	}
	if _, err := strconv.ParseInt(rows[1][execCol], 10, 64); err != nil {
		t.Fatalf("expected execution_time_ms to parse as an integer, got %q: %v", rows[1][execCol], err)
	}
}

// TestExportCSV_RunErrorWithEmbeddedBlankLineDoesNotBreakSectionSplit is
// the regression test for security review finding M6: a run_error
// containing an embedded blank line (e.g. a multi-line recovered panic
// message) made the documented blank-line raw/summary section separator
// ambiguous -- Go's encoding/csv quotes a field with an embedded
// newline per RFC 4180 (valid CSV), but a BLANK line inside that quoted
// field looks identical, byte-for-byte, to the real section separator
// this package's own split-then-parse convention relies on.
func TestExportCSV_RunErrorWithEmbeddedBlankLineDoesNotBreakSectionSplit(t *testing.T) {
	raw := RawResults{
		{RunID: "r1", ScenarioID: "s1", Mode: "vulnerable", Result: rawRun("s1", "vulnerable", false, 1, nil).Result,
			RunErr: sentinelErr("line one\n\nline three (after a blank line)")},
		rawRun("s1", "hardened", false, 1, nil),
	}
	summary := Summarize(raw)

	var buf bytes.Buffer
	if err := ExportCSV(&buf, raw, summary); err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}

	sections := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n\n")
	if len(sections) != 2 {
		t.Fatalf("expected exactly 2 sections (raw, summary) despite the embedded blank line in run_error, got %d: %q", len(sections), buf.String())
	}

	rawReader := csv.NewReader(strings.NewReader(sections[0]))
	rawRows, err := rawReader.ReadAll()
	if err != nil {
		t.Fatalf("parse raw CSV section: %v", err)
	}
	if len(rawRows) != 3 { // header + 2 runs
		t.Fatalf("expected a header row plus 2 raw rows, got %d: %v", len(rawRows), rawRows)
	}
	header := rawRows[0]
	runErrCol := -1
	for i, h := range header {
		if h == "run_error" {
			runErrCol = i
		}
	}
	if !strings.Contains(rawRows[1][runErrCol], "\\n") {
		t.Fatalf("expected the embedded newline to be escaped as a literal \\n, got %q", rawRows[1][runErrCol])
	}
	if strings.Contains(rawRows[1][runErrCol], "\n") {
		t.Fatalf("expected NO literal newline byte left in the run_error cell, got %q", rawRows[1][runErrCol])
	}
}
