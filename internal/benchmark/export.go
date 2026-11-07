package benchmark

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// rawRunJSON is the flat, §3/§6-shaped JSON record for one raw run --
// deliberately NOT just marshaling RawRun directly (which would nest
// harness.Result under a "result" key instead of the flat field list
// BENCHMARK_METHODOLOGY.md §3 names). A nil *int64 metric serializes as
// JSON null via encoding/json's own native behavior -- never a
// fabricated 0, never the literal string "null".
//
// AttackID/TargetConfiguration are sourced from RawRun's OWN
// ScenarioID/Mode fields, not harness.Result's (security review findings
// I2/I3 -- see RawRun's own doc comment): Result can be its zero value
// when RunErr != nil, and TargetConfiguration (sourced from
// Environment.Profile.Name) silently collides if the caller's two
// profiles share a Name, which RunComparative now rejects outright, but
// an export reader should never have to care about that distinction --
// ScenarioID/Mode are always correct regardless.
type rawRunJSON struct {
	RunID               string    `json:"run_id"`
	Timestamp           time.Time `json:"timestamp"`
	AttackID            string    `json:"attack_id"`
	TargetConfiguration string    `json:"target_configuration"`
	AttackType          string    `json:"attack_type"`
	Success             bool      `json:"success"`
	ExecutionTimeMS     int64     `json:"execution_time_ms"`
	TimeToCompromiseMS  *int64    `json:"time_to_compromise_ms"`
	DataLeakedBytes     *int64    `json:"data_leaked_bytes"`
	RecordsCompromised  *int64    `json:"records_compromised"`
	DetectionLatencyMS  *int64    `json:"detection_latency_ms"`
	Attempts            int       `json:"attempts"`
	ComputationalCost   *int64    `json:"computational_cost"`
	MemoryUsageBytes    *int64    `json:"memory_usage_bytes"`
	Seed                *int64    `json:"seed"`
	// RunError is nil unless the run's own harness.Runner.Run call
	// itself returned an error (RawRun.RunErr) -- "preserve every raw
	// run including failures" means recording the failure explicitly,
	// never dropping the row or pretending it succeeded.
	RunError *string `json:"run_error"`
}

func toRawRunJSON(run RawRun) rawRunJSON {
	j := rawRunJSON{
		RunID:               run.RunID,
		Timestamp:           run.Timestamp,
		AttackID:            run.ScenarioID,
		TargetConfiguration: run.Mode,
		AttackType:          run.Result.AttackType,
		Success:             run.Result.Success,
		ExecutionTimeMS:     run.Result.ExecutionTimeMS,
		TimeToCompromiseMS:  run.Result.TimeToCompromiseMS,
		DataLeakedBytes:     run.Result.DataLeakedBytes,
		RecordsCompromised:  run.Result.RecordsCompromised,
		DetectionLatencyMS:  run.Result.DetectionLatencyMS,
		Attempts:            run.Result.Attempts,
		ComputationalCost:   run.Result.ComputationalCost,
		MemoryUsageBytes:    run.Result.MemoryUsageBytes,
		Seed:                run.Result.Seed,
	}
	if run.RunErr != nil {
		msg := run.RunErr.Error()
		j.RunError = &msg
	}
	return j
}

type summaryJSON struct {
	ScenarioID  string             `json:"scenario_id"`
	Mode        string             `json:"mode"`
	N           int                `json:"n"`
	Errors      int                `json:"errors"`
	SuccessRate float64            `json:"success_rate"`
	Mean        map[Metric]float64 `json:"mean"`
	Median      map[Metric]float64 `json:"median"`
	StdDev      map[Metric]float64 `json:"stddev"`
	SampleSize  map[Metric]int     `json:"sample_size"`
}

func toSummaryJSON(s Summary) summaryJSON {
	return summaryJSON{
		ScenarioID:  s.ScenarioID,
		Mode:        s.Mode,
		N:           s.N,
		Errors:      s.Errors,
		SuccessRate: s.SuccessRate,
		Mean:        s.Mean,
		Median:      s.Median,
		StdDev:      s.StdDev,
		SampleSize:  s.SampleSize,
	}
}

type exportDoc struct {
	Raw     []rawRunJSON  `json:"raw"`
	Summary []summaryJSON `json:"summary"`
}

// ExportJSON writes raw and summary together as one JSON document
// ({"raw": [...], "summary": [...]}) -- BENCHMARK_METHODOLOGY.md §6
// describes raw/summary as "always shipped alongside, never instead of"
// each other; one combined document is this package's way of making
// that non-optional by construction, for a single io.Writer call.
func ExportJSON(w io.Writer, raw RawResults, summary []Summary) error {
	doc := exportDoc{
		Raw:     make([]rawRunJSON, len(raw)),
		Summary: make([]summaryJSON, len(summary)),
	}
	for i, run := range raw {
		doc.Raw[i] = toRawRunJSON(run)
	}
	for i, s := range summary {
		doc.Summary[i] = toSummaryJSON(s)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

var rawCSVHeader = []string{
	"run_id", "timestamp", "attack_id", "target_configuration", "attack_type",
	"success", "execution_time_ms", "time_to_compromise_ms", "data_leaked_bytes",
	"records_compromised", "detection_latency_ms", "attempts", "computational_cost",
	"memory_usage_bytes", "seed", "run_error",
}

// ExportCSV writes raw and summary as two blocks in one stream,
// separated by a blank line: a single CSV table can't naturally carry
// two differently-shaped record types the way one JSON document can.
// Parse each section with its OWN csv.Reader after splitting on the
// blank-line separator (as this package's own
// TestExportCSV_ParsesBack does) -- feeding the combined stream to a
// single default csv.Reader fails, since it requires a consistent
// field count across every record and the raw/summary blocks have
// different widths; that is expected, not a bug to work around with a
// variable-width reader.
//
// An absent (nil) metric is an EMPTY cell -- never "0" and never the
// literal text "null" -- so "unavailable" is never confusable with "a
// measured zero" (the user's explicit "never fabricate missing
// measurements" requirement, applied to CSV's lack of a native null).
// The summary block always has the same columns (one pair of
// mean_X/median_X/stddev_X/samples_X per allMetrics entry) regardless of
// which metrics any individual group actually has -- a consistent
// schema a spreadsheet or any CSV-reading tool can rely on, with an
// empty cell for a metric a given (scenario,mode) group never recorded.
//
// run_error is sanitized to a single line (security review finding M6):
// Go's encoding/csv quotes a field containing an embedded newline per
// RFC 4180, which is valid CSV but defeats the blank-line
// section-separator convention above if that embedded newline happens
// to be blank (e.g. inside a multi-line panic message) -- every embedded
// CR/LF in run_error is replaced with a literal `\n`/`\r` escape
// sequence instead, guaranteeing every row is exactly one physical line.
func ExportCSV(w io.Writer, raw RawResults, summary []Summary) error {
	cw := csv.NewWriter(w)

	if err := cw.Write(rawCSVHeader); err != nil {
		return fmt.Errorf("benchmark: write raw CSV header: %w", err)
	}
	for _, run := range raw {
		if err := cw.Write(rawCSVRow(run)); err != nil {
			return fmt.Errorf("benchmark: write raw CSV row %q: %w", run.RunID, err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("benchmark: flush raw CSV: %w", err)
	}

	if _, err := io.WriteString(w, "\n"); err != nil {
		return fmt.Errorf("benchmark: write CSV section separator: %w", err)
	}

	if err := cw.Write(summaryCSVHeader()); err != nil {
		return fmt.Errorf("benchmark: write summary CSV header: %w", err)
	}
	for _, s := range summary {
		if err := cw.Write(summaryCSVRow(s)); err != nil {
			return fmt.Errorf("benchmark: write summary CSV row %q/%q: %w", s.ScenarioID, s.Mode, err)
		}
	}
	cw.Flush()
	return cw.Error()
}

func rawCSVRow(run RawRun) []string {
	j := toRawRunJSON(run)
	return []string{
		j.RunID,
		j.Timestamp.Format(time.RFC3339Nano),
		j.AttackID,
		j.TargetConfiguration,
		j.AttackType,
		strconv.FormatBool(j.Success),
		strconv.FormatInt(j.ExecutionTimeMS, 10),
		formatOptionalInt(j.TimeToCompromiseMS),
		formatOptionalInt(j.DataLeakedBytes),
		formatOptionalInt(j.RecordsCompromised),
		formatOptionalInt(j.DetectionLatencyMS),
		strconv.Itoa(j.Attempts),
		formatOptionalInt(j.ComputationalCost),
		formatOptionalInt(j.MemoryUsageBytes),
		formatOptionalInt(j.Seed),
		sanitizeCSVFreeText(formatOptionalString(j.RunError)),
	}
}

func summaryCSVHeader() []string {
	header := []string{"scenario_id", "mode", "n", "errors", "success_rate"}
	for _, m := range allMetrics {
		header = append(header, "mean_"+string(m), "median_"+string(m), "stddev_"+string(m), "samples_"+string(m))
	}
	return header
}

func summaryCSVRow(s Summary) []string {
	row := []string{s.ScenarioID, s.Mode, strconv.Itoa(s.N), strconv.Itoa(s.Errors), strconv.FormatFloat(s.SuccessRate, 'f', -1, 64)}
	for _, m := range allMetrics {
		if n, ok := s.SampleSize[m]; ok {
			row = append(row,
				strconv.FormatFloat(s.Mean[m], 'f', -1, 64),
				strconv.FormatFloat(s.Median[m], 'f', -1, 64),
				strconv.FormatFloat(s.StdDev[m], 'f', -1, 64),
				strconv.Itoa(n),
			)
		} else {
			row = append(row, "", "", "", "")
		}
	}
	return row
}

func formatOptionalInt(v *int64) string {
	if v == nil {
		return ""
	}
	return strconv.FormatInt(*v, 10)
}

func formatOptionalString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// sanitizeCSVFreeText replaces embedded carriage returns/line feeds with
// literal escape sequences, guaranteeing the field never introduces a
// new physical line into the CSV stream (security review finding M6).
func sanitizeCSVFreeText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\\n")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}
