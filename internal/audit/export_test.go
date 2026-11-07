package audit

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"banksec-lab/internal/domain"
)

func sampleExportEvents() []Event {
	tx := domain.TransactionID("tx-1")
	attack := "attack-1"
	return []Event{
		{
			ID:        "e1",
			Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			Type:      "deposit",
			Component: "backend",
			Actor:     "owner-1",
			Operation: "Deposit",
			Outcome:   "ok",
			TxID:      &tx,
			AttackID:  &attack,
		},
		{
			ID:        "e2",
			Timestamp: time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC),
			Type:      "withdraw",
			Component: "backend",
			Actor:     "owner-2",
			Operation: "Withdraw",
			Outcome:   "error",
		},
	}
}

func TestExportJSON_RoundTrips(t *testing.T) {
	events := sampleExportEvents()

	var buf bytes.Buffer
	if err := ExportJSON(&buf, events); err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}

	var got []Event
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(got) != len(events) {
		t.Fatalf("expected %d events, got %d", len(events), len(got))
	}
	for i := range events {
		if !got[i].Timestamp.Equal(events[i].Timestamp) {
			t.Fatalf("event %d: timestamp mismatch: got %v want %v", i, got[i].Timestamp, events[i].Timestamp)
		}
		got[i].Timestamp = events[i].Timestamp // normalize for the rest of the comparison below
		if got[i].ID != events[i].ID || got[i].Outcome != events[i].Outcome {
			t.Fatalf("event %d: mismatch: got %+v want %+v", i, got[i], events[i])
		}
		if (got[i].TxID == nil) != (events[i].TxID == nil) {
			t.Fatalf("event %d: TxID nilness mismatch: got %v want %v", i, got[i].TxID, events[i].TxID)
		}
		if got[i].TxID != nil && *got[i].TxID != *events[i].TxID {
			t.Fatalf("event %d: TxID mismatch: got %v want %v", i, *got[i].TxID, *events[i].TxID)
		}
	}
}

func TestExportCSV_ParsesBack(t *testing.T) {
	events := sampleExportEvents()

	var buf bytes.Buffer
	if err := ExportCSV(&buf, events); err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}

	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv ReadAll: %v", err)
	}
	// header + one row per event
	if len(records) != len(events)+1 {
		t.Fatalf("expected %d records (header + %d events), got %d", len(events)+1, len(events), len(records))
	}
	header := records[0]
	wantCols := []string{"id", "timestamp", "type", "component", "actor", "operation", "outcome", "tx_id", "attack_id"}
	if len(header) != len(wantCols) {
		t.Fatalf("expected %d columns, got %d: %v", len(wantCols), len(header), header)
	}
	for i, col := range wantCols {
		if header[i] != col {
			t.Fatalf("expected column %d to be %q, got %q", i, col, header[i])
		}
	}
	if records[1][0] != "e1" || records[1][7] != "tx-1" || records[1][8] != "attack-1" {
		t.Fatalf("unexpected row 1: %v", records[1])
	}
	if records[2][0] != "e2" || records[2][7] != "" || records[2][8] != "" {
		t.Fatalf("expected row 2's tx_id/attack_id to be empty for a nil pointer, got %v", records[2])
	}
}

// TestExportCSV_NeutralizesFormulaInjection is the regression test for
// security review finding I11: Actor/Operation/Outcome are client- or
// business-logic-controlled strings (e.g. Actor comes straight from a
// request's Actor field), and a cell beginning with =, +, -, @, a tab,
// or a carriage return is interpreted as a formula by Excel/LibreOffice
// when the exported CSV is later opened -- letting a crafted event
// smuggle a formula (e.g. a HYPERLINK/DDE payload) into whatever opens
// the export.
func TestExportCSV_NeutralizesFormulaInjection(t *testing.T) {
	events := []Event{{
		ID:        "e1",
		Timestamp: time.Now(),
		Type:      "op",
		Component: "backend",
		Actor:     "=HYPERLINK(\"http://evil\",\"x\")",
		Operation: "+cmd|' /C calc'!A0",
		Outcome:   "-2+3",
	}, {
		ID:        "e2",
		Timestamp: time.Now(),
		Type:      "op",
		Component: "@SUM(1+1)",
		Actor:     "\tx",
		Operation: "\rx",
		Outcome:   "ok",
	}}

	var buf bytes.Buffer
	if err := ExportCSV(&buf, events); err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}

	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv ReadAll: %v", err)
	}

	dangerousLeads := []byte{'=', '+', '-', '@', '\t', '\r'}
	for _, row := range records[1:] {
		for _, cell := range row {
			if len(cell) == 0 {
				continue
			}
			for _, lead := range dangerousLeads {
				if cell[0] == lead {
					t.Fatalf("cell %q starts with a spreadsheet-formula-triggering character %q -- not neutralized", cell, lead)
				}
			}
		}
	}
}

func TestExportCSV_TimestampIsUTC(t *testing.T) {
	loc := time.FixedZone("TEST+6", 6*60*60)
	events := []Event{{ID: "e1", Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, loc)}}

	var buf bytes.Buffer
	if err := ExportCSV(&buf, events); err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv ReadAll: %v", err)
	}
	ts := records[1][1]
	if !strings.HasSuffix(ts, "Z") {
		t.Fatalf("expected a UTC (Z-suffixed) timestamp in the CSV export, got %q", ts)
	}
}
