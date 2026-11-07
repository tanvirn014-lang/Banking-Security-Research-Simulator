package audit

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// ExportJSON writes events to w as a JSON array, in the order given.
func ExportJSON(w io.Writer, events []Event) error {
	enc := json.NewEncoder(w)
	if err := enc.Encode(events); err != nil {
		return fmt.Errorf("encode events as JSON: %w", err)
	}
	return nil
}

// csvColumns names ExportCSV's header row, in column order.
var csvColumns = []string{"id", "timestamp", "type", "component", "actor", "operation", "outcome", "tx_id", "attack_id"}

// csvFormulaLeads are the leading characters a spreadsheet application
// (Excel, LibreOffice Calc, Google Sheets) treats a cell as a formula or
// DDE command for, if sanitizeCSVCell doesn't neutralize them first.
var csvFormulaLeads = []byte{'=', '+', '-', '@', '\t', '\r'}

// sanitizeCSVCell guards against CSV/formula injection: several of
// Event's fields (Actor, Operation, Component, Outcome) are client- or
// business-logic-controlled strings with no character restrictions, so a
// crafted event could otherwise smuggle a formula (e.g. HYPERLINK or a
// DDE payload) into whatever spreadsheet tool later opens this export.
// Prefixing a leading trigger character with a single quote is the
// standard mitigation: spreadsheet applications then treat the cell as
// literal text (security review finding I11).
func sanitizeCSVCell(s string) string {
	if len(s) == 0 {
		return s
	}
	for _, lead := range csvFormulaLeads {
		if s[0] == lead {
			return "'" + s
		}
	}
	return s
}

// ExportCSV writes events to w as CSV: a header row (csvColumns) followed
// by one row per event. TxID/AttackID render as an empty field when nil.
// Timestamps are rendered in UTC so the export doesn't depend on the
// exporting machine's local time zone.
func ExportCSV(w io.Writer, events []Event) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvColumns); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}
	for _, e := range events {
		var txID, attackID string
		if e.TxID != nil {
			txID = string(*e.TxID)
		}
		if e.AttackID != nil {
			attackID = *e.AttackID
		}
		row := []string{
			sanitizeCSVCell(e.ID),
			e.Timestamp.UTC().Format(time.RFC3339Nano),
			sanitizeCSVCell(e.Type),
			sanitizeCSVCell(e.Component),
			sanitizeCSVCell(string(e.Actor)),
			sanitizeCSVCell(e.Operation),
			sanitizeCSVCell(e.Outcome),
			sanitizeCSVCell(txID),
			sanitizeCSVCell(attackID),
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("write CSV row for event %s: %w", e.ID, err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flush CSV writer: %w", err)
	}
	return nil
}
