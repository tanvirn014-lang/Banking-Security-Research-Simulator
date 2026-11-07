package audit

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"banksec-lab/internal/testsupport"
)

func newTestStream(t *testing.T) Stream {
	t.Helper()
	s, err := NewSQLiteStream(testsupport.TempSQLitePath(t), false)
	if err != nil {
		t.Fatalf("NewSQLiteStream: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func newTestStreamAt(t *testing.T, path string, hashChained bool) Stream {
	t.Helper()
	s, err := NewSQLiteStream(path, hashChained)
	if err != nil {
		t.Fatalf("NewSQLiteStream: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

// tamperRow bypasses Record to directly modify a recorded event's
// outcome via raw SQL, simulating an attacker (or a bug) writing
// straight to the database file.
func tamperRow(t *testing.T, path, id string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE events SET outcome = 'tampered' WHERE id = ?`, id); err != nil {
		t.Fatalf("tamper row: %v", err)
	}
}

func TestRecordSince_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStream(t)

	since := time.Now().Add(-time.Minute)
	err := s.Record(ctx, Event{
		ID:        "e1",
		Timestamp: time.Now(),
		Type:      "deposit",
		Component: "backend",
		Actor:     "owner-1",
		Operation: "Deposit",
		Outcome:   "ok",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	events, err := s.Since(ctx, since)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].ID != "e1" {
		t.Fatalf("expected event e1, got %+v", events[0])
	}
}

func TestSubscribe_ReceivesRecordedEvent(t *testing.T) {
	ctx := context.Background()
	s := newTestStream(t)

	received := make(chan Event, 1)
	unsubscribe := s.Subscribe(func(e Event) { received <- e })
	defer unsubscribe()

	if err := s.Record(ctx, Event{ID: "e2", Timestamp: time.Now(), Type: "withdraw"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	select {
	case e := <-received:
		if e.ID != "e2" {
			t.Fatalf("expected event e2, got %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive the recorded event within 1s")
	}
}

func TestVerifyChain_OKWhenUntampered(t *testing.T) {
	ctx := context.Background()
	s := newTestStreamAt(t, testsupport.TempSQLitePath(t), true)

	for i, id := range []string{"c1", "c2", "c3"} {
		if err := s.Record(ctx, Event{ID: id, Timestamp: time.Now(), Type: "op", Operation: "x", Outcome: "ok"}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	ok, brokenAt, err := s.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !ok || brokenAt != nil {
		t.Fatalf("expected ok=true, brokenAt=nil for an untampered chain, got ok=%v brokenAt=%v", ok, brokenAt)
	}
}

func TestVerifyChain_DetectsTamper(t *testing.T) {
	ctx := context.Background()
	path := testsupport.TempSQLitePath(t)
	s := newTestStreamAt(t, path, true)

	for i, id := range []string{"t1", "t2", "t3"} {
		if err := s.Record(ctx, Event{ID: id, Timestamp: time.Now(), Type: "op", Operation: "x", Outcome: "ok"}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	tamperRow(t, path, "t2")

	ok, brokenAt, err := s.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if ok {
		t.Fatalf("expected ok=false after a raw-SQL tamper")
	}
	if brokenAt == nil || *brokenAt != "t2" {
		t.Fatalf("expected brokenAt=%q, got %v", "t2", brokenAt)
	}
}

func TestVerifyChain_ErrorsWhenNotEnabled(t *testing.T) {
	ctx := context.Background()
	s := newTestStream(t) // hashChained=false

	if err := s.Record(ctx, Event{ID: "n1", Timestamp: time.Now(), Type: "op"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	_, _, err := s.VerifyChain(ctx)
	if !errors.Is(err, ErrChainNotEnabled) {
		t.Fatalf("expected ErrChainNotEnabled, got %v", err)
	}
}

func strPtr(s string) *string { return &s }

// TestVerifyChain_DetectsTruncation is the regression test for Milestone
// 5+6 security review finding C2: deleting trailing rows (or every row)
// via raw SQL left a self-consistent, shorter chain that VerifyChain
// reported as ok=true, because it only checked that each stored row
// linked correctly to its predecessor -- never that nothing was missing
// off the end.
// TestVerifyChain_NoFalsePositiveUnderConcurrentRecord is the regression
// test for Milestone 8 security review finding I1: VerifyChain read the
// checkpoint file and then scanned the events table as two separate,
// unlocked steps. A concurrent Record landing in between (inserting a
// row and advancing the checkpoint) made the row count VerifyChain
// scanned disagree with the (now-stale) checkpoint count it had already
// read, reporting a false "trailing event(s) missing" break -- even
// though nothing was tampered, more was legitimately added. Worse,
// combined with detection.auditChainRule's dedup latch, one false
// positive permanently silenced the rule for any *real* later tamper.
func TestVerifyChain_NoFalsePositiveUnderConcurrentRecord(t *testing.T) {
	ctx := context.Background()
	s := newTestStreamAt(t, testsupport.TempSQLitePath(t), true)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		n := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			n++
			_ = s.Record(ctx, Event{ID: fmt.Sprintf("bg-%d", n), Timestamp: time.Now(), Type: "op"})
		}
	}()

	deadline := time.Now().Add(200 * time.Millisecond)
	falsePositives := 0
	for time.Now().Before(deadline) {
		ok, brokenAt, err := s.VerifyChain(ctx)
		if err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
		if !ok {
			falsePositives++
			t.Logf("false positive: brokenAt=%v", brokenAt)
		}
	}
	close(stop)
	wg.Wait()

	if falsePositives > 0 {
		t.Fatalf("expected zero false positives from an untampered chain under concurrent Record, got %d", falsePositives)
	}
}

func TestVerifyChain_DetectsTruncation(t *testing.T) {
	ctx := context.Background()
	path := testsupport.TempSQLitePath(t)
	s := newTestStreamAt(t, path, true)

	for i, id := range []string{"d1", "d2", "d3"} {
		if err := s.Record(ctx, Event{ID: id, Timestamp: time.Now(), Type: "op", Operation: "x", Outcome: "ok"}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM events WHERE id = 'd3'`); err != nil {
		t.Fatalf("delete trailing row: %v", err)
	}

	ok, _, err := s.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if ok {
		t.Fatalf("expected ok=false after deleting the trailing event, got ok=true")
	}
}

// TestEventHashInput_NoFieldBoundaryCollision is the regression test for
// finding C3: the old NUL-joined encoding let a NUL byte in a
// client-controlled field (e.g. Actor) shift content across field
// boundaries without changing the joined bytes -- e.g.
// (actor="alice\x00x", operation="Deposit") and (actor="alice",
// operation="x\x00Deposit") joined identically. The length-prefixed
// encoding must distinguish them.
func TestEventHashInput_NoFieldBoundaryCollision(t *testing.T) {
	var txID, attackID sql.NullString
	a := eventHashInput(genesisHash, "id", 0, "", "", "alice\x00x", "Deposit", "", txID, attackID)
	b := eventHashInput(genesisHash, "id", 0, "", "", "alice", "x\x00Deposit", "", txID, attackID)
	if bytes.Equal(a, b) {
		t.Fatalf("expected distinct hash inputs for field-boundary-shifted actor/operation, got identical bytes")
	}
}

// TestChainCheckpoint_PersistsAcrossReopen is the regression test for
// finding I5's audit-package analogue: a hash-chained stream closed and
// reopened at the same path (the CLI's normal multi-invocation pattern)
// must keep verifying ok=true, and new events must continue the same
// chain rather than silently restarting at genesis.
func TestChainCheckpoint_PersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := testsupport.TempSQLitePath(t)

	s1, err := NewSQLiteStream(path, true)
	if err != nil {
		t.Fatalf("NewSQLiteStream (first open): %v", err)
	}
	if err := s1.Record(ctx, Event{ID: "p1", Timestamp: time.Now(), Type: "op"}); err != nil {
		t.Fatalf("Record p1: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := NewSQLiteStream(path, true)
	if err != nil {
		t.Fatalf("NewSQLiteStream (reopen): %v", err)
	}
	defer s2.Close()

	ok, brokenAt, err := s2.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain after reopen, before any new write: %v", err)
	}
	if !ok || brokenAt != nil {
		t.Fatalf("expected ok=true immediately after reopening an untampered chain, got ok=%v brokenAt=%v", ok, brokenAt)
	}

	if err := s2.Record(ctx, Event{ID: "p2", Timestamp: time.Now(), Type: "op"}); err != nil {
		t.Fatalf("Record p2: %v", err)
	}
	ok, brokenAt, err = s2.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain after a post-reopen write: %v", err)
	}
	if !ok || brokenAt != nil {
		t.Fatalf("expected ok=true after continuing the chain post-reopen, got ok=%v brokenAt=%v", ok, brokenAt)
	}
}

// TestNewSQLiteStream_ModeMismatchRejected is the regression test for
// finding I7: opening a stream file with a different hashChained value
// than it was created with must fail loudly at construction, not
// silently (previously: every subsequent Record under hashChained=true
// against vulnerable-written data failed deep inside the hash-chain
// logic, and the reverse direction left stale hashes nobody checked).
func TestNewSQLiteStream_ModeMismatchRejected(t *testing.T) {
	path := testsupport.TempSQLitePath(t)

	s, err := NewSQLiteStream(path, false)
	if err != nil {
		t.Fatalf("NewSQLiteStream(false): %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := NewSQLiteStream(path, true); err == nil {
		t.Fatalf("expected an error reopening a hashChained=false stream with hashChained=true, got none")
	}
}

func TestFilter_ByComponent(t *testing.T) {
	ctx := context.Background()
	s := newTestStream(t)

	mustRecord := func(id, component string) {
		t.Helper()
		if err := s.Record(ctx, Event{ID: id, Timestamp: time.Now(), Component: component}); err != nil {
			t.Fatalf("Record %s: %v", id, err)
		}
	}
	mustRecord("f1", "keystore")
	mustRecord("f2", "backend")
	mustRecord("f3", "keystore")

	events, err := s.Filter(ctx, Filter{Component: "keystore"})
	if err != nil {
		t.Fatalf("Filter: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events for component=keystore, got %d: %+v", len(events), events)
	}
	for _, e := range events {
		if e.Component != "keystore" {
			t.Fatalf("unexpected component in filtered results: %+v", e)
		}
	}
}

func TestFilter_ByAttackID(t *testing.T) {
	ctx := context.Background()
	s := newTestStream(t)

	attackA := "attack-A"
	if err := s.Record(ctx, Event{ID: "a1", Timestamp: time.Now(), AttackID: &attackA}); err != nil {
		t.Fatalf("Record a1: %v", err)
	}
	if err := s.Record(ctx, Event{ID: "a2", Timestamp: time.Now()}); err != nil {
		t.Fatalf("Record a2: %v", err)
	}

	events, err := s.Filter(ctx, Filter{AttackID: strPtr("attack-A")})
	if err != nil {
		t.Fatalf("Filter: %v", err)
	}
	if len(events) != 1 || events[0].ID != "a1" {
		t.Fatalf("expected exactly [a1] for attack_id=attack-A, got %+v", events)
	}
}

func TestFilter_ByTimeRange(t *testing.T) {
	ctx := context.Background()
	s := newTestStream(t)

	base := time.Now()
	if err := s.Record(ctx, Event{ID: "r1", Timestamp: base.Add(-time.Hour)}); err != nil {
		t.Fatalf("Record r1: %v", err)
	}
	if err := s.Record(ctx, Event{ID: "r2", Timestamp: base}); err != nil {
		t.Fatalf("Record r2: %v", err)
	}
	if err := s.Record(ctx, Event{ID: "r3", Timestamp: base.Add(time.Hour)}); err != nil {
		t.Fatalf("Record r3: %v", err)
	}

	events, err := s.Filter(ctx, Filter{Since: base.Add(-time.Minute), Until: base.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Filter: %v", err)
	}
	if len(events) != 1 || events[0].ID != "r2" {
		t.Fatalf("expected exactly [r2] for the narrow time range, got %+v", events)
	}
}
