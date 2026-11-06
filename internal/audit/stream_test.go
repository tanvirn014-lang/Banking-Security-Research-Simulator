package audit

import (
	"context"
	"testing"
	"time"

	"banksec-lab/internal/testsupport"
)

func newTestStream(t *testing.T) Stream {
	t.Helper()
	s, err := NewSQLiteStream(testsupport.TempSQLitePath(t))
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
