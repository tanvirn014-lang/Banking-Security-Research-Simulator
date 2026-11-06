package protocol

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/backend"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/keystore"
	"banksec-lab/internal/ledger"
	"banksec-lab/internal/testsupport"
)

func newTestWiring(t *testing.T) (backend.Service, Client) {
	t.Helper()

	l, err := ledger.NewSQLiteStore(testsupport.TempSQLitePath(t))
	if err != nil {
		t.Fatalf("ledger.NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	k, err := keystore.NewSQLiteStore(testsupport.TempSQLitePath(t))
	if err != nil {
		t.Fatalf("keystore.NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { k.Close() })

	a, err := audit.NewSQLiteStream(testsupport.TempSQLitePath(t))
	if err != nil {
		t.Fatalf("audit.NewSQLiteStream: %v", err)
	}
	t.Cleanup(func() { a.Close() })

	svc := backend.NewService(l, k, a)

	clientConn, serverConn := NewPipeTransport()
	server := NewServer(serverConn)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go server.Serve(ctx, svc)

	client := NewClient(clientConn)
	return svc, client
}

func TestSendReceive_CreateAccount(t *testing.T) {
	ctx := context.Background()
	_, client := newTestWiring(t)

	resp, err := client.Send(ctx, Request{
		Op:    "create-account",
		Actor: domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner},
		Params: map[string]string{
			"owner": "owner-1",
		},
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected OK response, got %+v", resp)
	}
	if resp.Data["account"] == "" {
		t.Fatalf("expected an account ID in response data, got %+v", resp)
	}
}

func TestSendReceive_DepositAndBalance(t *testing.T) {
	ctx := context.Background()
	_, client := newTestWiring(t)

	createResp, err := client.Send(ctx, Request{
		Op:     "create-account",
		Actor:  domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner},
		Params: map[string]string{"owner": "owner-1"},
	})
	if err != nil || !createResp.OK {
		t.Fatalf("create-account: resp=%+v err=%v", createResp, err)
	}
	acct := createResp.Data["account"]

	depositResp, err := client.Send(ctx, Request{
		Op:    "deposit",
		Actor: domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner},
		Params: map[string]string{
			"account": acct,
			"amount":  "1000",
		},
	})
	if err != nil || !depositResp.OK {
		t.Fatalf("deposit: resp=%+v err=%v", depositResp, err)
	}

	balResp, err := client.Send(ctx, Request{
		Op:     "balance",
		Actor:  domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner},
		Params: map[string]string{"account": acct},
	})
	if err != nil || !balResp.OK {
		t.Fatalf("balance: resp=%+v err=%v", balResp, err)
	}
	got, err := strconv.ParseInt(balResp.Data["balance"], 10, 64)
	if err != nil {
		t.Fatalf("parse balance %q: %v", balResp.Data["balance"], err)
	}
	if got != 1000 {
		t.Fatalf("got balance %d, want 1000", got)
	}
}

func mustCreateAccount(t *testing.T, ctx context.Context, client Client, ownerID string) string {
	t.Helper()
	resp, err := client.Send(ctx, Request{
		Op:     "create-account",
		Actor:  domain.Principal{ID: domain.PrincipalID(ownerID), Role: domain.RoleAccountOwner},
		Params: map[string]string{"owner": ownerID},
	})
	if err != nil || !resp.OK {
		t.Fatalf("create-account: resp=%+v err=%v", resp, err)
	}
	return resp.Data["account"]
}

func TestSendReceive_SuccessfulWithdraw(t *testing.T) {
	ctx := context.Background()
	_, client := newTestWiring(t)
	actor := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}
	acct := mustCreateAccount(t, ctx, client, "owner-1")

	if resp, err := client.Send(ctx, Request{Op: "deposit", Actor: actor, Params: map[string]string{"account": acct, "amount": "1000"}}); err != nil || !resp.OK {
		t.Fatalf("deposit: resp=%+v err=%v", resp, err)
	}

	resp, err := client.Send(ctx, Request{Op: "withdraw", Actor: actor, Params: map[string]string{"account": acct, "amount": "400"}})
	if err != nil || !resp.OK {
		t.Fatalf("withdraw: resp=%+v err=%v", resp, err)
	}

	balResp, err := client.Send(ctx, Request{Op: "balance", Actor: actor, Params: map[string]string{"account": acct}})
	if err != nil || !balResp.OK {
		t.Fatalf("balance: resp=%+v err=%v", balResp, err)
	}
	got, _ := strconv.ParseInt(balResp.Data["balance"], 10, 64)
	if got != 600 {
		t.Fatalf("got balance %d, want 600", got)
	}
}

func TestSendReceive_SuccessfulTransfer(t *testing.T) {
	ctx := context.Background()
	_, client := newTestWiring(t)
	actor := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}
	acctA := mustCreateAccount(t, ctx, client, "owner-1")
	acctB := mustCreateAccount(t, ctx, client, "owner-1")

	if resp, err := client.Send(ctx, Request{Op: "deposit", Actor: actor, Params: map[string]string{"account": acctA, "amount": "1000"}}); err != nil || !resp.OK {
		t.Fatalf("deposit: resp=%+v err=%v", resp, err)
	}

	resp, err := client.Send(ctx, Request{Op: "transfer", Actor: actor, Params: map[string]string{"from": acctA, "to": acctB, "amount": "300"}})
	if err != nil || !resp.OK {
		t.Fatalf("transfer: resp=%+v err=%v", resp, err)
	}

	balB, err := client.Send(ctx, Request{Op: "balance", Actor: actor, Params: map[string]string{"account": acctB}})
	if err != nil || !balB.OK {
		t.Fatalf("balance B: resp=%+v err=%v", balB, err)
	}
	got, _ := strconv.ParseInt(balB.Data["balance"], 10, 64)
	if got != 300 {
		t.Fatalf("got balance %d, want 300", got)
	}
}

func TestSendReceive_History(t *testing.T) {
	ctx := context.Background()
	_, client := newTestWiring(t)
	actor := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}
	acct := mustCreateAccount(t, ctx, client, "owner-1")

	if resp, err := client.Send(ctx, Request{Op: "deposit", Actor: actor, Params: map[string]string{"account": acct, "amount": "1000"}}); err != nil || !resp.OK {
		t.Fatalf("deposit: resp=%+v err=%v", resp, err)
	}

	resp, err := client.Send(ctx, Request{Op: "history", Actor: actor, Params: map[string]string{"account": acct}})
	if err != nil || !resp.OK {
		t.Fatalf("history: resp=%+v err=%v", resp, err)
	}
	if resp.Data["history"] == "" || resp.Data["history"] == "null" {
		t.Fatalf("expected a non-empty history payload, got %+v", resp)
	}
}

func TestSend_SerializedUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	_, client := newTestWiring(t)
	actor := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}
	acct := mustCreateAccount(t, ctx, client, "owner-1")
	if resp, err := client.Send(ctx, Request{Op: "deposit", Actor: actor, Params: map[string]string{"account": acct, "amount": "10000"}}); err != nil || !resp.OK {
		t.Fatalf("deposit: resp=%+v err=%v", resp, err)
	}

	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			resp, err := client.Send(ctx, Request{Op: "withdraw", Actor: actor, Params: map[string]string{"account": acct, "amount": "100"}})
			if err != nil {
				errs <- err
				return
			}
			if !resp.OK {
				errs <- fmt.Errorf("withdraw rejected: %s", resp.Error)
				return
			}
			errs <- nil
		}()
	}

	done := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			if err := <-errs; err != nil {
				t.Errorf("concurrent withdraw %d failed: %v", i, err)
			}
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent Sends did not all complete within 10s -- likely a hang from unserialized frame interleaving")
	}
}

func TestSend_RespectsContextDeadline(t *testing.T) {
	// A server that never reads, so any blocked I/O must be interrupted
	// by ctx, not time out at the test's own expense.
	clientConn, _ := NewPipeTransport()
	client := NewClient(clientConn)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := client.Send(ctx, Request{Op: "balance", Params: map[string]string{"account": "x"}})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Send to fail when nothing reads the request and the context deadline passes")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Send took %v to return after a 100ms context deadline -- it is not ctx-aware", elapsed)
	}
}

func TestServer_MalformedRequestGetsErrorResponse(t *testing.T) {
	// Writes a raw malformed frame directly, bypassing Client's JSON
	// encoding, to prove the server replies with an error instead of
	// silently dying (which would hang a real Client forever).
	clientConn, serverConn := NewPipeTransport()
	server := NewServer(serverConn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx, nil)

	if err := writeFrame(clientConn, Frame{Version: 1, Seq: 1, Payload: []byte("not valid json")}); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	respFrame, err := readFrame(clientConn)
	if err != nil {
		t.Fatalf("expected an error response frame, got a read error: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(respFrame.Payload, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.OK {
		t.Fatalf("expected a non-OK response for a malformed request, got %+v", resp)
	}
}

func TestReadFrame_RejectsOversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	var header [13]byte
	header[0] = 1
	binary.BigEndian.PutUint64(header[1:9], 1)
	binary.BigEndian.PutUint32(header[9:13], MaxFrameSize+1)
	buf.Write(header[:])

	_, err := readFrame(&buf)
	if err == nil {
		t.Fatal("expected readFrame to reject a payload length above MaxFrameSize")
	}
}

func TestSendReceive_UnknownOp_ReturnsError(t *testing.T) {
	ctx := context.Background()
	_, client := newTestWiring(t)

	resp, err := client.Send(ctx, Request{Op: "no-such-op"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.OK {
		t.Fatalf("expected a non-OK response for an unknown op, got %+v", resp)
	}
	if resp.Error == "" {
		t.Fatalf("expected a non-empty Error for an unknown op")
	}
}
