package protocol

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"banksec-lab/internal/audit"
	"banksec-lab/internal/backend"
	"banksec-lab/internal/config"
	"banksec-lab/internal/domain"
	"banksec-lab/internal/keystore"
	"banksec-lab/internal/ledger"
	"banksec-lab/internal/testsupport"
)

// testMAC and testMACKey are the placeholder MAC used by every test in
// this file (Task C5 replaces this with internal/crypto's real Engine).
func testMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

var testMACKey = []byte("test-mac-key")

func hardenedWireProfile() config.SecurityProfile {
	return config.SecurityProfile{
		Name:                     "hardened",
		CryptoProfile:            "standard",
		MinAcceptedCryptoProfile: "standard",
		ProtocolAuthEnforced:     true,
		AuthzEnforced:            true,
		AtomicityEnforced:        true,
	}
}

func vulnerableWireProfile() config.SecurityProfile {
	return config.SecurityProfile{
		Name:                     "vulnerable",
		CryptoProfile:            "standard",
		MinAcceptedCryptoProfile: "standard",
		ProtocolAuthEnforced:     false,
		AuthzEnforced:            false,
		AtomicityEnforced:        false,
	}
}

func newTestWiring(t *testing.T) (backend.Service, Client) {
	t.Helper()
	return newTestWiringWithProfile(t, hardenedWireProfile())
}

func newTestStores(t *testing.T) (ledger.Store, keystore.Store, audit.Stream) {
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

	return l, k, a
}

func newTestWiringWithProfile(t *testing.T, profile config.SecurityProfile) (backend.Service, Client) {
	t.Helper()
	l, k, a := newTestStores(t)
	svc := backend.NewService(l, k, a, profile)

	clientConn, serverConn := NewPipeTransport()
	server := NewServer(serverConn, testMAC, testMACKey, profile)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go server.Serve(ctx, svc)

	client := NewClient(clientConn, testMAC, testMACKey, profile)
	return svc, client
}

// newRawTestWiring returns the raw client-side net.Conn (bypassing
// Client) so a test can construct frames by hand to simulate replay,
// tamper, and downgrade attacks.
func newRawTestWiring(t *testing.T, profile config.SecurityProfile) (net.Conn, backend.Service) {
	t.Helper()
	l, k, a := newTestStores(t)
	svc := backend.NewService(l, k, a, profile)

	clientConn, serverConn := NewPipeTransport()
	server := NewServer(serverConn, testMAC, testMACKey, profile)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go server.Serve(ctx, svc)
	return clientConn, svc
}

func rawSend(t *testing.T, conn net.Conn, seq uint64, cryptoProf domain.CryptoProfileName, tag []byte, req Request) Response {
	t.Helper()
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	if err := writeFrame(conn, Frame{Version: 1, Seq: seq, CryptoProf: cryptoProf, Payload: payload, AuthTag: tag}); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	respFrame, err := readFrame(conn)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(respFrame.Payload, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
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
	client := NewClient(clientConn, testMAC, testMACKey, hardenedWireProfile())

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
	// Vulnerable profile: isolates this test to the malformed-JSON path,
	// rather than also tripping the (separately tested) auth-tag check.
	server := NewServer(serverConn, testMAC, testMACKey, vulnerableWireProfile())
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
	var fixed [9]byte // Version(1) + Seq(8)
	fixed[0] = 1
	binary.BigEndian.PutUint64(fixed[1:9], 1)
	buf.Write(fixed[:])
	buf.WriteByte(0) // crypto-profile length: 0 (none declared)
	var payloadLen [4]byte
	binary.BigEndian.PutUint32(payloadLen[:], MaxFrameSize+1)
	buf.Write(payloadLen[:])

	_, err := readFrame(&buf)
	if err == nil {
		t.Fatal("expected readFrame to reject a payload length above MaxFrameSize")
	}
}

func TestReplay_RejectedWhenHardened(t *testing.T) {
	conn, _ := newRawTestWiring(t, hardenedWireProfile())
	req := Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
	payload, _ := json.Marshal(req)
	tag := testMAC(testMACKey, macInput(1, 1, "standard", payload))

	first := rawSend(t, conn, 1, "standard", tag, req)
	if !first.OK {
		t.Fatalf("expected the first send to succeed, got %+v", first)
	}

	replay := rawSend(t, conn, 1, "standard", tag, req) // identical Seq, byte-for-byte identical frame
	if replay.OK {
		t.Fatalf("expected the replayed frame to be rejected under the hardened profile, got %+v", replay)
	}
	if !strings.Contains(replay.Error, "replayed") {
		t.Fatalf("expected a replay-related error, got %q", replay.Error)
	}
}

func TestReplay_AcceptedWhenVulnerable(t *testing.T) {
	conn, _ := newRawTestWiring(t, vulnerableWireProfile())
	req := Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
	payload, _ := json.Marshal(req)
	tag := testMAC(testMACKey, macInput(1, 1, "standard", payload))

	first := rawSend(t, conn, 1, "standard", tag, req)
	if !first.OK {
		t.Fatalf("expected the first send to succeed, got %+v", first)
	}

	replay := rawSend(t, conn, 1, "standard", tag, req)
	if !replay.OK {
		t.Fatalf("expected the replayed frame to be accepted under the vulnerable profile, got %+v", replay)
	}
}

func TestReplay_BumpedSequenceWithStaleTagRejectedWhenHardened(t *testing.T) {
	// The attack the earlier tag scheme missed: a captured (payload, tag)
	// pair resent at a DIFFERENT Seq, not an identical resend. This only
	// rejects correctly because the tag now covers Seq (macInput), not
	// just Payload -- found in Milestone 3's security review.
	conn, _ := newRawTestWiring(t, hardenedWireProfile())
	req := Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
	payload, _ := json.Marshal(req)
	tagForSeq1 := testMAC(testMACKey, macInput(1, 1, "standard", payload))

	first := rawSend(t, conn, 1, "standard", tagForSeq1, req)
	if !first.OK {
		t.Fatalf("expected the first send to succeed, got %+v", first)
	}

	bumped := rawSend(t, conn, 2, "standard", tagForSeq1, req) // same payload, bumped Seq, stale tag
	if bumped.OK {
		t.Fatalf("expected a bumped-sequence replay with a stale tag to be rejected, got %+v", bumped)
	}
	if !strings.Contains(bumped.Error, "auth") {
		t.Fatalf("expected an auth-related rejection (the tag no longer covers Seq=2), got %q", bumped.Error)
	}
}

func TestForgedHighSequence_DoesNotJamConnection(t *testing.T) {
	// A forged frame with a huge Seq and a garbage tag must be rejected
	// WITHOUT advancing the replay-tracking Seq, or every subsequent
	// legitimate (low-Seq) request would be permanently locked out --
	// found in Milestone 3's security review.
	conn, _ := newRawTestWiring(t, hardenedWireProfile())

	garbageReq := Request{Op: "balance", Params: map[string]string{"account": "x"}}
	garbage := rawSend(t, conn, ^uint64(0), "standard", []byte("garbage-tag"), garbageReq)
	if garbage.OK {
		t.Fatalf("expected the garbage-tagged, high-Seq frame to be rejected, got %+v", garbage)
	}

	req := Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
	payload, _ := json.Marshal(req)
	tag := testMAC(testMACKey, macInput(1, 1, "standard", payload))
	legit := rawSend(t, conn, 1, "standard", tag, req)
	if !legit.OK {
		t.Fatalf("expected a legitimate low-Seq request to still succeed after the rejected forged frame, got %+v", legit)
	}
}

func TestTamper_RejectedWhenHardened(t *testing.T) {
	conn, _ := newRawTestWiring(t, hardenedWireProfile())
	reqA := Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
	reqB := Request{Op: "create-account", Params: map[string]string{"owner": "owner-2"}}
	payloadA, _ := json.Marshal(reqA)
	tagA := testMAC(testMACKey, macInput(1, 1, "standard", payloadA))

	// Send reqB's bytes on the wire but with a tag computed over reqA's
	// payload -- a tampered-in-transit frame.
	resp := rawSend(t, conn, 1, "standard", tagA, reqB)
	if resp.OK {
		t.Fatalf("expected the tampered frame to be rejected under the hardened profile, got %+v", resp)
	}
	if !strings.Contains(resp.Error, "auth") {
		t.Fatalf("expected an auth-related error, got %q", resp.Error)
	}
}

func TestTamper_AcceptedWhenVulnerable(t *testing.T) {
	// Uses "deposit" (not "create-account") so the tampered payload's
	// effect is directly observable: reqA deposits 100, reqB (the bytes
	// actually sent, under reqA's stale tag) deposits 999. If the server
	// is really processing the bytes on the wire rather than silently
	// falling back to reqA, the resulting balance proves it.
	conn, svc := newRawTestWiring(t, vulnerableWireProfile())
	acct, err := svc.CreateAccount(context.Background(), "owner-1")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	actor := domain.Principal{ID: "owner-1", Role: domain.RoleAccountOwner}

	reqA := Request{Op: "deposit", Actor: actor, Params: map[string]string{"account": string(acct), "amount": "100"}}
	reqB := Request{Op: "deposit", Actor: actor, Params: map[string]string{"account": string(acct), "amount": "999"}}
	payloadA, _ := json.Marshal(reqA)
	tagA := testMAC(testMACKey, macInput(1, 1, "standard", payloadA))

	resp := rawSend(t, conn, 1, "standard", tagA, reqB)
	if !resp.OK {
		t.Fatalf("expected the tampered frame to be accepted under the vulnerable profile, got %+v", resp)
	}

	bal, err := svc.Balance(context.Background(), actor, acct)
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if bal != 999 {
		t.Fatalf("expected the server to have processed reqB's actual bytes (deposit 999), got balance %d", bal)
	}
}

func TestDowngrade_RejectedWhenHardened(t *testing.T) {
	conn, _ := newRawTestWiring(t, hardenedWireProfile())
	req := Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
	payload, _ := json.Marshal(req)
	tag := testMAC(testMACKey, macInput(1, 1, "weak-educational", payload))

	resp := rawSend(t, conn, 1, "weak-educational", tag, req)
	if resp.OK {
		t.Fatalf("expected the downgraded-profile frame to be rejected under the hardened profile, got %+v", resp)
	}
	if !strings.Contains(resp.Error, "below server minimum") {
		t.Fatalf("expected a downgrade-related error, got %q", resp.Error)
	}
}

func TestDowngrade_AcceptedWhenVulnerable(t *testing.T) {
	conn, _ := newRawTestWiring(t, vulnerableWireProfile())
	req := Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
	payload, _ := json.Marshal(req)
	tag := testMAC(testMACKey, macInput(1, 1, "weak-educational", payload))

	resp := rawSend(t, conn, 1, "weak-educational", tag, req)
	if !resp.OK {
		t.Fatalf("expected the downgraded-profile frame to be accepted under the vulnerable profile, got %+v", resp)
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
