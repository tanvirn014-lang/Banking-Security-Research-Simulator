package protocol

import (
	"context"
	"encoding/json"
	"testing"

	"banksec-lab/internal/backend"
	"banksec-lab/internal/config"
	"banksec-lab/internal/crypto"
	"banksec-lab/internal/domain"
)

// newAttackTestWiring mirrors newTestWiringWithProfile but returns the
// Client cast to AttackClient, for Milestone 8's protocol-level attack
// scenarios (replay/tamper/downgrade), which need raw frame access that
// a normal Client (Send only) does not expose.
func newAttackTestWiring(t *testing.T, profile config.SecurityProfile) (backend.Service, AttackClient) {
	t.Helper()
	svc, client := newTestWiringWithProfile(t, profile)
	ac, ok := client.(AttackClient)
	if !ok {
		t.Fatalf("expected the Client NewClient returns to also satisfy AttackClient")
	}
	return svc, ac
}

func TestAttackClient_LastSentFrame_MatchesWhatWasActuallySent(t *testing.T) {
	ctx := context.Background()
	_, client := newAttackTestWiring(t, hardenedWireProfile())

	req := Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
	resp, err := client.Send(ctx, req)
	if err != nil || !resp.OK {
		t.Fatalf("Send: resp=%+v err=%v", resp, err)
	}

	frame, ok := client.LastSentFrame()
	if !ok {
		t.Fatalf("expected LastSentFrame to report a frame after a successful Send")
	}
	// Under a hardened profile the payload on the wire is ciphertext, so
	// a captured frame no longer decodes as JSON. That is the point of
	// wire encryption, and asserting it here is what stops the property
	// being lost again: if this ever parses as a Request, banking
	// traffic has gone out in the clear.
	var leaked Request
	if err := json.Unmarshal(frame.Payload, &leaked); err == nil {
		t.Fatalf("the captured frame decoded as a plaintext request (%+v) -- traffic is not encrypted", leaked)
	}

	// It must still be the real request underneath: decrypting with the
	// session key the connection agreed recovers exactly what was sent.
	pc, ok := client.(*pipeClient)
	if !ok {
		t.Fatalf("expected the concrete pipeClient, got %T", client)
	}
	sessionKey := pc.SessionKey()
	if sessionKey == nil {
		t.Fatal("a hardened connection must have agreed a session key")
	}

	plaintext, err := crypto.NewEngine().Decrypt(frame.CryptoProf, sessionKey, frame.Payload)
	if err != nil {
		t.Fatalf("decrypt the captured frame with the session key: %v", err)
	}
	var gotReq Request
	if err := json.Unmarshal(plaintext, &gotReq); err != nil {
		t.Fatalf("decode the decrypted payload: %v", err)
	}
	if gotReq.Op != req.Op {
		t.Fatalf("captured frame's payload doesn't match what Send sent: got %+v want %+v", gotReq, req)
	}
}

// TestAttackClient_LastSentFrame_MutatingReturnedFrameDoesNotAliasClientState
// is the regression test for security review finding M2: LastSentFrame
// previously returned the Client's own internal lastFrame value
// directly, whose Payload/AuthTag slices alias the Client's own
// backing arrays. A tamper scenario's entire point is to mutate a
// captured frame's bytes in place (e.g. frame.Payload[0] ^= 0xFF);
// without an independent copy, that mutation corrupts the Client's own
// internal state, which a later LastSentFrame call (or a later
// legitimate Send relying on consistent internal bookkeeping) would
// then observe.
func TestAttackClient_LastSentFrame_MutatingReturnedFrameDoesNotAliasClientState(t *testing.T) {
	ctx := context.Background()
	_, client := newAttackTestWiring(t, hardenedWireProfile())

	req := Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
	if resp, err := client.Send(ctx, req); err != nil || !resp.OK {
		t.Fatalf("Send: resp=%+v err=%v", resp, err)
	}

	first, ok := client.LastSentFrame()
	if !ok {
		t.Fatalf("expected a captured frame")
	}
	origPayload := append([]byte(nil), first.Payload...)
	origTag := append([]byte(nil), first.AuthTag...)

	// Mutate the returned frame's slices IN PLACE, as a tamper scenario
	// would.
	for i := range first.Payload {
		first.Payload[i] ^= 0xFF
	}
	for i := range first.AuthTag {
		first.AuthTag[i] ^= 0xFF
	}

	second, ok := client.LastSentFrame()
	if !ok {
		t.Fatalf("expected a captured frame on the second call")
	}
	if string(second.Payload) != string(origPayload) {
		t.Fatalf("mutating the first LastSentFrame call's Payload corrupted the Client's own internal state: got %v want %v", second.Payload, origPayload)
	}
	if string(second.AuthTag) != string(origTag) {
		t.Fatalf("mutating the first LastSentFrame call's AuthTag corrupted the Client's own internal state: got %v want %v", second.AuthTag, origTag)
	}
}

func TestAttackClient_Replay_RejectedHardened_AcceptedVulnerable(t *testing.T) {
	ctx := context.Background()

	t.Run("hardened", func(t *testing.T) {
		_, client := newAttackTestWiring(t, hardenedWireProfile())
		req := Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
		if resp, err := client.Send(ctx, req); err != nil || !resp.OK {
			t.Fatalf("initial Send: resp=%+v err=%v", resp, err)
		}
		frame, ok := client.LastSentFrame()
		if !ok {
			t.Fatalf("expected a captured frame")
		}
		resp, err := client.SendRawFrame(ctx, frame)
		if err != nil {
			t.Fatalf("SendRawFrame (replay): %v", err)
		}
		if resp.OK {
			t.Fatalf("expected the replayed frame to be rejected in hardened mode, got OK response %+v", resp)
		}
	})

	t.Run("vulnerable", func(t *testing.T) {
		_, client := newAttackTestWiring(t, vulnerableWireProfile())
		req := Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
		if resp, err := client.Send(ctx, req); err != nil || !resp.OK {
			t.Fatalf("initial Send: resp=%+v err=%v", resp, err)
		}
		frame, ok := client.LastSentFrame()
		if !ok {
			t.Fatalf("expected a captured frame")
		}
		resp, err := client.SendRawFrame(ctx, frame)
		if err != nil {
			t.Fatalf("SendRawFrame (replay): %v", err)
		}
		if !resp.OK {
			t.Fatalf("expected the replayed frame to be accepted in vulnerable mode, got %+v", resp)
		}
	})
}

func TestAttackClient_Tamper_RejectedHardened_AcceptedVulnerable(t *testing.T) {
	ctx := context.Background()

	tamper := func(t *testing.T, profile config.SecurityProfile) Response {
		_, client := newAttackTestWiring(t, profile)
		req := Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
		if resp, err := client.Send(ctx, req); err != nil || !resp.OK {
			t.Fatalf("initial Send: resp=%+v err=%v", resp, err)
		}
		frame, ok := client.LastSentFrame()
		if !ok {
			t.Fatalf("expected a captured frame")
		}
		tampered := Request{Op: "create-account", Params: map[string]string{"owner": "owner-ATTACKER"}}
		payload, err := json.Marshal(tampered)
		if err != nil {
			t.Fatalf("marshal tampered request: %v", err)
		}
		frame.Payload = payload // AuthTag stays the one computed for the ORIGINAL payload
		resp, err := client.SendRawFrame(ctx, frame)
		if err != nil {
			t.Fatalf("SendRawFrame (tamper): %v", err)
		}
		return resp
	}

	t.Run("hardened", func(t *testing.T) {
		resp := tamper(t, hardenedWireProfile())
		if resp.OK {
			t.Fatalf("expected the tampered frame to be rejected in hardened mode, got OK response %+v", resp)
		}
	})
	t.Run("vulnerable", func(t *testing.T) {
		resp := tamper(t, vulnerableWireProfile())
		if !resp.OK {
			t.Fatalf("expected the tampered frame to be accepted in vulnerable mode, got %+v", resp)
		}
	})
}

func TestAttackClient_Downgrade_RejectedHardened_AcceptedVulnerable(t *testing.T) {
	ctx := context.Background()

	downgrade := func(t *testing.T, profile config.SecurityProfile) Response {
		_, client := newAttackTestWiring(t, profile)
		req := Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
		payload, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		frame, err := client.BuildFrame(domain.CryptoProfileName("weak-educational"), payload)
		if err != nil {
			t.Fatalf("BuildFrame: %v", err)
		}
		resp, err := client.SendRawFrame(ctx, frame)
		if err != nil {
			t.Fatalf("SendRawFrame (downgrade): %v", err)
		}
		return resp
	}

	t.Run("hardened", func(t *testing.T) {
		resp := downgrade(t, hardenedWireProfile()) // MinAcceptedCryptoProfile: standard
		if resp.OK {
			t.Fatalf("expected the downgraded frame to be rejected in hardened mode, got OK response %+v", resp)
		}
	})
	t.Run("vulnerable", func(t *testing.T) {
		resp := downgrade(t, vulnerableWireProfile())
		if !resp.OK {
			t.Fatalf("expected the downgraded frame to be accepted in vulnerable mode, got %+v", resp)
		}
	})
}
