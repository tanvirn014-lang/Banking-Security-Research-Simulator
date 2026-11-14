package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"banksec-lab/internal/config"
	"banksec-lab/internal/crypto"
)

// captureFrame sends one request under profile and returns the frame
// that actually went onto the wire, plus the client that sent it.
func captureFrame(t *testing.T, profile config.SecurityProfile, req Request) (Frame, *pipeClient) {
	t.Helper()
	_, client := newAttackTestWiring(t, profile)

	if _, err := client.Send(context.Background(), req); err != nil {
		t.Fatalf("Send: %v", err)
	}
	frame, ok := client.LastSentFrame()
	if !ok {
		t.Fatal("no frame was captured")
	}
	pc, ok := client.(*pipeClient)
	if !ok {
		t.Fatalf("expected *pipeClient, got %T", client)
	}
	return frame, pc
}

func accountRequest() Request {
	return Request{Op: "create-account", Params: map[string]string{"owner": "owner-1"}}
}

// The property this whole change exists to provide.
func TestWire_HardenedTrafficIsCiphertext(t *testing.T) {
	frame, pc := captureFrame(t, hardenedWireProfile(), accountRequest())

	if pc.SessionKey() == nil {
		t.Fatal("a hardened connection must agree a session key")
	}
	if bytes.Contains(frame.Payload, []byte("create-account")) {
		t.Fatalf("the operation name is readable on the wire: %q", frame.Payload)
	}
	if bytes.Contains(frame.Payload, []byte("owner-1")) {
		t.Fatal("the account owner is readable on the wire")
	}
	var leaked Request
	if err := json.Unmarshal(frame.Payload, &leaked); err == nil {
		t.Fatalf("the wire payload parses as a request: %+v", leaked)
	}
}

// And the differential: under the weakened profile the same traffic is
// readable. This is not an oversight -- see wireEncryptionEnabled for
// why encrypting it would have destroyed the tamper attack surface the
// weakened profile exists to provide.
func TestWire_VulnerableTrafficIsPlaintext(t *testing.T) {
	frame, pc := captureFrame(t, vulnerableWireProfile(), accountRequest())

	if pc.SessionKey() != nil {
		t.Fatal("the weakened profile must not agree a session key")
	}
	var seen Request
	if err := json.Unmarshal(frame.Payload, &seen); err != nil {
		t.Fatalf("expected readable JSON on the wire under the weakened profile: %v", err)
	}
	if seen.Op != "create-account" {
		t.Fatalf("op = %q, want create-account", seen.Op)
	}
}

// Ciphertext must still carry the real request: confidentiality cannot
// come at the cost of correctness.
func TestWire_CiphertextDecryptsToTheOriginalRequest(t *testing.T) {
	req := accountRequest()
	frame, pc := captureFrame(t, hardenedWireProfile(), req)

	plaintext, err := crypto.NewEngine().Decrypt(frame.CryptoProf, pc.SessionKey(), frame.Payload)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	var got Request
	if err := json.Unmarshal(plaintext, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Op != req.Op || got.Params["owner"] != req.Params["owner"] {
		t.Fatalf("round trip lost the request: got %+v want %+v", got, req)
	}
}

// Two connections must not share a session key, or the key agreement
// would be decorative.
func TestWire_EachConnectionAgreesItsOwnKey(t *testing.T) {
	_, first := captureFrame(t, hardenedWireProfile(), accountRequest())
	_, second := captureFrame(t, hardenedWireProfile(), accountRequest())

	if bytes.Equal(first.SessionKey(), second.SessionKey()) {
		t.Fatal("two separate connections agreed the same session key")
	}
}

// The handshake must happen once, not per request.
func TestWire_HandshakeHappensOncePerConnection(t *testing.T) {
	_, client := newAttackTestWiring(t, hardenedWireProfile())
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := client.Send(ctx, accountRequest()); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	pc := client.(*pipeClient)
	key := pc.SessionKey()
	if key == nil {
		t.Fatal("no session key")
	}
	if _, err := client.Send(ctx, accountRequest()); err != nil {
		t.Fatalf("fourth send: %v", err)
	}
	if !bytes.Equal(key, pc.SessionKey()) {
		t.Fatal("the session key changed mid-connection -- the handshake ran more than once")
	}
}

// A corrupted ciphertext must be refused, never passed to the request
// parser as if it were plaintext.
func TestWire_UndecryptablePayloadIsRefusedNotParsed(t *testing.T) {
	_, client := newAttackTestWiring(t, hardenedWireProfile())
	ctx := context.Background()

	if _, err := client.Send(ctx, accountRequest()); err != nil {
		t.Fatalf("priming send: %v", err)
	}
	frame, _ := client.LastSentFrame()

	// Corrupt the ciphertext but keep a structurally valid frame.
	frame.Payload = append([]byte(nil), frame.Payload...)
	frame.Payload[len(frame.Payload)-1] ^= 0xFF
	frame.Seq++

	resp, err := client.SendRawFrame(ctx, frame)
	if err != nil {
		t.Fatalf("SendRawFrame: %v", err)
	}
	if resp.OK {
		t.Fatal("a corrupted ciphertext was accepted")
	}
	if !strings.Contains(strings.ToLower(resp.Error), "decrypt") &&
		!strings.Contains(strings.ToLower(resp.Error), "tamper") &&
		!strings.Contains(strings.ToLower(resp.Error), "auth") {
		t.Fatalf("expected a decryption or authentication failure, got %q", resp.Error)
	}
}

// pqc has no key agreement of this shape, so it must carry
// authenticated-but-unencrypted frames and say so, rather than
// appearing to be encrypted.
func TestWire_PQCIsAuthenticatedButNotEncrypted(t *testing.T) {
	if supportsWireEncryption("pqc") {
		t.Fatal("pqc must not claim wire encryption")
	}
	p := hardenedWireProfile()
	p.CryptoProfile = "pqc"
	p.MinAcceptedCryptoProfile = "pqc"
	if wireEncryptionEnabled(p) {
		t.Fatal("a pqc connection must not be reported as wire-encrypted")
	}
}
