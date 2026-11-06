package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"banksec-lab/internal/config"
)

// MACFunc computes an authentication tag over data, keyed by key. This is
// a placeholder until internal/crypto's Engine exists (Task C5 replaces
// it with the real Engine's MAC/Sign, selected per the active profile).
type MACFunc func(key, data []byte) []byte

// Client sends requests to a Server and waits for its response.
type Client interface {
	Send(ctx context.Context, req Request) (Response, error)
}

type pipeClient struct {
	conn    net.Conn
	mac     MACFunc
	macKey  []byte
	profile config.SecurityProfile

	// mu serializes the entire write+read round trip of Send, not just
	// the sequence counter -- without it, concurrent Sends can interleave
	// their frames on the wire and each read the wrong response.
	mu      sync.Mutex
	nextSeq uint64
}

// NewClient wraps conn as a Client. mac/macKey authenticate every frame
// Send writes (the tag covers Version+Seq+CryptoProf+Payload, not just
// Payload); profile.CryptoProfile is declared on every frame so the
// server can enforce its own minimum.
//
// macKey MUST be unique per connection/session and never reused across
// separate Client/Server pairs: replay protection (lastSeen) is tracked
// per-connection, so a frame captured on one connection authenticates
// successfully on a different connection if both share a key. cmd/banksec
// already generates a fresh key per CLI invocation; a future caller that
// reuses one instance's key across multiple connections reopens this
// surface. Binding the key (or the tag) to a per-connection/session
// identity is deferred to Milestone 5's key-management design, where
// session key provisioning becomes a first-class concern -- found in
// Milestone 3's security review.
//
// Response frames are not authenticated at all (no tag, no profile) --
// also deferred to Task C5 alongside the real crypto Engine. This is not
// a load-bearing gap for the system's security conclusions: the default
// transport is net.Pipe (in-process memory, no real on-path attacker),
// and the Attack Harness (Milestone 7) is designed to verify outcomes
// through its own read-only Oracle, never by trusting a protocol
// response -- see ARCHITECTURE.md §4.2.
func NewClient(conn net.Conn, mac MACFunc, macKey []byte, profile config.SecurityProfile) Client {
	return &pipeClient{conn: conn, mac: mac, macKey: macKey, profile: profile}
}

func (c *pipeClient) Send(ctx context.Context, req Request) (Response, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("encode request: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.nextSeq++
	seq := c.nextSeq
	tag := c.mac(c.macKey, macInput(1, seq, c.profile.CryptoProfile, payload))

	// net.Conn's blocking I/O does not itself observe ctx, so a deadline
	// (or, for a cancelable-without-deadline ctx, a watcher that forces
	// one) is how Send becomes interruptible.
	if deadline, ok := ctx.Deadline(); ok {
		c.conn.SetDeadline(deadline)
	} else {
		c.conn.SetDeadline(time.Time{})
	}
	stopWatcher := make(chan struct{})
	defer close(stopWatcher)
	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				c.conn.SetDeadline(time.Now())
			case <-stopWatcher:
			}
		}()
	}

	frame := Frame{Version: 1, Seq: seq, CryptoProf: c.profile.CryptoProfile, Payload: payload, AuthTag: tag}
	if err := writeFrame(c.conn, frame); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Response{}, ctxErr
		}
		return Response{}, fmt.Errorf("send request: %w", err)
	}

	respFrame, err := readFrame(c.conn)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Response{}, ctxErr
		}
		return Response{}, fmt.Errorf("receive response: %w", err)
	}

	var resp Response
	if err := json.Unmarshal(respFrame.Payload, &resp); err != nil {
		return Response{}, fmt.Errorf("decode response: %w", err)
	}
	return resp, nil
}
