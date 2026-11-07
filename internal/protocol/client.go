package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"banksec-lab/internal/config"
	"banksec-lab/internal/crypto"
)

// Client sends requests to a Server and waits for its response.
type Client interface {
	Send(ctx context.Context, req Request) (Response, error)
}

type pipeClient struct {
	conn    net.Conn
	engine  crypto.Engine
	authKey []byte
	profile config.SecurityProfile

	// mu serializes the entire write+read round trip of Send, not just
	// the sequence counter -- without it, concurrent Sends can interleave
	// their frames on the wire and each read the wrong response.
	mu      sync.Mutex
	nextSeq uint64
}

// NewClient wraps conn as a Client. engine/authKey authenticate every
// frame Send writes, per profile.CryptoProfile (the tag covers
// Version+Seq+CryptoProf+Payload, not just Payload -- see macInput).
//
// authKey's shape depends on profile.CryptoProfile: for "standard" and
// "weak-educational" it is a shared symmetric key (the same bytes the
// corresponding Server's key must hold); for "pqc" it is an ML-DSA
// private key seed, and the Server must hold the *corresponding public
// key*, not the same bytes -- see auth.go's computeTag/verifyTag.
//
// authKey MUST be unique per connection/session and never reused across
// separate Client/Server pairs: replay protection (lastSeen) is tracked
// per-connection, so a frame captured on one connection authenticates
// successfully on a different connection if both share a key. Binding
// the key to a per-connection/session identity is deferred to
// Milestone 5's key-management design (ruled in Milestone 3's security
// review).
//
// Response frames are not authenticated at all (no tag, no profile) --
// also deferred, per the same ruling: the default transport is net.Pipe
// (no real on-path attacker), and the Attack Harness verifies outcomes
// through its own Oracle, never by trusting a protocol response.
func NewClient(conn net.Conn, engine crypto.Engine, authKey []byte, profile config.SecurityProfile) Client {
	return &pipeClient{conn: conn, engine: engine, authKey: authKey, profile: profile}
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
	tag, err := computeTag(c.engine, c.profile.CryptoProfile, c.authKey, macInput(1, seq, c.profile.CryptoProfile, payload))
	if err != nil {
		return Response{}, fmt.Errorf("compute auth tag: %w", err)
	}

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
