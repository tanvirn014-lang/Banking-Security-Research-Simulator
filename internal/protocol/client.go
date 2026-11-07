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
	"banksec-lab/internal/domain"
)

// Client sends requests to a Server and waits for its response.
type Client interface {
	Send(ctx context.Context, req Request) (Response, error)
}

// AttackClient extends Client with raw frame access, for Milestone 8's
// protocol-level attack scenarios (replay/tamper/downgrade --
// ATTACK_SURFACES.md §2). Every Client NewClient returns also satisfies
// this interface (same underlying type); normal callers (cmd/banksec)
// only ever see it through the narrower Client interface, since nothing
// about reaching this capability goes through the wire protocol itself
// -- it is Go-level API surface internal callers opt into by type
// asserting, not something a remote peer could ever invoke.
type AttackClient interface {
	Client
	// LastSentFrame returns the most recent frame Send actually wrote to
	// the wire, exactly as sent (including its real, valid AuthTag) --
	// the harness's own prior legitimate traffic, captured for a replay
	// or tamper scenario to reuse (ATTACK_SURFACES.md §2's prerequisite:
	// the harness observes its own attack-path connection, it does not
	// need to sniff another session).
	LastSentFrame() (frame Frame, ok bool)
	// BuildFrame constructs a validly-authenticated Frame for payload
	// under profile -- which may differ from this Client's own
	// configured profile (the downgrade attack's whole premise) -- using
	// this Client's own auth key and the next sequence number. It does
	// not send it; combine with SendRawFrame.
	//
	// USAGE TRAP (security review finding M4, documentation-only --
	// deliberately not a behavior change): building a frame consumes
	// this Client's shared sequence counter immediately, whether or not
	// the built frame is ever actually sent. If a built-but-unsent
	// frame's sequence number is later sent out of order (e.g. a
	// subsequent legitimate Send on the same Client goes out at a LOWER
	// sequence number than one BuildFrame already handed out and never
	// sent), the server's replay check (f.Seq <= lastSeen) will reject
	// that later, genuinely legitimate Send as a replay -- not because
	// anything was replayed, but because this Client's own bookkeeping
	// advanced past it. This is a caller-side ordering hazard, not a
	// security weakness in the Server: avoid interleaving BuildFrame
	// calls with ordinary Send calls on the same Client when the built
	// frame might go unsent.
	BuildFrame(profile domain.CryptoProfileName, payload []byte) (Frame, error)
	// SendRawFrame writes f to the wire exactly as given -- no sequence
	// increment, no tag computation, no modification of any kind -- and
	// reads back the Response. Lets a caller resend a captured frame
	// (replay), a captured-then-mutated frame (tamper), or a
	// BuildFrame-constructed frame declaring a weaker profile
	// (downgrade).
	SendRawFrame(ctx context.Context, f Frame) (Response, error)
}

type pipeClient struct {
	conn    net.Conn
	engine  crypto.Engine
	authKey []byte
	profile config.SecurityProfile

	// mu serializes the entire write+read round trip of Send/
	// SendRawFrame, not just the sequence counter -- without it,
	// concurrent calls can interleave their frames on the wire and each
	// read the wrong response.
	mu        sync.Mutex
	nextSeq   uint64
	lastFrame Frame
	hasLast   bool
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
	frame := Frame{Version: 1, Seq: seq, CryptoProf: c.profile.CryptoProfile, Payload: payload, AuthTag: tag}

	respFrame, err := c.roundTrip(ctx, frame)
	if err != nil {
		return Response{}, err
	}
	c.lastFrame = frame
	c.hasLast = true

	var resp Response
	if err := json.Unmarshal(respFrame.Payload, &resp); err != nil {
		return Response{}, fmt.Errorf("decode response: %w", err)
	}
	return resp, nil
}

// LastSentFrame returns a copy of the most recently sent frame, with
// its own independent Payload/AuthTag backing arrays -- not slices
// aliasing c.lastFrame's. A tamper scenario's whole point is to mutate
// a captured frame's bytes in place; without this copy, that mutation
// would alias back into this Client's own internal state (security
// review finding M2).
func (c *pipeClient) LastSentFrame() (Frame, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hasLast {
		return Frame{}, false
	}
	return cloneFrame(c.lastFrame), true
}

func cloneFrame(f Frame) Frame {
	clone := f
	clone.Payload = append([]byte(nil), f.Payload...)
	clone.AuthTag = append([]byte(nil), f.AuthTag...)
	return clone
}

func (c *pipeClient) BuildFrame(profile domain.CryptoProfileName, payload []byte) (Frame, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.nextSeq++
	seq := c.nextSeq
	tag, err := computeTag(c.engine, profile, c.authKey, macInput(1, seq, profile, payload))
	if err != nil {
		return Frame{}, fmt.Errorf("compute auth tag: %w", err)
	}
	return Frame{Version: 1, Seq: seq, CryptoProf: profile, Payload: payload, AuthTag: tag}, nil
}

func (c *pipeClient) SendRawFrame(ctx context.Context, f Frame) (Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	respFrame, err := c.roundTrip(ctx, f)
	if err != nil {
		return Response{}, err
	}

	var resp Response
	if err := json.Unmarshal(respFrame.Payload, &resp); err != nil {
		return Response{}, fmt.Errorf("decode response: %w", err)
	}
	return resp, nil
}

// roundTrip writes f and reads back the response frame, honoring ctx's
// deadline/cancellation. Caller must hold c.mu.
func (c *pipeClient) roundTrip(ctx context.Context, f Frame) (Frame, error) {
	// net.Conn's blocking I/O does not itself observe ctx, so a deadline
	// (or, for a cancelable-without-deadline ctx, a watcher that forces
	// one) is how this becomes interruptible.
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

	if err := writeFrame(c.conn, f); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Frame{}, ctxErr
		}
		return Frame{}, fmt.Errorf("send frame: %w", err)
	}

	respFrame, err := readFrame(c.conn)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Frame{}, ctxErr
		}
		return Frame{}, fmt.Errorf("receive response: %w", err)
	}
	return respFrame, nil
}
