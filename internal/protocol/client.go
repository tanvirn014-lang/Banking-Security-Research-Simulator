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
	// HandshakeTranscript returns the public values exchanged during key
	// agreement -- what a passive eavesdropper would have seen. ok is
	// false when the connection agreed no session key.
	HandshakeTranscript() (clientPub, serverPub []byte, ok bool)
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

	// sessionKey encrypts this connection's frame payloads, agreed with
	// the server on the first Send. Nil until the handshake runs, and
	// nil forever under a profile whose key establishment does not fit
	// this handshake's shape (see supportsWireEncryption).
	sessionKey    []byte
	handshakeDone bool
	// handshakeClientPub and handshakeServerPub are the public values
	// exchanged during key agreement, retained so an attack scenario can
	// work from what an eavesdropper would actually have seen on the
	// wire rather than from values handed to it out of band.
	handshakeClientPub []byte
	handshakeServerPub []byte
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

	if err := c.ensureHandshake(ctx); err != nil {
		return Response{}, err
	}

	payload, err = sealPayload(c.engine, c.profile.CryptoProfile, c.sessionKey, payload)
	if err != nil {
		return Response{}, err
	}

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

// ensureHandshake agrees a session key with the server, once per
// connection. The caller must already hold c.mu.
//
// It runs lazily on the first Send rather than in NewClient, so that
// constructing a client stays non-blocking and the constructor's
// signature is unchanged -- every existing caller keeps working, and a
// client that is built but never used performs no I/O.
//
// Under a profile with no key agreement of this shape (pqc), the
// handshake is skipped and the connection carries authenticated but
// unencrypted frames. That is recorded as a known limitation rather
// than hidden: see docs/CRYPTOGRAPHY.md.
func (c *pipeClient) ensureHandshake(ctx context.Context) error {
	if c.handshakeDone {
		return nil
	}
	c.handshakeDone = true // one attempt per connection, success or not

	if !wireEncryptionEnabled(c.profile) {
		return nil
	}

	priv, pub, err := c.engine.GenerateKeyPair(c.profile.CryptoProfile)
	if err != nil {
		return fmt.Errorf("generate session keypair: %w", err)
	}

	// The handshake frame is authenticated with the same tag scheme as
	// every other frame, so a tampered client public key is caught by
	// the server's existing check rather than silently agreeing a key
	// with an attacker. The server's reply is not authenticated, which
	// is the same limitation every response frame already carries (see
	// NewClient's doc comment) and is acceptable only because the
	// default transport is an in-memory pipe with no on-path attacker.
	tag, err := computeTag(c.engine, c.profile.CryptoProfile, c.authKey,
		macInput(1, handshakeSeq, c.profile.CryptoProfile, pub))
	if err != nil {
		return fmt.Errorf("authenticate handshake: %w", err)
	}

	resp, err := c.roundTrip(ctx, Frame{
		Version:    1,
		Seq:        handshakeSeq,
		CryptoProf: c.profile.CryptoProfile,
		Payload:    pub,
		AuthTag:    tag,
	})
	if err != nil {
		return fmt.Errorf("session handshake: %w", err)
	}
	if len(resp.Payload) == 0 {
		return fmt.Errorf("session handshake: server returned no public key")
	}

	key, err := deriveSessionKey(c.engine, c.profile.CryptoProfile, priv, resp.Payload)
	if err != nil {
		return fmt.Errorf("session handshake: %w", err)
	}
	c.sessionKey = key
	c.handshakeClientPub = append([]byte(nil), pub...)
	c.handshakeServerPub = append([]byte(nil), resp.Payload...)
	return nil
}

// HandshakeTranscript returns the two public values exchanged during
// key agreement -- exactly what a passive eavesdropper on the wire would
// have observed, and nothing more.
//
// This exists so a cryptanalytic attack scenario can be a real attack
// on real traffic rather than a demonstration on synthetic inputs: an
// attacker who can break the agreement recovers the session key from
// these alone. It deliberately does not expose either private key.
func (c *pipeClient) HandshakeTranscript() (clientPub, serverPub []byte, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handshakeClientPub == nil || c.handshakeServerPub == nil {
		return nil, nil, false
	}
	return append([]byte(nil), c.handshakeClientPub...),
		append([]byte(nil), c.handshakeServerPub...), true
}

// SessionKey returns the key this connection encrypts its frames under,
// or nil if it has none.
//
// Exposed so an attack scenario can check whether traffic it captured
// is encrypted at all, and so a test can confirm that a key recovered
// by cryptanalysis matches the real one. It is deliberately not part of
// the Client interface -- only a caller holding the concrete type, which
// means this package and the attack harness, can reach it.
func (c *pipeClient) SessionKey() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sessionKey == nil {
		return nil
	}
	return append([]byte(nil), c.sessionKey...)
}
