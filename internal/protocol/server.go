package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"banksec-lab/internal/apperr"
	"banksec-lab/internal/backend"
	"banksec-lab/internal/config"
	"banksec-lab/internal/crypto"
	"banksec-lab/internal/domain"
)

var ErrReplayDetected = apperr.New(apperr.CodeConflict, "replayed sequence number")
var ErrAuthFailed = apperr.New(apperr.CodeConflict, "auth tag verification failed")
var ErrProfileDowngrade = apperr.New(apperr.CodeConflict, "crypto profile below server minimum")
var ErrAuthSchemeMismatch = apperr.New(apperr.CodeConflict, "declared crypto profile's authentication scheme does not match server configuration")

// Server serves requests from a single Client connection against a
// backend.Service, until the connection closes or ctx is canceled.
type Server interface {
	Serve(ctx context.Context, svc backend.Service) error
}

type pipeServer struct {
	conn      net.Conn
	engine    crypto.Engine
	verifyKey []byte
	profile   config.SecurityProfile

	// sessionKey decrypts this connection's frame payloads, agreed
	// during the handshake. Nil until then, and nil for the whole
	// connection under a profile whose key establishment does not fit
	// this handshake's shape (see supportsWireEncryption).
	sessionKey []byte

	// lastSeen is the highest Seq accepted so far on this connection.
	// Only tracked/enforced when profile.ProtocolAuthEnforced is true --
	// vulnerable mode does not track it at all, the deliberately
	// exploitable replay surface.
	lastSeen uint64
}

// NewServer wraps conn as a Server. engine/verifyKey verify every
// frame's AuthTag (see auth.go's verifyTag for how verifyKey's shape
// depends on the frame's declared profile); profile gates replay/tamper/
// downgrade enforcement (ProtocolAuthEnforced) and sets the accepted
// crypto-profile floor (MinAcceptedCryptoProfile). See NewClient's doc
// comment for the key-uniqueness requirement and the response-
// authentication deferral.
func NewServer(conn net.Conn, engine crypto.Engine, verifyKey []byte, profile config.SecurityProfile) Server {
	return &pipeServer{conn: conn, engine: engine, verifyKey: verifyKey, profile: profile}
}

func (s *pipeServer) Serve(ctx context.Context, svc backend.Service) error {
	// Closing the connection on ctx cancellation unblocks any in-flight
	// Read/Write, since net.Pipe's blocking I/O does not itself observe ctx.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			s.conn.Close()
		case <-done:
		}
	}()

	for {
		reqFrame, err := readFrame(s.conn)
		if err != nil {
			return nil // connection closed (by peer, or by us on ctx cancellation)
		}

		// The handshake is recognised before any other check. It must
		// not reach the replay logic, which rejects anything whose
		// sequence number is not strictly greater than the last seen --
		// and lastSeen starts at zero, so a handshake routed through it
		// would be rejected as a replay of itself.
		if reqFrame.Seq == handshakeSeq && wireEncryptionEnabled(s.profile) {
			if err := s.handleHandshake(reqFrame); err != nil {
				return err
			}
			continue
		}

		var resp Response
		if rejectErr := s.checkFrameSecurity(reqFrame); rejectErr != nil {
			resp = errorResponse(rejectErr)
		} else {
			// Decryption comes after the security check, never before:
			// the tag covers the ciphertext, so verifying it first is
			// the "then-MAC" half of encrypt-then-MAC. A payload that
			// will not decrypt is rejected outright — treating the raw
			// bytes as plaintext instead would hand an attacker who
			// corrupted the ciphertext a direct path to the request
			// parser.
			plaintext, decErr := openPayload(s.engine, reqFrame.CryptoProf, s.sessionKey, reqFrame.Payload)
			switch {
			case decErr != nil:
				resp = errorResponse(apperr.Wrap(apperr.CodeValidation, "undecryptable payload", decErr))
			default:
				var req Request
				if err := json.Unmarshal(plaintext, &req); err != nil {
					// Reply with an error instead of returning: a Client
					// is blocked in readFrame waiting for exactly this
					// response, and dying here would hang it forever
					// rather than surfacing the problem.
					resp = errorResponse(apperr.Wrap(apperr.CodeValidation, "malformed request", err))
				} else {
					resp = dispatch(ctx, svc, req)
				}
			}
		}

		payload, err := json.Marshal(resp)
		if err != nil {
			return fmt.Errorf("encode response: %w", err)
		}
		if err := writeFrame(s.conn, Frame{Version: reqFrame.Version, Seq: reqFrame.Seq, Payload: payload}); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
	}
}

// checkFrameSecurity enforces downgrade, tamper, and replay protection.
// All three are gated by ProtocolAuthEnforced -- vulnerable mode performs
// none of them, the deliberately exploitable surface for Task I2.
//
// Order matters, in three ways:
//  1. Downgrade is checked before the tag: if a frame declares a profile
//     weaker than the configured minimum, there is no reason to even
//     attempt verifying it under that untrusted scheme -- and for "pqc"
//     vs. the symmetric profiles, the *kind* of verification differs
//     (asymmetric vs. keyed-MAC), so attempting it first would also be
//     more complex for no benefit.
//  2. The scheme-match check is next: s.verifyKey has exactly one shape,
//     matching s.profile.CryptoProfile (a shared symmetric secret for
//     standard/weak-educational, an ML-DSA PUBLIC key for pqc -- see
//     NewServer's doc comment). verifyTag picks its verification method
//     from the frame's declared CryptoProf, not from s.profile.CryptoProfile,
//     so without this check a pqc-configured server's public verifyKey
//     would get used as an HMAC secret for any declared symmetric profile
//     ranked at or above MinAcceptedCryptoProfile -- and an HMAC key need
//     not be secret-shaped to produce a "valid" tag, so anyone who knows
//     the (public, by design) key could forge authenticated requests.
//     Found as Critical finding C1 in Milestone 4's security review.
//  3. The tag is verified (over Version+Seq+CryptoProf+Payload, via
//     macInput) before lastSeen is ever advanced. Advancing lastSeen on
//     an unauthenticated frame would let a forged high-Seq frame
//     permanently block every subsequent legitimate request on this
//     connection, even though the forged frame itself gets rejected -- a
//     denial-of-service found in Milestone 3's security review.
func (s *pipeServer) checkFrameSecurity(f Frame) error {
	if !s.profile.ProtocolAuthEnforced {
		return nil
	}

	if profileRank(f.CryptoProf) < profileRank(s.profile.MinAcceptedCryptoProfile) {
		return ErrProfileDowngrade
	}

	if (f.CryptoProf == "pqc") != (s.profile.CryptoProfile == "pqc") {
		return ErrAuthSchemeMismatch
	}

	ok, err := verifyTag(s.engine, f.CryptoProf, s.verifyKey, macInput(f.Version, f.Seq, f.CryptoProf, f.Payload), f.AuthTag)
	if err != nil || !ok {
		return ErrAuthFailed
	}

	if f.Seq <= s.lastSeen {
		return ErrReplayDetected
	}
	s.lastSeen = f.Seq
	return nil
}

func dispatch(ctx context.Context, svc backend.Service, req Request) Response {
	switch req.Op {
	case "create-account":
		acct, err := svc.CreateAccount(ctx, domain.PrincipalID(req.Params["owner"]))
		if err != nil {
			return errorResponse(err)
		}
		return Response{OK: true, Data: map[string]string{"account": string(acct)}}

	case "deposit":
		amount, err := parseAmount(req.Params["amount"])
		if err != nil {
			return errorResponse(err)
		}
		if err := svc.Deposit(ctx, req.Actor, domain.AccountID(req.Params["account"]), amount); err != nil {
			return errorResponse(err)
		}
		return Response{OK: true}

	case "withdraw":
		amount, err := parseAmount(req.Params["amount"])
		if err != nil {
			return errorResponse(err)
		}
		if err := svc.Withdraw(ctx, req.Actor, domain.AccountID(req.Params["account"]), amount); err != nil {
			return errorResponse(err)
		}
		return Response{OK: true}

	case "transfer":
		amount, err := parseAmount(req.Params["amount"])
		if err != nil {
			return errorResponse(err)
		}
		from := domain.AccountID(req.Params["from"])
		to := domain.AccountID(req.Params["to"])
		if err := svc.Transfer(ctx, req.Actor, from, to, amount); err != nil {
			return errorResponse(err)
		}
		return Response{OK: true}

	case "balance":
		bal, err := svc.Balance(ctx, req.Actor, domain.AccountID(req.Params["account"]))
		if err != nil {
			return errorResponse(err)
		}
		return Response{OK: true, Data: map[string]string{"balance": strconv.FormatInt(int64(bal), 10)}}

	case "history":
		entries, err := svc.History(ctx, req.Actor, domain.AccountID(req.Params["account"]))
		if err != nil {
			return errorResponse(err)
		}
		encoded, err := json.Marshal(entries)
		if err != nil {
			return errorResponse(apperr.Wrap(apperr.CodeInternal, "encode history", err))
		}
		return Response{OK: true, Data: map[string]string{"history": string(encoded)}}

	default:
		return errorResponse(apperr.New(apperr.CodeValidation, "unknown operation: "+req.Op))
	}
}

func parseAmount(s string) (domain.Money, error) {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, apperr.Wrap(apperr.CodeValidation, "invalid amount "+s, err)
	}
	return domain.Money(v), nil
}

func errorResponse(err error) Response {
	return Response{
		OK:    false,
		Error: fmt.Sprintf("%s: %s", apperr.CodeOf(err), err.Error()),
	}
}

// handleHandshake answers a client's key-agreement frame and records
// the resulting session key for this connection.
//
// The client's frame is authenticated with the same tag scheme as every
// other frame, and that check is enforced here under the same profile
// gate as the rest — so under a hardened profile a tampered client
// public key is rejected rather than silently agreed with. The reply
// carries no tag, which is the limitation every response frame in this
// protocol already has, and is acceptable only because the default
// transport is an in-memory pipe with no on-path attacker. A real
// network transport would need the reply authenticated too.
func (s *pipeServer) handleHandshake(f Frame) error {
	if s.profile.ProtocolAuthEnforced {
		ok, err := verifyTag(s.engine, f.CryptoProf, s.verifyKey,
			macInput(f.Version, f.Seq, f.CryptoProf, f.Payload), f.AuthTag)
		if err != nil || !ok {
			// Refuse to agree a key, and say nothing useful back. The
			// client's next frame then fails to decrypt, which is the
			// correct outcome: no session was established.
			return writeFrame(s.conn, Frame{Version: f.Version, Seq: f.Seq})
		}
	}

	priv, pub, err := s.engine.GenerateKeyPair(f.CryptoProf)
	if err != nil {
		return fmt.Errorf("generate session keypair: %w", err)
	}

	key, err := deriveSessionKey(s.engine, f.CryptoProf, priv, f.Payload)
	if err != nil {
		// A malformed or hostile peer public key must not establish a
		// session. Reply with nothing and leave sessionKey nil.
		return writeFrame(s.conn, Frame{Version: f.Version, Seq: f.Seq})
	}
	s.sessionKey = key

	return writeFrame(s.conn, Frame{Version: f.Version, Seq: f.Seq, Payload: pub})
}
