package protocol

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"banksec-lab/internal/apperr"
	"banksec-lab/internal/backend"
	"banksec-lab/internal/config"
	"banksec-lab/internal/domain"
)

var ErrReplayDetected = apperr.New(apperr.CodeConflict, "replayed sequence number")
var ErrAuthFailed = apperr.New(apperr.CodeConflict, "auth tag verification failed")
var ErrProfileDowngrade = apperr.New(apperr.CodeConflict, "crypto profile below server minimum")

// Server serves requests from a single Client connection against a
// backend.Service, until the connection closes or ctx is canceled.
type Server interface {
	Serve(ctx context.Context, svc backend.Service) error
}

type pipeServer struct {
	conn    net.Conn
	mac     MACFunc
	macKey  []byte
	profile config.SecurityProfile

	// lastSeen is the highest Seq accepted so far on this connection.
	// Only tracked/enforced when profile.ProtocolAuthEnforced is true --
	// vulnerable mode does not track it at all, the deliberately
	// exploitable replay surface.
	lastSeen uint64
}

// NewServer wraps conn as a Server. mac/macKey verify every frame's
// AuthTag; profile gates replay/tamper/downgrade enforcement
// (ProtocolAuthEnforced) and sets the accepted crypto-profile floor
// (MinAcceptedCryptoProfile). See NewClient's doc comment for the macKey
// uniqueness requirement and the response-authentication deferral.
func NewServer(conn net.Conn, mac MACFunc, macKey []byte, profile config.SecurityProfile) Server {
	return &pipeServer{conn: conn, mac: mac, macKey: macKey, profile: profile}
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

		var resp Response
		if rejectErr := s.checkFrameSecurity(reqFrame); rejectErr != nil {
			resp = errorResponse(rejectErr)
		} else {
			var req Request
			if err := json.Unmarshal(reqFrame.Payload, &req); err != nil {
				// Reply with an error instead of returning: a Client is
				// blocked in readFrame waiting for exactly this response,
				// and dying here would hang it forever rather than
				// surfacing the problem.
				resp = errorResponse(apperr.Wrap(apperr.CodeValidation, "malformed request", err))
			} else {
				resp = dispatch(ctx, svc, req)
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

// checkFrameSecurity enforces tamper, downgrade, and replay protection.
// All three are gated by ProtocolAuthEnforced -- vulnerable mode performs
// none of them, the deliberately exploitable surface for Task I2.
//
// Order matters: the tag is verified (over Version+Seq+CryptoProf+Payload,
// via macInput) before lastSeen is ever advanced. Advancing lastSeen on an
// unauthenticated frame would let a forged high-Seq frame permanently
// block every subsequent legitimate request on this connection, even
// though the forged frame itself gets rejected -- a denial-of-service
// found in Milestone 3's security review.
func (s *pipeServer) checkFrameSecurity(f Frame) error {
	if !s.profile.ProtocolAuthEnforced {
		return nil
	}

	expectedTag := s.mac(s.macKey, macInput(f.Version, f.Seq, f.CryptoProf, f.Payload))
	if !hmac.Equal(expectedTag, f.AuthTag) {
		return ErrAuthFailed
	}

	if profileRank(f.CryptoProf) < profileRank(s.profile.MinAcceptedCryptoProfile) {
		return ErrProfileDowngrade
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
