// Package protocol implements the wire protocol between the CLI/Attack
// Harness and the Backend.
package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"banksec-lab/internal/domain"
)

// Frame is the wire envelope.
type Frame struct {
	Version    uint8
	Seq        uint64
	CryptoProf domain.CryptoProfileName
	Payload    []byte
	AuthTag    []byte
}

// MaxFrameSize bounds a frame's payload. Without this, a forged or
// corrupted header's 32-bit length field can claim up to 4 GiB, causing
// readFrame to allocate that much before ever validating anything else.
const MaxFrameSize uint32 = 1 << 20 // 1 MiB

// MaxAuthTagSize bounds a frame's AuthTag for the same reason MaxFrameSize
// bounds Payload. 64 KiB comfortably exceeds every tag this project
// produces (HMAC-SHA256: 32 bytes; ML-DSA-44 signatures: 2420 bytes --
// discovered to not fit the originally-chosen 1-byte length prefix by
// Task C5's TestDowngrade_AllProfilePairs_RejectedWhenHardened).
const MaxAuthTagSize uint32 = 1 << 16

// Request is a client-to-server call. Params are string-encoded so the
// CLI can build them directly from command-line flags.
type Request struct {
	Op     string
	Actor  domain.Principal
	Params map[string]string
}

// Response is a server-to-client result.
type Response struct {
	OK    bool
	Error string
	Data  map[string]string
}

// Wire layout: Version(1) | Seq(8, BE) | CryptoProf-len(1) | CryptoProf |
// Payload-len(4, BE) | Payload | AuthTag-len(4, BE) | AuthTag.
// CryptoProf is capped at 255 bytes -- comfortably larger than any profile
// name this project produces. AuthTag uses a 4-byte length (see
// MaxAuthTagSize) because an ML-DSA-44 signature (2420 bytes) does not fit
// a 1-byte prefix.

func writeFrame(w io.Writer, f Frame) error {
	cryptoProf := []byte(f.CryptoProf)
	if len(cryptoProf) > 255 {
		return fmt.Errorf("crypto profile name too long: %d bytes", len(cryptoProf))
	}
	if len(f.Payload) > int(MaxFrameSize) {
		return fmt.Errorf("frame payload too large: %d bytes (max %d)", len(f.Payload), MaxFrameSize)
	}
	if uint32(len(f.AuthTag)) > MaxAuthTagSize {
		return fmt.Errorf("auth tag too long: %d bytes (max %d)", len(f.AuthTag), MaxAuthTagSize)
	}

	var buf bytes.Buffer
	buf.WriteByte(f.Version)
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], f.Seq)
	buf.Write(seqBuf[:])
	buf.WriteByte(byte(len(cryptoProf)))
	buf.Write(cryptoProf)
	var payloadLenBuf [4]byte
	binary.BigEndian.PutUint32(payloadLenBuf[:], uint32(len(f.Payload)))
	buf.Write(payloadLenBuf[:])
	buf.Write(f.Payload)
	var authTagLenBuf [4]byte
	binary.BigEndian.PutUint32(authTagLenBuf[:], uint32(len(f.AuthTag)))
	buf.Write(authTagLenBuf[:])
	buf.Write(f.AuthTag)

	if _, err := w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

func readFrame(r io.Reader) (Frame, error) {
	var f Frame

	var fixed [9]byte // Version(1) + Seq(8)
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return Frame{}, err // EOF/io.ErrUnexpectedEOF propagate as-is for callers to detect connection close
	}
	f.Version = fixed[0]
	f.Seq = binary.BigEndian.Uint64(fixed[1:9])

	var cryptoProfLen [1]byte
	if _, err := io.ReadFull(r, cryptoProfLen[:]); err != nil {
		return Frame{}, fmt.Errorf("read crypto profile length: %w", err)
	}
	cryptoProf := make([]byte, cryptoProfLen[0])
	if _, err := io.ReadFull(r, cryptoProf); err != nil {
		return Frame{}, fmt.Errorf("read crypto profile: %w", err)
	}
	f.CryptoProf = domain.CryptoProfileName(cryptoProf)

	var payloadLenBuf [4]byte
	if _, err := io.ReadFull(r, payloadLenBuf[:]); err != nil {
		return Frame{}, fmt.Errorf("read payload length: %w", err)
	}
	payloadLen := binary.BigEndian.Uint32(payloadLenBuf[:])
	if payloadLen > MaxFrameSize {
		return Frame{}, fmt.Errorf("frame payload too large: %d bytes (max %d)", payloadLen, MaxFrameSize)
	}
	f.Payload = make([]byte, payloadLen)
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		return Frame{}, fmt.Errorf("read frame payload: %w", err)
	}

	var authTagLenBuf [4]byte
	if _, err := io.ReadFull(r, authTagLenBuf[:]); err != nil {
		return Frame{}, fmt.Errorf("read auth tag length: %w", err)
	}
	authTagLen := binary.BigEndian.Uint32(authTagLenBuf[:])
	if authTagLen > MaxAuthTagSize {
		return Frame{}, fmt.Errorf("auth tag too large: %d bytes (max %d)", authTagLen, MaxAuthTagSize)
	}
	f.AuthTag = make([]byte, authTagLen)
	if _, err := io.ReadFull(r, f.AuthTag); err != nil {
		return Frame{}, fmt.Errorf("read auth tag: %w", err)
	}

	return f, nil
}

// macInput builds the canonical bytes a Frame's AuthTag authenticates:
// Version, Seq, CryptoProf, and Payload together. Binding Seq and
// CryptoProf into the tag (not just Payload) is what makes the tag
// actually protect them -- an earlier version of this scheme computed the
// tag over the payload alone, which let a captured (payload, tag) pair be
// replayed at a different Seq, or its declared CryptoProf rewritten,
// without invalidating the tag (found in Milestone 3's security review).
func macInput(version uint8, seq uint64, cryptoProf domain.CryptoProfileName, payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(version)
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], seq)
	buf.Write(seqBuf[:])
	cp := []byte(cryptoProf)
	var cpLenBuf [4]byte
	binary.BigEndian.PutUint32(cpLenBuf[:], uint32(len(cp)))
	buf.Write(cpLenBuf[:])
	buf.Write(cp)
	buf.Write(payload)
	return buf.Bytes()
}

// profileRank gives crypto profiles a comparable strength ordering, so
// the server can detect a declared profile weaker than its configured
// minimum. An unrecognized name (e.g. a blank/forged declaration) ranks
// below every real profile.
func profileRank(name domain.CryptoProfileName) int {
	switch name {
	case "weak-educational":
		return 0
	case "standard":
		return 1
	case "pqc":
		return 2
	default:
		return -1
	}
}
