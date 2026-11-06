// Package protocol implements the wire protocol between the CLI/Attack
// Harness and the Backend. This task is the basic, correct request/
// response plumbing over net.Pipe only — no sequence tracking, no auth
// tag, no crypto-profile declaration yet (Task S2 adds all three as a
// SecurityProfile-gated layer, additively, on top of this Frame format).
package protocol

import (
	"encoding/binary"
	"fmt"
	"io"

	"banksec-lab/internal/domain"
)

// Frame is the wire envelope. Version and Seq are carried now so Task S2
// can start enforcing them without changing the wire format.
type Frame struct {
	Version uint8
	Seq     uint64
	Payload []byte
}

// MaxFrameSize bounds a frame's payload. Without this, a forged or
// corrupted header's 32-bit length field can claim up to 4 GiB, causing
// readFrame to allocate that much before ever validating anything else.
const MaxFrameSize uint32 = 1 << 20 // 1 MiB

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

func writeFrame(w io.Writer, f Frame) error {
	var header [13]byte
	header[0] = f.Version
	binary.BigEndian.PutUint64(header[1:9], f.Seq)
	binary.BigEndian.PutUint32(header[9:13], uint32(len(f.Payload)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if _, err := w.Write(f.Payload); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}
	return nil
}

func readFrame(r io.Reader) (Frame, error) {
	var header [13]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err // EOF/io.ErrUnexpectedEOF propagate as-is for callers to detect connection close
	}
	f := Frame{
		Version: header[0],
		Seq:     binary.BigEndian.Uint64(header[1:9]),
	}
	payloadLen := binary.BigEndian.Uint32(header[9:13])
	if payloadLen > MaxFrameSize {
		return Frame{}, fmt.Errorf("frame payload too large: %d bytes (max %d)", payloadLen, MaxFrameSize)
	}
	f.Payload = make([]byte, payloadLen)
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		return Frame{}, fmt.Errorf("read frame payload: %w", err)
	}
	return f, nil
}
