package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// Client sends requests to a Server and waits for its response.
type Client interface {
	Send(ctx context.Context, req Request) (Response, error)
}

type pipeClient struct {
	conn net.Conn

	// mu serializes the entire write+read round trip of Send, not just
	// the sequence counter -- without it, concurrent Sends can interleave
	// their frames on the wire and each read the wrong response.
	mu      sync.Mutex
	nextSeq uint64
}

// NewClient wraps conn as a Client.
func NewClient(conn net.Conn) Client {
	return &pipeClient{conn: conn}
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

	if err := writeFrame(c.conn, Frame{Version: 1, Seq: seq, Payload: payload}); err != nil {
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
