package protocol

import "net"

// NewPipeTransport returns an in-memory connection pair (no sockets) for
// the default, in-process transport between a Client and a Server.
func NewPipeTransport() (clientConn, serverConn net.Conn) {
	return net.Pipe()
}
