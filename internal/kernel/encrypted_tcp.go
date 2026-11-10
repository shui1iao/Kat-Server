package kernel

import (
	"errors"
	"io"
	"net"
)

// Payload I/O always uses the authenticated codec, deadlines and addresses use
// the transport. This wrapper can never satisfy the raw *net.TCPConn fast path.
type encryptedStream struct {
	net.Conn
	codec io.ReadWriteCloser
}

func (c *encryptedStream) Read(b []byte) (int, error)  { return c.codec.Read(b) }
func (c *encryptedStream) Write(b []byte) (int, error) { return c.codec.Write(b) }
func (c *encryptedStream) Close() error                { return c.codec.Close() }
func (c *encryptedStream) CloseWrite() error {
	if v, ok := c.codec.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return errors.New("encrypted stream has no half-close")
}
func (s *Server) acceptSS(raw net.Conn, in Inbound) (request, error) {
	// No prefix/bufio/ReadFull here: SIP022 owns its one initial raw Read.
	codec, e := in.ssRuntime.codec.Accept(raw)
	if e != nil {
		if tcp, ok := raw.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = raw.Close()
		return request{}, e
	}
	a := codec.Target()
	return request{Command: 1, Mode: "shadowsocks", UserIndex: 0, Target: Address{a.Host, a.Port}, Stream: &encryptedStream{raw, codec}}, nil
}
