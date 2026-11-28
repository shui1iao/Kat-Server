//go:build !linux

package kernel

import "net"

type tcpProgressSample struct{}

func (tcpProgressSample) advanced(tcpProgressSample) bool { return false }

func extractTCPConn(c net.Conn) *net.TCPConn {
	for c != nil {
		if tc, ok := c.(*net.TCPConn); ok {
			return tc
		}
		if as, ok := c.(*activityStream); ok {
			c = as.Conn
			continue
		}
		if sd, ok := c.(*ssDownReadConn); ok {
			c = sd.Conn
			continue
		}
		break
	}
	return nil
}

func sampleTCPProgress(*net.TCPConn) tcpProgressSample { return tcpProgressSample{} }
