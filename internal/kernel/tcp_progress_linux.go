//go:build linux

package kernel

import (
	"net"

	"golang.org/x/sys/unix"
)

type tcpProgressSample struct {
	bytes uint64
	ok    bool
}

func (cur tcpProgressSample) advanced(prev tcpProgressSample) bool {
	return cur.ok && prev.ok && cur.bytes > prev.bytes
}

func tcpProgressFromInfo(info *unix.TCPInfo) tcpProgressSample {
	if info == nil {
		return tcpProgressSample{}
	}
	return tcpProgressSample{
		bytes: info.Bytes_received + info.Bytes_acked,
		ok:    true,
	}
}

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

func sampleTCPProgress(tc *net.TCPConn) tcpProgressSample {
	if tc == nil {
		return tcpProgressSample{}
	}
	raw, err := tc.SyscallConn()
	if err != nil || raw == nil {
		return tcpProgressSample{}
	}
	var out tcpProgressSample
	_ = raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.SOL_TCP, unix.TCP_INFO)
		if err != nil || info == nil {
			return
		}
		out = tcpProgressFromInfo(info)
	})
	return out
}
