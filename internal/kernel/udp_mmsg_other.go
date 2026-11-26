//go:build !(linux && (amd64 || arm64 || loong64 || riscv64 || ppc64le || s390x))

package kernel

import (
	"net"
	"net/netip"
	"syscall"
)

const (
	udpMmsgBatchSize  = 32
	udpMmsgSlotBytes  = 65535
	udpMmsgUpgradeCnt = 4
)

type udpRecvBatch struct {
	bufs  [1][]byte
	lens  [1]int
	addrs [1]netip.AddrPort
}

func acquireUDPRecvBatch() *udpRecvBatch {
	return &udpRecvBatch{bufs: [1][]byte{make([]byte, udpMmsgSlotBytes)}}
}

func releaseUDPRecvBatch(*udpRecvBatch) {}

func isIPv6UDPSocket(*net.UDPConn) bool { return false }

func readUDPBatch(conn *net.UDPConn, _ syscall.RawConn, b *udpRecvBatch) (int, error) {
	n, addr, err := conn.ReadFromUDPAddrPort(b.bufs[0])
	if err != nil {
		return 0, err
	}
	b.lens[0] = n
	b.addrs[0] = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	return 1, nil
}

type udpSendBatch struct{}

func writeUDPBatch(conn *net.UDPConn, _ syscall.RawConn, _ bool, _ *udpSendBatch, pkts [][]byte, addrs []netip.AddrPort) (int, error) {
	for i := range pkts {
		if _, err := conn.WriteToUDPAddrPort(pkts[i], addrs[i]); err != nil {
			return i, err
		}
	}
	return len(pkts), nil
}

func enableUDPGRO(syscall.RawConn) bool { return false }
