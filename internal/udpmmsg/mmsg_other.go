//go:build !(linux && (amd64 || arm64 || loong64 || riscv64 || ppc64le || s390x))

package udpmmsg

import (
	"net"
	"net/netip"
	"syscall"
)

const (
	BatchSize     = 32
	MaxSlabs      = 6
	SlotBytes     = 65535
	UpgradeCnt    = 4
	MaxGSOSegSize = 1472
	MaxGSOTotal   = 65487
)

type RecvBatch struct {
	Bufs  [1][]byte
	Lens  [1]int
	Addrs [1]netip.AddrPort
}

func SetMaxSlabs(int)                {}
func PoolLen() int                   { return 0 }
func AcquireRecvBatch() *RecvBatch   { return &RecvBatch{Bufs: [1][]byte{make([]byte, SlotBytes)}} }
func ReleaseRecvBatch(*RecvBatch)    {}
func TrimPool() int                  { return 0 }
func IsIPv6Socket(*net.UDPConn) bool { return false }
func EnableGRO(syscall.RawConn) bool { return false }
func GROSegmentSize([]byte, int) int { return 0 }

func ReadBatch(conn *net.UDPConn, _ syscall.RawConn, b *RecvBatch) (int, error) {
	if b == nil {
		return 0, syscall.EINVAL
	}
	n, addr, err := conn.ReadFromUDPAddrPort(b.Bufs[0])
	if err != nil {
		return 0, err
	}
	b.Lens[0] = n
	b.Addrs[0] = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	return 1, nil
}

type SendBatch struct {
	gsoDisabled bool
}

func (sb *SendBatch) GSODisabled() bool { return true }
func (sb *SendBatch) DisableGSO() {
	if sb != nil {
		sb.gsoDisabled = true
	}
}

func WriteBatch(conn *net.UDPConn, _ syscall.RawConn, _ bool, _ *SendBatch, pkts [][]byte, addrs []netip.AddrPort) (int, error) {
	for i := range pkts {
		if _, err := conn.WriteToUDPAddrPort(pkts[i], addrs[i]); err != nil {
			return i, err
		}
	}
	return len(pkts), nil
}
