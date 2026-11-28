//go:build linux && (amd64 || arm64 || loong64 || riscv64 || ppc64le || s390x)

package udpmmsg

import (
	"encoding/binary"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	BatchSize     = 32
	MaxSlabs      = 6
	SlotBytes     = 65535
	UpgradeCnt    = 4
	MaxGSOSegSize = 1472
	// MaxGSOTotal is the IPv6-safe UDP payload ceiling: 65535 - 40(IPv6) - 8(UDP) = 65487.
	MaxGSOTotal    = 65487
	udpCmsgBufSize = 64
	groSkipFlags   = unix.MSG_TRUNC | unix.MSG_CTRUNC
)

// udpGSODisabled is flipped only on ENOPROTOOPT (kernel lacks SOL_UDP/UDP_SEGMENT).
// Interface/route/socket-specific rejections (EINVAL, EIO, EOPNOTSUPP) stay local
// to the caller's SendBatch so other NICs retain GSO offload.
var udpGSODisabled atomic.Bool

// Linux 64-bit struct mmsghdr { struct msghdr msg_hdr; unsigned int msg_len; char pad[4]; }
type linuxMmsghdr struct {
	hdr unix.Msghdr
	len uint32
	_   [4]byte
}

type pendingPkt struct {
	buf  []byte
	addr netip.AddrPort
}

type RecvBatch struct {
	backing []byte
	Bufs    [BatchSize][]byte
	rawBufs [BatchSize][]byte
	iovs    [BatchSize]unix.Iovec
	sas     [BatchSize]unix.RawSockaddrAny
	cmsgs   [BatchSize][udpCmsgBufSize]byte
	msgs    [BatchSize]linuxMmsghdr
	Lens    [BatchSize]int
	Addrs   [BatchSize]netip.AddrPort
	pending []pendingPkt
	pendIdx int
}

var (
	recvBatchPool = make(chan *RecvBatch, MaxSlabs)
	maxSlabsLimit atomic.Int32
)

func init() {
	maxSlabsLimit.Store(MaxSlabs)
}

// SetMaxSlabs configures the maximum number of idle RecvBatch slabs retained
// in the pool (clamped to 0..MaxSlabs). Excess cached slabs are trimmed immediately.
func SetMaxSlabs(n int) {
	if n < 0 {
		n = 0
	}
	if n > MaxSlabs {
		n = MaxSlabs
	}
	maxSlabsLimit.Store(int32(n))
	for len(recvBatchPool) > n {
		select {
		case <-recvBatchPool:
		default:
			return
		}
	}
}

// PoolLen returns the current number of idle RecvBatch slabs in the pool.
func PoolLen() int {
	return len(recvBatchPool)
}

func AcquireRecvBatch() *RecvBatch {
	select {
	case b := <-recvBatchPool:
		b.pending = b.pending[:0]
		b.pendIdx = 0
		return b
	default:
	}
	b := &RecvBatch{
		backing: make([]byte, BatchSize*SlotBytes),
	}
	for i := 0; i < BatchSize; i++ {
		slot := b.backing[i*SlotBytes : (i+1)*SlotBytes]
		b.rawBufs[i] = slot
		b.Bufs[i] = slot
		b.iovs[i].Base = &slot[0]
		b.iovs[i].Len = uint64(len(slot))
		b.msgs[i].hdr.Iov = &b.iovs[i]
		b.msgs[i].hdr.Iovlen = 1
		b.msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&b.sas[i]))
		b.msgs[i].hdr.Namelen = unix.SizeofSockaddrAny
		b.msgs[i].hdr.Control = &b.cmsgs[i][0]
		b.msgs[i].hdr.Controllen = udpCmsgBufSize
	}
	return b
}

func ReleaseRecvBatch(b *RecvBatch) {
	if b == nil {
		return
	}
	b.pending = b.pending[:0]
	b.pendIdx = 0
	for i := 0; i < BatchSize; i++ {
		b.Bufs[i] = b.rawBufs[i]
	}
	if len(recvBatchPool) >= int(maxSlabsLimit.Load()) {
		return
	}
	select {
	case recvBatchPool <- b:
	default:
	}
}

// TrimPool releases all idle RecvBatch slabs cached in recvBatchPool so the
// Go runtime can return unused 2 MiB spans to the OS after burst traffic subsides.
func TrimPool() int {
	dropped := 0
	for {
		select {
		case <-recvBatchPool:
			dropped++
		default:
			return dropped
		}
	}
}

func EnableGRO(raw syscall.RawConn) bool {
	if raw == nil {
		return false
	}
	ok := false
	_ = raw.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_GRO, 1); err == nil {
			ok = true
		}
	})
	return ok
}

// GROSegmentSize extracts the UDP_GRO segment size from ancillary control bytes
// when neither MSG_TRUNC nor MSG_CTRUNC is set; returns 0 when uncoalesced.
func GROSegmentSize(oob []byte, flags int) int {
	if flags&groSkipFlags != 0 || len(oob) < unix.SizeofCmsghdr {
		return 0
	}
	return parseGROSegmentSize(oob)
}

func parseGROSegmentSize(cmsgData []byte) int {
	for len(cmsgData) >= unix.SizeofCmsghdr {
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&cmsgData[0]))
		if hdr.Len < unix.SizeofCmsghdr || int(hdr.Len) > len(cmsgData) {
			break
		}
		if hdr.Level == unix.SOL_UDP && hdr.Type == unix.UDP_GRO && int(hdr.Len) >= unix.CmsgLen(2) {
			return int(*(*uint16)(unsafe.Pointer(&cmsgData[unix.CmsgLen(0)])))
		}
		step := unix.CmsgSpace(int(hdr.Len) - unix.CmsgLen(0))
		if step <= 0 || step > len(cmsgData) {
			break
		}
		cmsgData = cmsgData[step:]
	}
	return 0
}

func parseRawSockaddr(sa *unix.RawSockaddrAny) (netip.AddrPort, bool) {
	switch sa.Addr.Family {
	case unix.AF_INET:
		in4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&in4.Port))[:])
		return netip.AddrPortFrom(netip.AddrFrom4(in4.Addr), port), true
	case unix.AF_INET6:
		in6 := (*unix.RawSockaddrInet6)(unsafe.Pointer(sa))
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&in6.Port))[:])
		addr := netip.AddrFrom16(in6.Addr).Unmap()
		return netip.AddrPortFrom(addr, port), true
	default:
		return netip.AddrPort{}, false
	}
}

func fillRawSockaddr(sa *unix.RawSockaddrAny, ap netip.AddrPort, v6Socket bool) uint32 {
	addr := ap.Addr().Unmap()
	port := ap.Port()
	if addr.Is4() && !v6Socket {
		in4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		*in4 = unix.RawSockaddrInet4{Family: unix.AF_INET}
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&in4.Port))[:], port)
		in4.Addr = addr.As4()
		return unix.SizeofSockaddrInet4
	}
	in6 := (*unix.RawSockaddrInet6)(unsafe.Pointer(sa))
	*in6 = unix.RawSockaddrInet6{Family: unix.AF_INET6}
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&in6.Port))[:], port)
	if addr.Is4() {
		a4 := addr.As4()
		in6.Addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a4[0], a4[1], a4[2], a4[3]}
	} else {
		in6.Addr = addr.As16()
	}
	return unix.SizeofSockaddrInet6
}

func IsIPv6Socket(conn *net.UDPConn) bool {
	if conn == nil {
		return false
	}
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok && la.IP != nil {
		return la.IP.To4() == nil
	}
	return false
}

func (b *RecvBatch) drainPending() int {
	rem := len(b.pending) - b.pendIdx
	if rem <= 0 {
		b.pending = b.pending[:0]
		b.pendIdx = 0
		return 0
	}
	n := rem
	if n > BatchSize {
		n = BatchSize
	}
	for i := 0; i < n; i++ {
		it := b.pending[b.pendIdx+i]
		b.Bufs[i] = it.buf
		b.Lens[i] = len(it.buf)
		b.Addrs[i] = it.addr
	}
	b.pendIdx += n
	if b.pendIdx >= len(b.pending) {
		b.pending = b.pending[:0]
		b.pendIdx = 0
	}
	return n
}

// ReadBatch receives up to BatchSize datagrams using Linux recvmmsg
// (with transparent UDP_GRO super-packet splitting) integrated with Go netpoller.
func ReadBatch(conn *net.UDPConn, raw syscall.RawConn, b *RecvBatch) (int, error) {
	if b == nil {
		return 0, unix.EINVAL
	}
	if raw == nil {
		b.Bufs[0] = b.rawBufs[0]
		n, addr, err := conn.ReadFromUDPAddrPort(b.Bufs[0])
		if err != nil {
			return 0, err
		}
		b.Lens[0] = n
		b.Addrs[0] = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		return 1, nil
	}
	if n := b.drainPending(); n > 0 {
		return n, nil
	}
	var count int
	var sysErr error
	err := raw.Read(func(fd uintptr) bool {
		for i := 0; i < BatchSize; i++ {
			b.msgs[i].hdr.Namelen = unix.SizeofSockaddrAny
			b.msgs[i].hdr.Controllen = udpCmsgBufSize
			b.msgs[i].hdr.Flags = 0
			b.msgs[i].len = 0
		}
		r1, _, errno := unix.Syscall6(
			unix.SYS_RECVMMSG,
			fd,
			uintptr(unsafe.Pointer(&b.msgs[0])),
			uintptr(BatchSize),
			uintptr(unix.MSG_DONTWAIT),
			0,
			0,
		)
		if errno != 0 {
			if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK || errno == unix.EINTR {
				return false
			}
			sysErr = errno
			return true
		}
		count = int(r1)
		return true
	})
	runtime.KeepAlive(b)
	if err != nil {
		return 0, err
	}
	if sysErr != nil {
		return 0, &net.OpError{Op: "read", Net: "udp", Err: sysErr}
	}

	hasGRO := false
	for i := 0; i < count; i++ {
		if b.msgs[i].hdr.Flags&groSkipFlags == 0 && b.msgs[i].hdr.Controllen >= unix.SizeofCmsghdr {
			if gso := parseGROSegmentSize(b.cmsgs[i][:b.msgs[i].hdr.Controllen]); gso > 0 && int(b.msgs[i].len) > gso {
				hasGRO = true
				break
			}
		}
	}
	if !hasGRO {
		for i := 0; i < count; i++ {
			b.Bufs[i] = b.rawBufs[i]
			b.Lens[i] = int(b.msgs[i].len)
			if ap, ok := parseRawSockaddr(&b.sas[i]); ok {
				b.Addrs[i] = ap
			} else {
				b.Addrs[i] = netip.AddrPort{}
			}
		}
		return count, nil
	}

	// Split UDP_GRO coalesced datagrams zero-copy into b.pending, then serve up to BatchSize.
	b.pending = b.pending[:0]
	b.pendIdx = 0
	for i := 0; i < count; i++ {
		tot := int(b.msgs[i].len)
		ap, _ := parseRawSockaddr(&b.sas[i])
		rawSlice := b.rawBufs[i][:tot]
		gso := 0
		if b.msgs[i].hdr.Flags&groSkipFlags == 0 && b.msgs[i].hdr.Controllen >= unix.SizeofCmsghdr {
			gso = parseGROSegmentSize(b.cmsgs[i][:b.msgs[i].hdr.Controllen])
		}
		if gso > 0 && tot > gso {
			for off := 0; off < tot; off += gso {
				end := off + gso
				if end > tot {
					end = tot
				}
				b.pending = append(b.pending, pendingPkt{buf: rawSlice[off:end], addr: ap})
			}
		} else {
			b.pending = append(b.pending, pendingPkt{buf: rawSlice, addr: ap})
		}
	}
	return b.drainPending(), nil
}

type SendBatch struct {
	iovs        [BatchSize]unix.Iovec
	sas         [BatchSize]unix.RawSockaddrAny
	msgs        [BatchSize]linuxMmsghdr
	gsoCmsg     [32]byte
	gsoDisabled bool
}

// GSODisabled reports whether GSO has been locally disabled on this SendBatch
// (or globally due to ENOPROTOOPT).
func (sb *SendBatch) GSODisabled() bool {
	return (sb != nil && sb.gsoDisabled) || udpGSODisabled.Load()
}

// DisableGSO marks this SendBatch as ineligible for UDP_SEGMENT so callers
// sharing socket-level state can skip redundant failing sendmsg attempts.
func (sb *SendBatch) DisableGSO() {
	if sb != nil {
		sb.gsoDisabled = true
	}
}

// gsoRunLength returns how many consecutive packets starting at pkts[0] can be
// coalesced into a single Linux UDP_SEGMENT (GSO) sendmsg call.
func gsoRunLength(pkts [][]byte, addrs []netip.AddrPort) (run int, segSize int) {
	n := len(pkts)
	if n < 2 {
		return 0, 0
	}
	segSize = len(pkts[0])
	if segSize < 64 || segSize > MaxGSOSegSize {
		return 0, 0
	}
	target := addrs[0]
	total := segSize
	run = 1
	maxRun := n
	if maxRun > BatchSize {
		maxRun = BatchSize
	}
	for i := 1; i < maxRun; i++ {
		if addrs[i] != target {
			break
		}
		l := len(pkts[i])
		if l == 0 || l > segSize || total+l > MaxGSOTotal {
			break
		}
		total += l
		run++
		if l < segSize {
			// Shorter trailing segment must end the GSO super-packet.
			break
		}
	}
	if run < 2 {
		return 0, 0
	}
	return run, segSize
}

func sendUDPGSO(raw syscall.RawConn, v6Socket bool, sb *SendBatch, pkts [][]byte, addr netip.AddrPort, segSize int) (bool, error) {
	saLen := fillRawSockaddr(&sb.sas[0], addr, v6Socket)
	for i, p := range pkts {
		sb.iovs[i].Base = &p[0]
		sb.iovs[i].Len = uint64(len(p))
	}
	cmsgSpace := unix.CmsgSpace(2)
	for i := 0; i < cmsgSpace; i++ {
		sb.gsoCmsg[i] = 0
	}
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&sb.gsoCmsg[0]))
	cmsg.Level = unix.SOL_UDP
	cmsg.Type = unix.UDP_SEGMENT
	cmsg.SetLen(unix.CmsgLen(2))
	*(*uint16)(unsafe.Pointer(&sb.gsoCmsg[unix.CmsgLen(0)])) = uint16(segSize)

	msg := unix.Msghdr{
		Name:       (*byte)(unsafe.Pointer(&sb.sas[0])),
		Namelen:    saLen,
		Iov:        &sb.iovs[0],
		Iovlen:     uint64(len(pkts)),
		Control:    &sb.gsoCmsg[0],
		Controllen: uint64(cmsgSpace),
	}
	var sysErr error
	err := raw.Write(func(fd uintptr) bool {
		_, _, errno := unix.Syscall(
			unix.SYS_SENDMSG,
			fd,
			uintptr(unsafe.Pointer(&msg)),
			uintptr(unix.MSG_DONTWAIT),
		)
		if errno != 0 {
			if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK || errno == unix.EINTR {
				return false
			}
			sysErr = errno
			return true
		}
		return true
	})
	runtime.KeepAlive(pkts)
	runtime.KeepAlive(sb)
	if err != nil {
		return false, err
	}
	if sysErr != nil {
		if sysErr == unix.ENOPROTOOPT {
			udpGSODisabled.Store(true)
			sb.gsoDisabled = true
			return false, nil
		}
		if sysErr == unix.EINVAL || sysErr == unix.EIO || sysErr == unix.EOPNOTSUPP {
			sb.gsoDisabled = true
			return false, nil
		}
		if sysErr == unix.EMSGSIZE {
			return false, nil
		}
		return false, &net.OpError{Op: "write", Net: "udp", Err: sysErr}
	}
	return true, nil
}

// WriteBatch sends up to len(pkts) datagrams via Linux UDP_SEGMENT (GSO)
// for same-destination equal-sized runs, falling back seamlessly to sendmmsg.
func WriteBatch(conn *net.UDPConn, raw syscall.RawConn, v6Socket bool, sb *SendBatch, pkts [][]byte, addrs []netip.AddrPort) (int, error) {
	n := len(pkts)
	if n == 0 {
		return 0, nil
	}
	if n == 1 || raw == nil || sb == nil {
		for i := 0; i < n; i++ {
			if _, err := conn.WriteToUDPAddrPort(pkts[i], addrs[i]); err != nil {
				return i, err
			}
		}
		return n, nil
	}
	sentTotal := 0
	gsoFallback := false
	for sentTotal < n {
		// Fast path: coalesce same-destination equal-sized runs into one UDP_SEGMENT sendmsg.
		if !gsoFallback && !sb.gsoDisabled && !udpGSODisabled.Load() {
			if run, segSize := gsoRunLength(pkts[sentTotal:], addrs[sentTotal:]); run >= 2 {
				ok, err := sendUDPGSO(raw, v6Socket, sb, pkts[sentTotal:sentTotal+run], addrs[sentTotal], segSize)
				if err != nil {
					return sentTotal, err
				}
				if ok {
					sentTotal += run
					continue
				}
				// Avoid retrying sendUDPGSO on the same run if EMSGSIZE forced fallback.
				gsoFallback = true
			}
		}

		rem := n - sentTotal
		if rem > BatchSize {
			rem = BatchSize
		}
		for i := 0; i < rem; i++ {
			p := pkts[sentTotal+i]
			if len(p) > 0 {
				sb.iovs[i].Base = &p[0]
				sb.iovs[i].Len = uint64(len(p))
			} else {
				sb.iovs[i].Base = nil
				sb.iovs[i].Len = 0
			}
			saLen := fillRawSockaddr(&sb.sas[i], addrs[sentTotal+i], v6Socket)
			sb.msgs[i].hdr = unix.Msghdr{
				Name:    (*byte)(unsafe.Pointer(&sb.sas[i])),
				Namelen: saLen,
				Iov:     &sb.iovs[i],
				Iovlen:  1,
			}
			sb.msgs[i].len = 0
		}
		var sent int
		var sysErr error
		err := raw.Write(func(fd uintptr) bool {
			r1, _, errno := unix.Syscall6(
				unix.SYS_SENDMMSG,
				fd,
				uintptr(unsafe.Pointer(&sb.msgs[0])),
				uintptr(rem),
				uintptr(unix.MSG_DONTWAIT),
				0,
				0,
			)
			if errno != 0 {
				if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK || errno == unix.EINTR {
					return false
				}
				sysErr = errno
				return true
			}
			sent = int(r1)
			return true
		})
		runtime.KeepAlive(pkts)
		runtime.KeepAlive(sb)
		if err != nil {
			return sentTotal, err
		}
		if sysErr != nil {
			return sentTotal, &net.OpError{Op: "write", Net: "udp", Err: sysErr}
		}
		if sent == 0 {
			return sentTotal, &net.OpError{Op: "write", Net: "udp", Err: unix.EAGAIN}
		}
		sentTotal += sent
	}
	return sentTotal, nil
}
