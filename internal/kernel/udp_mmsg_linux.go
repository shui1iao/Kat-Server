//go:build linux && (amd64 || arm64 || loong64 || riscv64 || ppc64le || s390x)

package kernel

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
	udpMmsgBatchSize  = 32
	udpMmsgMaxSlabs   = 6
	udpMmsgSlotBytes  = 65535
	udpMmsgUpgradeCnt = 4
	udpGSOMaxSegSize  = 1472
	udpGSOMaxTotal    = 65507
	udpCmsgBufSize    = 64
)

var udpGSODisabled atomic.Bool

// Linux 64-bit struct mmsghdr { struct msghdr msg_hdr; unsigned int msg_len; char pad[4]; }
type linuxMmsghdr struct {
	hdr unix.Msghdr
	len uint32
	_   [4]byte
}

type udpPendingPkt struct {
	buf  []byte
	addr netip.AddrPort
}

type udpRecvBatch struct {
	backing []byte
	bufs    [udpMmsgBatchSize][]byte
	rawBufs [udpMmsgBatchSize][]byte
	iovs    [udpMmsgBatchSize]unix.Iovec
	sas     [udpMmsgBatchSize]unix.RawSockaddrAny
	cmsgs   [udpMmsgBatchSize][udpCmsgBufSize]byte
	msgs    [udpMmsgBatchSize]linuxMmsghdr
	lens    [udpMmsgBatchSize]int
	addrs   [udpMmsgBatchSize]netip.AddrPort
	pending []udpPendingPkt
	pendIdx int
}

var udpRecvBatchPool = make(chan *udpRecvBatch, udpMmsgMaxSlabs)

func acquireUDPRecvBatch() *udpRecvBatch {
	select {
	case b := <-udpRecvBatchPool:
		b.pending = b.pending[:0]
		b.pendIdx = 0
		return b
	default:
	}
	b := &udpRecvBatch{
		backing: make([]byte, udpMmsgBatchSize*udpMmsgSlotBytes),
	}
	for i := 0; i < udpMmsgBatchSize; i++ {
		slot := b.backing[i*udpMmsgSlotBytes : (i+1)*udpMmsgSlotBytes]
		b.rawBufs[i] = slot
		b.bufs[i] = slot
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

func releaseUDPRecvBatch(b *udpRecvBatch) {
	if b == nil {
		return
	}
	b.pending = b.pending[:0]
	b.pendIdx = 0
	for i := 0; i < udpMmsgBatchSize; i++ {
		b.bufs[i] = b.rawBufs[i]
	}
	select {
	case udpRecvBatchPool <- b:
	default:
	}
}

func enableUDPGRO(raw syscall.RawConn) bool {
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

func parseUDPGROSegmentSize(cmsgData []byte) int {
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

func isIPv6UDPSocket(conn *net.UDPConn) bool {
	if conn == nil {
		return false
	}
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok && la.IP != nil {
		return la.IP.To4() == nil
	}
	return false
}

func (b *udpRecvBatch) drainPending() int {
	rem := len(b.pending) - b.pendIdx
	if rem <= 0 {
		b.pending = b.pending[:0]
		b.pendIdx = 0
		return 0
	}
	n := rem
	if n > udpMmsgBatchSize {
		n = udpMmsgBatchSize
	}
	for i := 0; i < n; i++ {
		it := b.pending[b.pendIdx+i]
		b.bufs[i] = it.buf
		b.lens[i] = len(it.buf)
		b.addrs[i] = it.addr
	}
	b.pendIdx += n
	if b.pendIdx >= len(b.pending) {
		b.pending = b.pending[:0]
		b.pendIdx = 0
	}
	return n
}

// readUDPBatch receives up to udpMmsgBatchSize datagrams using Linux recvmmsg
// (with transparent UDP_GRO super-packet splitting) integrated with Go netpoller.
func readUDPBatch(conn *net.UDPConn, raw syscall.RawConn, b *udpRecvBatch) (int, error) {
	if raw == nil || b == nil {
		b.bufs[0] = b.rawBufs[0]
		n, addr, err := conn.ReadFromUDPAddrPort(b.bufs[0])
		if err != nil {
			return 0, err
		}
		b.lens[0] = n
		b.addrs[0] = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		return 1, nil
	}
	if n := b.drainPending(); n > 0 {
		return n, nil
	}
	var count int
	var sysErr error
	err := raw.Read(func(fd uintptr) bool {
		for i := 0; i < udpMmsgBatchSize; i++ {
			b.msgs[i].hdr.Namelen = unix.SizeofSockaddrAny
			b.msgs[i].hdr.Controllen = udpCmsgBufSize
			b.msgs[i].hdr.Flags = 0
			b.msgs[i].len = 0
		}
		r1, _, errno := unix.Syscall6(
			unix.SYS_RECVMMSG,
			fd,
			uintptr(unsafe.Pointer(&b.msgs[0])),
			uintptr(udpMmsgBatchSize),
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
		if b.msgs[i].hdr.Controllen >= unix.SizeofCmsghdr {
			if gso := parseUDPGROSegmentSize(b.cmsgs[i][:b.msgs[i].hdr.Controllen]); gso > 0 && int(b.msgs[i].len) > gso {
				hasGRO = true
				break
			}
		}
	}
	if !hasGRO {
		for i := 0; i < count; i++ {
			b.bufs[i] = b.rawBufs[i]
			b.lens[i] = int(b.msgs[i].len)
			if ap, ok := parseRawSockaddr(&b.sas[i]); ok {
				b.addrs[i] = ap
			} else {
				b.addrs[i] = netip.AddrPort{}
			}
		}
		return count, nil
	}

	// Split UDP_GRO coalesced datagrams zero-copy into b.pending, then serve up to udpMmsgBatchSize.
	b.pending = b.pending[:0]
	b.pendIdx = 0
	for i := 0; i < count; i++ {
		tot := int(b.msgs[i].len)
		ap, _ := parseRawSockaddr(&b.sas[i])
		rawSlice := b.rawBufs[i][:tot]
		gso := 0
		if b.msgs[i].hdr.Controllen >= unix.SizeofCmsghdr {
			gso = parseUDPGROSegmentSize(b.cmsgs[i][:b.msgs[i].hdr.Controllen])
		}
		if gso > 0 && tot > gso {
			for off := 0; off < tot; off += gso {
				end := off + gso
				if end > tot {
					end = tot
				}
				b.pending = append(b.pending, udpPendingPkt{buf: rawSlice[off:end], addr: ap})
			}
		} else {
			b.pending = append(b.pending, udpPendingPkt{buf: rawSlice, addr: ap})
		}
	}
	return b.drainPending(), nil
}

type udpSendBatch struct {
	iovs    [udpMmsgBatchSize]unix.Iovec
	sas     [udpMmsgBatchSize]unix.RawSockaddrAny
	msgs    [udpMmsgBatchSize]linuxMmsghdr
	gsoCmsg [32]byte
}

// gsoRunLength returns how many consecutive packets starting at pkts[0] can be
// coalesced into a single Linux UDP_SEGMENT (GSO) sendmsg call.
func gsoRunLength(pkts [][]byte, addrs []netip.AddrPort) (run int, segSize int) {
	n := len(pkts)
	if n < 2 {
		return 0, 0
	}
	segSize = len(pkts[0])
	if segSize < 64 || segSize > udpGSOMaxSegSize {
		return 0, 0
	}
	target := addrs[0]
	total := segSize
	run = 1
	maxRun := n
	if maxRun > udpMmsgBatchSize {
		maxRun = udpMmsgBatchSize
	}
	for i := 1; i < maxRun; i++ {
		if addrs[i] != target {
			break
		}
		l := len(pkts[i])
		if l == 0 || l > segSize || total+l > udpGSOMaxTotal {
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

func sendUDPGSO(raw syscall.RawConn, v6Socket bool, sb *udpSendBatch, pkts [][]byte, addr netip.AddrPort, segSize int) (bool, error) {
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
		if sysErr == unix.EINVAL || sysErr == unix.EIO || sysErr == unix.EOPNOTSUPP || sysErr == unix.ENOPROTOOPT {
			udpGSODisabled.Store(true)
			return false, nil
		}
		if sysErr == unix.EMSGSIZE {
			return false, nil
		}
		return false, &net.OpError{Op: "write", Net: "udp", Err: sysErr}
	}
	return true, nil
}

// writeUDPBatch sends up to len(pkts) datagrams via Linux UDP_SEGMENT (GSO)
// for same-destination equal-sized runs, falling back seamlessly to sendmmsg.
func writeUDPBatch(conn *net.UDPConn, raw syscall.RawConn, v6Socket bool, sb *udpSendBatch, pkts [][]byte, addrs []netip.AddrPort) (int, error) {
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
	for sentTotal < n {
		// Fast path: coalesce same-destination equal-sized runs into one UDP_SEGMENT sendmsg.
		if !udpGSODisabled.Load() {
			if run, segSize := gsoRunLength(pkts[sentTotal:], addrs[sentTotal:]); run >= 2 {
				ok, err := sendUDPGSO(raw, v6Socket, sb, pkts[sentTotal:sentTotal+run], addrs[sentTotal], segSize)
				if err != nil {
					return sentTotal, err
				}
				if ok {
					sentTotal += run
					continue
				}
			}
		}

		rem := n - sentTotal
		if rem > udpMmsgBatchSize {
			rem = udpMmsgBatchSize
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
