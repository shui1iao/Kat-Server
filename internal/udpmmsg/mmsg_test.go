//go:build linux && (amd64 || arm64 || loong64 || riscv64 || ppc64le || s390x)

package udpmmsg

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestBatchEdgeSizesZeroTo65487(t *testing.T) {
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer rx.Close()
	tx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	// Ensure large socket buffers so 65487B datagram + burst never drops in loopback queue.
	_ = rx.SetReadBuffer(512 << 10)
	_ = tx.SetWriteBuffer(512 << 10)

	rxRaw, err := rx.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	txRaw, err := tx.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	dst := rx.LocalAddr().(*net.UDPAddr).AddrPort()

	sizes := []int{0, 1, 63, 64, 1400, 1420, 1472, 8192, MaxGSOTotal}
	pkts := make([][]byte, len(sizes))
	addrs := make([]netip.AddrPort, len(sizes))
	for i, sz := range sizes {
		b := make([]byte, sz)
		for j := range b {
			b[j] = byte((i*31 + j) & 0xff)
		}
		pkts[i] = b
		addrs[i] = dst
	}

	var sb SendBatch
	sent, err := WriteBatch(tx, txRaw, false, &sb, pkts, addrs)
	if err != nil || sent != len(pkts) {
		t.Fatalf("WriteBatch edge sizes: sent=%d want=%d err=%v", sent, len(pkts), err)
	}

	rb := AcquireRecvBatch()
	defer ReleaseRecvBatch(rb)
	_ = rx.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := 0
	for got < len(sizes) {
		cnt, err := ReadBatch(rx, rxRaw, rb)
		if err != nil {
			t.Fatalf("ReadBatch at %d: %v", got, err)
		}
		for i := 0; i < cnt; i++ {
			pay := rb.Bufs[i][:rb.Lens[i]]
			if !bytes.Equal(pay, pkts[got]) {
				t.Fatalf("pkt %d mismatch: got len=%d, want len=%d", got, len(pay), len(pkts[got]))
			}
			got++
		}
	}
}

func TestGSOAndGROOver32SegmentsAndTruncGuard(t *testing.T) {
	// 1. Real kernel GSO -> GRO round-trip over IPv4 and IPv6 loopback with >32 segments!
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			bindIP := net.IPv4(127, 0, 0, 1)
			isV6 := network == "udp6"
			if isV6 {
				bindIP = net.IPv6loopback
			}
			srv, err := net.ListenUDP(network, &net.UDPAddr{IP: bindIP, Port: 0})
			if err != nil {
				if isV6 {
					t.Skipf("udp6 unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer srv.Close()
			cli, err := net.ListenUDP(network, &net.UDPAddr{IP: bindIP, Port: 0})
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			_ = srv.SetReadBuffer(512 << 10)
			_ = cli.SetWriteBuffer(512 << 10)

			srvRaw, _ := srv.SyscallConn()
			cliRaw, _ := cli.SyscallConn()
			EnableGRO(srvRaw)
			_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))

			const count = 40 // > BatchSize (32)
			const seg = 1200
			dst := srv.LocalAddr().(*net.UDPAddr).AddrPort()
			pkts := make([][]byte, count)
			addrs := make([]netip.AddrPort, count)
			for i := 0; i < count; i++ {
				size := seg
				if i == count-1 {
					size = 333
				}
				b := make([]byte, size)
				b[0] = byte(i)
				b[size-1] = byte(i ^ 0x5a)
				pkts[i] = b
				addrs[i] = dst
			}

			var sb SendBatch
			sent, err := WriteBatch(cli, cliRaw, IsIPv6Socket(cli), &sb, pkts, addrs)
			if err != nil || sent != count {
				t.Fatalf("WriteBatch(%s) sent=%d err=%v", network, sent, err)
			}

			rb := AcquireRecvBatch()
			defer ReleaseRecvBatch(rb)
			got := 0
			for got < count {
				n, err := ReadBatch(srv, srvRaw, rb)
				if err != nil {
					t.Fatalf("ReadBatch(%s) at %d: %v", network, got, err)
				}
				for i := 0; i < n; i++ {
					pay := rb.Bufs[i][:rb.Lens[i]]
					if !bytes.Equal(pay, pkts[got]) {
						t.Fatalf("pkt %d mismatch: len=%d want=%d", got, len(pay), len(pkts[got]))
					}
					got++
				}
			}
		})
	}

	// 2. Deterministic >32 segment synthetic GRO split + drainPending + MSG_TRUNC/MSG_CTRUNC guard!
	rb := AcquireRecvBatch()
	defer ReleaseRecvBatch(rb)

	const segSize = 1000
	const totalGRO = 39*segSize + 333 // 40 segments > BatchSize(32)
	cmsgSpace := unix.CmsgSpace(2)
	clear(rb.cmsgs[0][:])
	chdr := (*unix.Cmsghdr)(unsafe.Pointer(&rb.cmsgs[0][0]))
	chdr.Level = unix.SOL_UDP
	chdr.Type = unix.UDP_GRO
	chdr.SetLen(unix.CmsgLen(2))
	*(*uint16)(unsafe.Pointer(&rb.cmsgs[0][unix.CmsgLen(0)])) = uint16(segSize)

	if got := GROSegmentSize(rb.cmsgs[0][:cmsgSpace], 0); got != segSize {
		t.Fatalf("GROSegmentSize got %d, want %d", got, segSize)
	}
	// MSG_TRUNC and MSG_CTRUNC must suppress GRO splitting!
	if got := GROSegmentSize(rb.cmsgs[0][:cmsgSpace], unix.MSG_TRUNC); got != 0 {
		t.Fatalf("expected MSG_TRUNC to suppress GROSegmentSize, got %d", got)
	}
	if got := GROSegmentSize(rb.cmsgs[0][:cmsgSpace], unix.MSG_CTRUNC); got != 0 {
		t.Fatalf("expected MSG_CTRUNC to suppress GROSegmentSize, got %d", got)
	}

	// Simulate ReadBatch splitting 40 segments into pending and draining in two batches (32 + 8).
	ap := netip.MustParseAddrPort("127.0.0.1:9000")
	rawSlice := rb.rawBufs[0][:totalGRO]
	for i := range rawSlice {
		rawSlice[i] = byte(i % 251)
	}
	rb.pending = rb.pending[:0]
	rb.pendIdx = 0
	for off := 0; off < totalGRO; off += segSize {
		end := min(off+segSize, totalGRO)
		rb.pending = append(rb.pending, pendingPkt{buf: rawSlice[off:end], addr: ap})
	}
	n1 := rb.drainPending()
	if n1 != BatchSize {
		t.Fatalf("first drainPending got %d, want %d", n1, BatchSize)
	}
	n2 := rb.drainPending()
	if n2 != 8 || rb.Lens[7] != 333 {
		t.Fatalf("second drainPending got n=%d tail=%d, want 8 and 333", n2, rb.Lens[7])
	}
	if n3 := rb.drainPending(); n3 != 0 {
		t.Fatalf("third drainPending got %d, want 0", n3)
	}

	// Verify gsoRunLength respects IPv6-safe ceiling 65487B (44 * 1472 = 64768 <= 65487; 45 * 1472 = 66240 > 65487).
	maxBatch := make([][]byte, BatchSize)
	maxAddrs := make([]netip.AddrPort, BatchSize)
	for i := range maxBatch {
		maxBatch[i] = make([]byte, MaxGSOSegSize)
		maxAddrs[i] = ap
	}
	run, s := gsoRunLength(maxBatch, maxAddrs)
	if run != BatchSize || s != MaxGSOSegSize || run*s > MaxGSOTotal {
		t.Fatalf("unexpected gsoRunLength: run=%d seg=%d total=%d", run, s, run*s)
	}
}

type failFirstSendmsgRawConn struct {
	real  syscall.RawConn
	fired bool
}

func (f *failFirstSendmsgRawConn) Control(fn func(fd uintptr)) error { return f.real.Control(fn) }
func (f *failFirstSendmsgRawConn) Read(fn func(fd uintptr) bool) error {
	return f.real.Read(fn)
}
func (f *failFirstSendmsgRawConn) Write(fn func(fd uintptr) bool) error {
	if !f.fired {
		f.fired = true
		// Trigger a genuine kernel EINVAL/EOPNOTSUPP on SOL_UDP/UDP_SEGMENT by invoking
		// the sendmsg closure on an AF_UNIX SOCK_DGRAM socketpair fd!
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			return errors.New("socketpair failed")
		}
		defer unix.Close(fds[0])
		defer unix.Close(fds[1])
		fn(uintptr(fds[0]))
		return nil
	}
	return f.real.Write(fn)
}

func TestLocalGSODowngradeDoesNotPolluteGlobalGSOAndTrimPool(t *testing.T) {
	prevGlobal := udpGSODisabled.Load()
	udpGSODisabled.Store(false)
	defer udpGSODisabled.Store(prevGlobal)

	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer rx.Close()
	txBad, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer txBad.Close()
	txGood, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer txGood.Close()

	rxRaw, _ := rx.SyscallConn()
	txBadRaw, _ := txBad.SyscallConn()
	txGoodRaw, _ := txGood.SyscallConn()
	dst := rx.LocalAddr().(*net.UDPAddr).AddrPort()

	pkts := [][]byte{
		bytes.Repeat([]byte("A"), 1200),
		bytes.Repeat([]byte("B"), 1200),
		bytes.Repeat([]byte("C"), 600),
	}
	addrs := []netip.AddrPort{dst, dst, dst}

	// 1. Socket 1 hits EINVAL/EOPNOTSUPP on UDP_SEGMENT -> must locally disable sbBad
	// and fall back cleanly to sendmmsg WITHOUT setting global udpGSODisabled!
	var sbBad SendBatch
	wrappedBad := &failFirstSendmsgRawConn{real: txBadRaw}
	sent, err := WriteBatch(txBad, wrappedBad, false, &sbBad, pkts, addrs)
	if err != nil || sent != len(pkts) {
		t.Fatalf("WriteBatch fallback failed: sent=%d err=%v", sent, err)
	}
	if !sbBad.GSODisabled() {
		t.Fatal("expected sbBad.GSODisabled() == true after socket-level GSO rejection")
	}
	if udpGSODisabled.Load() {
		t.Fatal("socket-level GSO rejection polluted process-global udpGSODisabled!")
	}

	// 2. Socket 2 (healthy NIC) must keep GSO enabled and succeed via UDP_SEGMENT!
	var sbGood SendBatch
	if sbGood.GSODisabled() {
		t.Fatal("healthy SendBatch unexpectedly disabled")
	}
	sent2, err := WriteBatch(txGood, txGoodRaw, false, &sbGood, pkts, addrs)
	if err != nil || sent2 != len(pkts) {
		t.Fatalf("healthy WriteBatch failed: sent=%d err=%v", sent2, err)
	}
	if sbGood.GSODisabled() || udpGSODisabled.Load() {
		t.Fatal("healthy socket unexpectedly disabled GSO")
	}

	rb := AcquireRecvBatch()
	_ = rx.SetReadDeadline(time.Now().Add(2 * time.Second))
	totalRx := 0
	for totalRx < 6 {
		n, err := ReadBatch(rx, rxRaw, rb)
		if err != nil {
			t.Fatalf("ReadBatch: %v", err)
		}
		totalRx += n
	}
	ReleaseRecvBatch(rb)

	// 3. Verify pool quota & TrimPool() reclaims all cached 2 MiB slabs!
	TrimPool()
	SetMaxSlabs(MaxSlabs)
	batches := make([]*RecvBatch, MaxSlabs)
	for i := range batches {
		batches[i] = AcquireRecvBatch()
	}
	for _, b := range batches {
		ReleaseRecvBatch(b)
	}
	if PoolLen() != MaxSlabs {
		t.Fatalf("expected PoolLen=%d, got %d", MaxSlabs, PoolLen())
	}
	SetMaxSlabs(2)
	if PoolLen() != 2 {
		t.Fatalf("expected SetMaxSlabs(2) to trim pool to 2, got %d", PoolLen())
	}
	SetMaxSlabs(MaxSlabs)
	dropped := TrimPool()
	if dropped != 2 || PoolLen() != 0 {
		t.Fatalf("TrimPool dropped=%d PoolLen=%d, want dropped=2 PoolLen=0", dropped, PoolLen())
	}
}

func TestReadBatchNilRecvBatchReturnsEINVAL(t *testing.T) {
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer rx.Close()
	rxRaw, err := rx.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := ReadBatch(rx, nil, nil); n != 0 || !errors.Is(err, unix.EINVAL) {
		t.Fatalf("ReadBatch(rx, nil, nil) = (%d, %v), want (0, EINVAL)", n, err)
	}
	if n, err := ReadBatch(rx, rxRaw, nil); n != 0 || !errors.Is(err, unix.EINVAL) {
		t.Fatalf("ReadBatch(rx, rxRaw, nil) = (%d, %v), want (0, EINVAL)", n, err)
	}
}
