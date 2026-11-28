package udpmmsg

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestCommonUDPMmsgBatchRoundTripAndGSOState(t *testing.T) {
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

	rxRaw, _ := rx.SyscallConn()
	txRaw, _ := tx.SyscallConn()

	if n, err := ReadBatch(rx, nil, nil); n != 0 || !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("ReadBatch(rx, nil, nil) = (%d, %v), want (0, EINVAL)", n, err)
	}

	if runtime.GOOS != "linux" {
		if !(&SendBatch{}).GSODisabled() {
			t.Fatal("expected (&SendBatch{}).GSODisabled() == true on non-Linux platform")
		}
		if !(*SendBatch)(nil).GSODisabled() {
			t.Fatal("expected (*SendBatch)(nil).GSODisabled() == true on non-Linux platform")
		}
	}
	var sb SendBatch
	sb.DisableGSO()
	if !sb.GSODisabled() {
		t.Fatal("expected sb.GSODisabled() == true after DisableGSO()")
	}

	dst := rx.LocalAddr().(*net.UDPAddr).AddrPort()
	pkts := [][]byte{
		[]byte("hello-udpmmsg-0"),
		bytes.Repeat([]byte{0x5a}, 512),
		[]byte("tail-pkt"),
	}
	addrs := []netip.AddrPort{dst, dst, dst}

	sent, err := WriteBatch(tx, txRaw, IsIPv6Socket(tx), &sb, pkts, addrs)
	if err != nil || sent != len(pkts) {
		t.Fatalf("WriteBatch sent=%d err=%v, want %d", sent, err, len(pkts))
	}

	rb := AcquireRecvBatch()
	defer func() {
		ReleaseRecvBatch(rb)
		ReleaseRecvBatch(nil)
	}()

	_ = rx.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := 0
	for got < len(pkts) {
		n, err := ReadBatch(rx, rxRaw, rb)
		if err != nil {
			t.Fatalf("ReadBatch at %d: %v", got, err)
		}
		for i := 0; i < n; i++ {
			payload := rb.Bufs[i][:rb.Lens[i]]
			if !bytes.Equal(payload, pkts[got]) {
				t.Fatalf("packet %d payload mismatch: got %dB, want %dB", got, len(payload), len(pkts[got]))
			}
			if !rb.Addrs[i].IsValid() {
				t.Fatalf("packet %d invalid source addr %v", got, rb.Addrs[i])
			}
			got++
		}
	}
}
