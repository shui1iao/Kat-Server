//go:build linux

package kernel

import (
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTCPProgressIgnoresRetransmitSegsWhenBytesZero(t *testing.T) {
	// Simulate passive Accepted connection whose peer blackholed before sending/acking payload:
	// kernel RTO retransmissions increment Segs_out while Bytes_received == 0 && Bytes_acked == 0.
	prev := tcpProgressFromInfo(&unix.TCPInfo{
		Bytes_received: 0,
		Bytes_acked:    0,
		Segs_in:        1,
		Segs_out:       2,
	})
	cur := tcpProgressFromInfo(&unix.TCPInfo{
		Bytes_received: 0,
		Bytes_acked:    0,
		Segs_in:        1,
		Segs_out:       12,
	})
	if cur.advanced(prev) {
		t.Fatal("expected advanced == false when bytes == 0 and only Segs_out increased")
	}
	if (tcpProgressSample{bytes: 10, ok: true}).advanced(tcpProgressSample{bytes: 0, ok: false}) {
		t.Fatal("expected advanced == false when prev.ok == false")
	}
	if (tcpProgressSample{bytes: 10, ok: false}).advanced(prev) {
		t.Fatal("expected advanced == false when cur.ok == false")
	}
	acked := tcpProgressFromInfo(&unix.TCPInfo{
		Bytes_received: 0,
		Bytes_acked:    64,
		Segs_in:        2,
		Segs_out:       3,
	})
	if !acked.advanced(prev) {
		t.Fatal("expected advanced == true once Bytes_acked advances")
	}

	// Live loopback socket sanity check for sampleTCPProgress.
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	acceptedCh := make(chan *net.TCPConn, 1)
	go func() {
		c, err := ln.AcceptTCP()
		if err == nil {
			acceptedCh <- c
		}
	}()

	cli, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	srvConn := <-acceptedCh
	defer srvConn.Close()

	s1 := sampleTCPProgress(srvConn)
	s2 := sampleTCPProgress(srvConn)
	if !s1.ok || !s2.ok {
		t.Fatal("expected sampleTCPProgress ok == true on live TCPConn")
	}
	if s2.advanced(s1) {
		t.Fatal("expected idle accepted TCPConn not to report progress")
	}

	if _, err := cli.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var buf [4]byte
	if _, err := io.ReadFull(srvConn, buf[:]); err != nil {
		t.Fatal(err)
	}
	s3 := sampleTCPProgress(srvConn)
	if !s3.advanced(s2) {
		t.Fatalf("expected progress after receiving payload: prev=%+v cur=%+v", s2, s3)
	}
}
