package kernel

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestUDPMmsgReadWriteBatchV4AndLargeDatagram(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	srvRaw, _ := srv.SyscallConn()
	cliRaw, _ := cli.SyscallConn()
	dst := srv.LocalAddr().(*net.UDPAddr).AddrPort()

	const count = 24
	pkts := make([][]byte, count)
	addrs := make([]netip.AddrPort, count)
	for i := 0; i < count; i++ {
		sz := 1200
		if i == count-1 {
			sz = 8192 // verify >2048B datagram without truncation
		}
		p := bytes.Repeat([]byte{byte(i + 1)}, sz)
		pkts[i] = p
		addrs[i] = dst
	}
	var sb udpSendBatch
	sent, err := writeUDPBatch(cli, cliRaw, false, &sb, pkts, addrs)
	if err != nil || sent != count {
		t.Fatalf("writeUDPBatch sent=%d err=%v", sent, err)
	}

	rb := acquireUDPRecvBatch()
	defer releaseUDPRecvBatch(rb)
	_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := 0
	for got < count {
		n, err := readUDPBatch(srv, srvRaw, rb)
		if err != nil {
			t.Fatalf("readUDPBatch got=%d err=%v", got, err)
		}
		for i := 0; i < n; i++ {
			if !bytes.Equal(rb.bufs[i][:rb.lens[i]], pkts[got]) {
				t.Fatalf("packet %d mismatch len=%d want=%d", got, rb.lens[i], len(pkts[got]))
			}
			got++
		}
	}
}

func TestUDPGSOAndGRORoundTrip(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	srvRaw, _ := srv.SyscallConn()
	cliRaw, _ := cli.SyscallConn()
	enableUDPGRO(srvRaw)
	_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))

	const count = 12
	const seg = 1200
	dst := srv.LocalAddr().(*net.UDPAddr).AddrPort()
	pkts := make([][]byte, count)
	addrs := make([]netip.AddrPort, count)
	for i := 0; i < count; i++ {
		size := seg
		if i == count-1 {
			size = 500 // shorter trailing segment
		}
		b := make([]byte, size)
		b[0] = byte(i)
		b[size-1] = byte(i ^ 0x5a)
		pkts[i] = b
		addrs[i] = dst
	}
	var sb udpSendBatch
	sent, err := writeUDPBatch(cli, cliRaw, false, &sb, pkts, addrs)
	if err != nil || sent != count {
		t.Fatalf("writeUDPBatch GSO sent=%d err=%v", sent, err)
	}
	rb := acquireUDPRecvBatch()
	defer releaseUDPRecvBatch(rb)
	got := 0
	for got < count {
		n, err := readUDPBatch(srv, srvRaw, rb)
		if err != nil {
			t.Fatalf("readUDPBatch GRO got=%d err=%v", got, err)
		}
		for i := 0; i < n; i++ {
			pay := rb.bufs[i][:rb.lens[i]]
			if len(pay) != len(pkts[got]) || pay[0] != byte(got) || pay[len(pay)-1] != byte(got^0x5a) {
				t.Fatalf("packet %d mismatch: len=%d want=%d", got, len(pay), len(pkts[got]))
			}
			got++
		}
	}
}
