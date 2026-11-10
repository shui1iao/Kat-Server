package kernel

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestUDPBadFramesAndLengths(t *testing.T) {
	cert, pool := testCert(t)
	target, _ := echoUDP(t)
	for _, p := range []string{"trojan"} {
		s := startTest(t, inFor(p, cert), nil)
		for _, bad := range []string{"oversize", "truncated", "badcrlf"} {
			t.Run(p+"-"+bad, func(t *testing.T) {
				c := dialPeer(t, s, pool)
				writeAll(c, peerHeader(p, 3, target))
				peerResponse(t, c, p)
				frame := peerAddr(target, false)
				switch bad {
				case "oversize":
					frame = append(frame, 255, 255)
				case "truncated":
					frame = append(frame, 0, 9, 13, 10, 1, 2)
				case "badcrlf":
					frame = append(frame, 0, 1, 0, 10, 1)
				}
				writeAll(c, frame)
				c.(interface{ CloseWrite() error }).CloseWrite()
				b, e := io.ReadAll(c)
				if e == nil && len(b) > 0 {
					t.Fatal("bad UDP frame accepted")
				}
				c.Close()
				waitFor(t, func() bool { return s.Stats().UDP == 0 })
			})
		}
	}
}
func TestLargeDatagramAndCombinedFrames(t *testing.T) {
	cert, pool := testCert(t)
	s := startTest(t, inFor("trojan", cert), nil)
	target, _ := echoUDP(t)
	c := dialPeer(t, s, pool)
	writeAll(c, peerHeader("trojan", 3, target))
	peerResponse(t, c, "trojan")
	want := bytes.Repeat([]byte{0x42}, maxDatagram)
	frame := peerUDPFrame("trojan", target, want)
	writeAll(c, frame)
	if got := peerUDPRead(t, c, "trojan"); !bytes.Equal(got, want) {
		t.Fatal("large UDP corrupted")
	}
	b := append(peerUDPFrame("trojan", target, []byte("merged1")), peerUDPFrame("trojan", target, []byte("merged2"))...)
	writeAll(c, b)
	for _, want := range []string{"merged1", "merged2"} {
		if string(peerUDPRead(t, c, "trojan")) != want {
			t.Fatal("coalesced frames corrupted")
		}
	}
}
func TestAuthenticatedSOCKSUDP(t *testing.T) {
	s := startTest(t, Inbound{Protocol: "socks5", Users: []User{{Username: "user", Password: "pass"}}}, nil)
	target, _ := echoUDP(t)
	u, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	c := dialPeer(t, s, nil)
	socksGreeting(t, c, true, "pass")
	port := u.LocalAddr().(*net.UDPAddr).Port
	writeAll(c, peerHeader("socks5", 3, Address{"127.0.0.1", uint16(port)}))
	a := peerResponse(t, c, "socks5")
	relay, e := net.ResolveUDPAddr("udp", a.String())
	if e != nil {
		t.Fatal(e)
	}
	socksUDPSend(t, u, relay, target, []byte("authenticated-udp"), 0)
	if string(socksUDPRead(t, u)) != "authenticated-udp" {
		t.Fatal("auth UDP failed")
	}
	c.Close()
	waitFor(t, func() bool { return s.Stats().UDP == 0 })
}
func TestUDPTargetLimit(t *testing.T) {
	s := startTest(t, inFor("socks5", nil), func(c *Config) { c.Limits.UDPTargets = 1 })
	a, _ := echoUDP(t)
	b, _ := echoUDP(t)
	_, u, relay := socksAssociate(t, s, 0)
	socksUDPSend(t, u, relay, a, []byte("allowed"), 0)
	if string(socksUDPRead(t, u)) != "allowed" {
		t.Fatal("first target")
	}
	socksUDPSend(t, u, relay, b, []byte("over-limit"), 0)
	u.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	buf := make([]byte, 128)
	if _, _, e := u.ReadFromUDP(buf); e == nil {
		t.Fatal("target limit ignored")
	}
	if s.Stats().Dropped == 0 {
		t.Fatal("target drop missing")
	}
}
func TestTotalConnectionsAndRelayCancel(t *testing.T) {
	s := startTest(t, inFor("socks5", nil), func(c *Config) { c.Limits.Connections = 1; c.Limits.Handshakes = 4 })
	target := echoTCP(t)
	c := dialPeer(t, s, nil)
	socksGreeting(t, c, false, "")
	writeAll(c, peerHeader("socks5", 1, target))
	peerResponse(t, c, "socks5")
	c2, e := net.Dial("tcp", s.Addresses()[0].String())
	if e != nil {
		t.Fatal(e)
	}
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e = c2.Read(b[:]); e == nil {
		t.Fatal("total limit ignored")
	}
	c.Close()
	waitFor(t, func() bool { return s.Stats().Active == 0 })
	a, bConn := net.Pipe()
	defer a.Close()
	defer bConn.Close()
	d, eConn := net.Pipe()
	defer d.Close()
	defer eConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.relay(ctx, a, d) }()
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancel not reported")
		}
	case <-time.After(time.Second):
		t.Fatal("relay cancel leaked")
	}
}
func TestFailedAuthenticationNeverDials(t *testing.T) {
	cert, pool := testCert(t)
	var accepted atomic.Int64
	target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) { accepted.Add(1) })
	s := startTest(t, inFor("trojan", cert), nil)
	c := dialPeer(t, s, pool)
	h := peerHeader("trojan", 1, target)
	h[1] ^= 1
	writeAll(c, append(h, []byte("secret")...))
	io.ReadAll(c)
	c.Close()
	waitFor(t, func() bool { return s.Stats().Active == 0 })
	if accepted.Load() != 0 {
		t.Fatal("unauthenticated dial occurred")
	}
}
func TestTLSVersions(t *testing.T) {
	cert, pool := testCert(t)
	s := startTest(t, inFor("trojan", cert), nil)
	target := echoTCP(t)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.Addresses()[0].String(), &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: version, MaxVersion: version})
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		writeAll(c, append(peerHeader("trojan", 1, target), []byte("tls")...))
		b, e := readN(c, 3)
		c.Close()
		if e != nil || string(b) != "tls" {
			t.Fatal("TLS version failed", version, e)
		}
	}
}
func TestDatagramTypeEnumerations(t *testing.T) {
	for _, raw := range [][]byte{{2}, {1, 127}, {3, 0}, {4, 1, 2}} {
		if _, e := readAddress(bytes.NewReader(raw), false); e == nil {
			t.Fatal("bad address accepted")
		}
	}
}
