package kernel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type dnsFixture struct {
	udp      *net.UDPConn
	tcp      net.Listener
	count    atomic.Int64
	tcpCount atomic.Int64
	wg       sync.WaitGroup
	fn       func([]byte) []byte
}

func dnsReply(w []byte, ips []string, ttl uint32) []byte {
	var m dnsmessage.Message
	if m.Unpack(w) != nil {
		return nil
	}
	m.Response = true
	m.RecursionAvailable = true
	m.Answers = nil
	if len(m.Questions) != 1 {
		return nil
	}
	q := m.Questions[0]
	for _, str := range ips {
		ip := netip.MustParseAddr(str)
		h := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: ttl}
		if ip.Is4() && q.Type == dnsmessage.TypeA {
			h.Type = dnsmessage.TypeA
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: ip.As4()}})
		}
		if ip.Is6() && q.Type == dnsmessage.TypeAAAA {
			h.Type = dnsmessage.TypeAAAA
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: ip.As16()}})
		}
	}
	b, _ := m.Pack()
	return b
}
func newDNSFixture(t *testing.T, fn func([]byte) []byte) *dnsFixture {
	t.Helper()
	var ln net.Listener
	var u *net.UDPConn
	var e error
	// TCP port 0 does not reserve the matching UDP port. An unrelated UDP
	// socket may already use it; choose another pair only for EADDRINUSE.
	for attempt := 0; attempt < 16; attempt++ {
		ln, e = net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		u, e = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ln.Addr().(*net.TCPAddr).Port})
		if e == nil {
			break
		}
		ln.Close()
		if !errors.Is(e, syscall.EADDRINUSE) {
			t.Fatal(e)
		}
	}
	if e != nil {
		t.Fatal(e)
	}
	f := &dnsFixture{udp: u, tcp: ln, fn: fn}
	f.wg.Add(2)
	go func() {
		defer f.wg.Done()
		b := make([]byte, 65536)
		for {
			n, peer, e := u.ReadFromUDP(b)
			if e != nil {
				return
			}
			f.count.Add(1)
			r := fn(bytes.Clone(b[:n]))
			if r != nil {
				u.WriteToUDP(r, peer)
			}
		}
	}()
	go func() {
		defer f.wg.Done()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			f.wg.Add(1)
			go func(c net.Conn) {
				defer f.wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				var sz [2]byte
				if _, e := io.ReadFull(c, sz[:]); e != nil {
					return
				}
				b := make([]byte, binary.BigEndian.Uint16(sz[:]))
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				f.count.Add(1)
				f.tcpCount.Add(1)
				r := fn(b)
				if r == nil {
					return
				}
				writeAll(c, append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
			}(c)
		}
	}()
	t.Cleanup(func() { u.Close(); ln.Close(); f.wg.Wait() })
	return f
}
func (f *dnsFixture) address() string { return f.tcp.Addr().String() }
func lookupDNS(t *testing.T, r *internalDNS, name string) ([]netip.Addr, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	return r.lookup(ctx, name)
}
func configuredDNS(t *testing.T, server string, cache int) *internalDNS {
	t.Helper()
	r, e := newInternalDNS(&DNSOptions{Server: server, CacheEntries: &cache})
	if e != nil {
		t.Fatal(e)
	}
	r.bootstrap = func(context.Context, string, string) ([]netip.Addr, error) { return nil, errDNS }
	t.Cleanup(r.close)
	return r
}

func TestDNSRoutingStrictSchema(t *testing.T) {
	base := `{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}]}`
	good := []string{``, `,"dns":{}`, `,"dns":{"server":"system","cache_entries":0}`, `,"dns":{"server":"8.8.8.8"}`, `,"dns":{"server":"dns.google:53"}`, `,"dns":{"server":"tcp://dns.google:53"}`, `,"dns":{"server":"udp://[::1]:53"}`, `,"dns":{"server":"https://dns.google/dns-query"}`}
	bad := []string{`,"dns":null`, `,"routing":null`, `,"routing":{"rules":[]}`, `,"outbounds":[]`, `,"groups":[]`, `,"providers":[]`, `,"rule_sets":[]`, `,"geoip":{}`, `,"geosite":{}`, `,"asn":{}`, `,"dns":[]`, `,"dns":{"server":""}`, `,"dns":{"server":null}`, `,"dns":{"server":"system","cache_entries":1}`, `,"dns":{"cache_entries":null}`, `,"dns":{"cache_entries":1.5}`, `,"dns":{"cache_entries":4097}`, `,"dns":{"server":"udp://a:0"}`, `,"dns":{"server":"tls://dns.google"}`, `,"dns":{"server":"udp://a/path"}`, `,"dns":{"server":"https://user@host/query"}`, `,"dns":{"server":"https://host"}`, `,"dns":{"server":"https://host/query?x=y"}`, `,"dns":{"unknown":1}`}
	for _, tc := range append(good, bad...) {
		p := filepath.Join(t.TempDir(), "c.json")
		s := strings.TrimSuffix(base, "}") + tc + "}"
		if e := os.WriteFile(p, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
		_, e := Load(p)
		valid := false
		for _, g := range good {
			if tc == g {
				valid = true
			}
		}
		if valid != (e == nil) {
			t.Fatalf("schema input %s valid=%v err=%v", tc, valid, e)
		}
	}
	for _, s := range []string{"[::1]:53", "::1", "https://[::1]/dns-query"} {
		if _, e := parseDNS(s); e != nil {
			t.Fatal(s, e)
		}
	}
}

func TestDNSRoutingTransportsBootstrapCache(t *testing.T) {
	f := newDNSFixture(t, func(b []byte) []byte { return dnsReply(b, []string{"127.0.0.1", "::1"}, 2) })
	for _, scheme := range []string{"udp://", "tcp://", ""} {
		t.Run(scheme, func(t *testing.T) {
			r := configuredDNS(t, scheme+f.address(), 2)
			var clock atomic.Int64
			clock.Store(time.Now().UnixNano())
			r.now = func() time.Time { return time.Unix(0, clock.Load()) }
			a, e := lookupDNS(t, r, "Target.Example.")
			if e != nil || len(a) != 2 {
				t.Fatal(a, e)
			}
			before := f.count.Load()
			if _, e = lookupDNS(t, r, "target.example"); e != nil || f.count.Load() != before {
				t.Fatal("cache miss", e)
			}
			clock.Add(int64(2 * time.Second))
			if _, e = lookupDNS(t, r, "target.example"); e != nil || f.count.Load() != before+2 {
				t.Fatal("TTL not expired", e)
			}
			lookupDNS(t, r, "two.example")
			lookupDNS(t, r, "three.example")
			r.mu.Lock()
			n := len(r.cache)
			r.mu.Unlock()
			if n != 2 {
				t.Fatal("cache capacity", n)
			}
		})
	}
	r := configuredDNS(t, "localhost:"+strings.Split(f.address(), ":")[1], 0)
	var bootstrap atomic.Int64
	r.bootstrap = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if host != "localhost" {
			t.Errorf("business DNS leaked to system: %s", host)
		}
		bootstrap.Add(1)
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, e := lookupDNS(t, r, "business.example"); e != nil || bootstrap.Load() != 2 {
		t.Fatal("domain upstream bootstrap", e, bootstrap.Load())
	}
	system, _ := newInternalDNS(&DNSOptions{Server: "system"})
	if system.capacity != 0 {
		t.Fatal("system cache changed")
	}
	t.Logf("isolated upstream queries=%d tcp=%d; no public DNS", f.count.Load(), f.tcpCount.Load())
}

func TestDNSRoutingWireValidationAndTC(t *testing.T) {
	var tc atomic.Bool
	f := newDNSFixture(t, func(w []byte) []byte {
		r := dnsReply(w, []string{"127.0.0.1"}, 5)
		var question dnsmessage.Message
		question.Unpack(w)
		if question.Questions[0].Type == dnsmessage.TypeA && tc.CompareAndSwap(false, true) {
			r[2] |= 2
			return r[:len(r)-3]
		}
		return r
	})
	r := configuredDNS(t, f.address(), 0)
	if _, e := lookupDNS(t, r, "tc.example"); e != nil || f.tcpCount.Load() == 0 {
		t.Fatal("TC TCP fallback", e, f.tcpCount.Load())
	}
	for _, mode := range []string{"id", "question", "rcode", "truncated", "length", "qtype", "cname-loop"} {
		t.Run(mode, func(t *testing.T) {
			g := newDNSFixture(t, func(w []byte) []byte {
				b := dnsReply(w, []string{"127.0.0.1"}, 5)
				var m dnsmessage.Message
				m.Unpack(b)
				switch mode {
				case "id":
					m.ID++
				case "question":
					m.Questions[0].Name, _ = dnsmessage.NewName("other.example.")
				case "rcode":
					m.RCode = dnsmessage.RCodeServerFailure
				case "truncated":
					return b[:10]
				case "length":
					return make([]byte, 65536)
				case "qtype":
					m.Questions[0].Type = dnsmessage.TypeMX
				case "cname-loop":
					q := m.Questions[0]
					m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeCNAME, TTL: 50}, Body: &dnsmessage.CNAMEResource{CNAME: q.Name}}}
				}
				b, _ = m.Pack()
				return b
			})
			d := configuredDNS(t, g.address(), 1)
			if _, e := lookupDNS(t, d, "invalid.example"); e == nil {
				t.Fatal("invalid answer accepted")
			}
			if len(d.cache) != 0 {
				t.Fatal("bad answer cached")
			}
		})
	}
}

func TestDNSRoutingDoHCertificateAndErrors(t *testing.T) {
	var mode atomic.Int32
	var requests atomic.Int64
	h := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/dns-message" {
			t.Error("invalid DoH request")
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
		switch mode.Load() {
		case 1:
			http.Redirect(w, r, "https://public.invalid/query", 302)
			return
		case 2:
			w.WriteHeader(503)
			return
		case 3:
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("bad"))
			return
		case 4:
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(make([]byte, 65536))
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(dnsReply(b, []string{"127.0.0.1"}, 10))
	}))
	defer h.Close()
	r := configuredDNS(t, h.URL+"/dns-query", 0)
	if _, e := lookupDNS(t, r, "doh.example"); e == nil {
		t.Fatal("untrusted cert accepted")
	}
	roots := x509.NewCertPool()
	roots.AddCert(h.Certificate())
	// Fresh resolver: never mutate a Transport while a canceled sibling TLS dial may still run.
	r = configuredDNS(t, h.URL+"/dns-query", 0)
	r.upstreams[0].transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if _, e := lookupDNS(t, r, "doh.example"); e != nil {
		t.Fatal("trusted DoH failed", e)
	}
	r.upstreams[0].transport.CloseIdleConnections()
	// Fresh resolver: never mutate a Transport while a canceled sibling TLS dial may still run.
	r = configuredDNS(t, h.URL+"/dns-query", 0)
	r.upstreams[0].transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: "wrong.example", MinVersion: tls.VersionTLS12}
	if _, e := lookupDNS(t, r, "doh.example"); e == nil {
		t.Fatal("hostname check bypassed")
	}
	r.upstreams[0].transport.CloseIdleConnections()
	// Fresh resolver: never mutate a Transport while a canceled sibling TLS dial may still run.
	r = configuredDNS(t, h.URL+"/dns-query", 0)
	r.upstreams[0].transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	for i := int32(1); i <= 4; i++ {
		mode.Store(i)
		if _, e := lookupDNS(t, r, "doh.example"); e == nil {
			t.Fatal("invalid DoH accepted", i)
		}
	}
	t.Logf("local TLS/DoH requests=%d; untrusted/name mismatch rejected", requests.Load())
}

func TestDNSRoutingConcurrentCancelAndPartialCache(t *testing.T) {
	f := newDNSFixture(t, func(w []byte) []byte {
		var m dnsmessage.Message
		m.Unpack(w)
		b := dnsReply(w, []string{"127.0.0.1"}, 30)
		if m.Questions[0].Type == dnsmessage.TypeAAAA {
			return nil
		}
		return b
	})
	r := configuredDNS(t, f.address(), 4)
	if a, e := lookupDNS(t, r, "partial.example"); e != nil || len(a) != 1 {
		t.Fatal("partial answer lost", a, e)
	}
	if len(r.cache) != 0 {
		t.Fatal("partial success cached as complete")
	}
	// Hold all 64 slots: cancellation must not spawn additional query workers.
	for i := 0; i < 64; i++ {
		r.slots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := r.lookup(ctx, "cancel.example"); !errors.Is(e, context.Canceled) {
		t.Fatal("slot cancellation", e)
	}
	for i := 0; i < 64; i++ {
		<-r.slots
	}
	ctx, cancel = context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := r.lookup(ctx, "cancel.example"); done <- e }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancellation ignored")
		}
	case <-time.After(time.Second):
		t.Fatal("query workers did not join")
	}
	good := newDNSFixture(t, func(w []byte) []byte { return dnsReply(w, []string{"127.0.0.1"}, 0) })
	r = configuredDNS(t, good.address(), 4)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := lookupDNS(t, r, "concurrent.example"); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if len(r.cache) != 0 || len(r.slots) != 0 {
		t.Fatal("zero TTL cached or slots leaked")
	}
}

func TestDNSCustomLiteralTCPUDPAndSystemFallback(t *testing.T) {
	dns := newDNSFixture(t, func(w []byte) []byte { return dnsReply(w, []string{"127.0.0.1"}, 30) })
	target := echoTCP(t)
	u := localUDP(t)
	name := "custom-target.example"
	s := startTest(t, ssIn(), func(c *Config) {
		c.DNS = &DNSOptions{Server: dns.address()}
	})
	c, e := s.dial(context.Background(), Address{name, target.Port})
	if e != nil {
		t.Fatal("custom DNS TCP", e)
	}
	c.SetDeadline(time.Now().Add(time.Second))
	writeAll(c, []byte("direct"))
	b := make([]byte, 6)
	if _, e = io.ReadFull(c, b); e != nil || string(b) != "direct" {
		t.Fatal("literal TCP echo", e)
	}
	c.Close()
	endpoint, _ := net.ResolveUDPAddr("udp", s.Addresses()[0].String())
	client := localUDP(t)
	dst := Address{name, addrFromNet(u.LocalAddr()).Port}
	client.WriteToUDP(udp2022(t, dst, 901, 1, []byte("allowed")), endpoint)
	p, out := recvUDP(t, u)
	if string(p) != "allowed" {
		t.Fatal("custom DNS native UDP")
	}
	u.WriteToUDP([]byte("reply"), out)
	w, _ := recvUDP(t, client)
	idleCheckResponse(t, true, w, "reply")
	broken := newDNSFixture(t, func(w []byte) []byte { return nil })
	r := configuredDNS(t, broken.address(), 0)
	var system atomic.Int64
	r.bootstrap = func(context.Context, string, string) ([]netip.Addr, error) {
		system.Add(1)
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, e := lookupDNS(t, r, "localhost"); e != nil || system.Load() != 1 {
		t.Fatal("custom failure did not use system exactly once", e, system.Load())
	}
}

func TestDNSRoutingPartialFamilyRealTCPUDP(t *testing.T) {
	for _, failure := range []string{"A-error", "AAAA-error", "AAAA-timeout"} {
		t.Run(failure, func(t *testing.T) {
			v6 := failure == "A-error"
			ip := "127.0.0.1"
			network := "tcp4"
			host := "127.0.0.1:0"
			if v6 {
				ip = "::1"
				network = "tcp6"
				host = "[::1]:0"
				p, e := net.Listen("tcp6", host)
				if e != nil {
					t.Skipf("IPv6 unavailable %v", e)
				}
				p.Close()
			}
			f := newDNSFixture(t, func(w []byte) []byte {
				var m dnsmessage.Message
				m.Unpack(w)
				typ := m.Questions[0].Type
				if failure == "AAAA-timeout" && typ == dnsmessage.TypeAAAA {
					return nil
				}
				b := dnsReply(w, []string{ip}, 10)
				if failure == "A-error" && typ == dnsmessage.TypeA || failure == "AAAA-error" && typ == dnsmessage.TypeAAAA {
					b[3] = b[3]&0xf0 | 2
				}
				return b
			})
			target := sinkTCP(t, network, host, func(c net.Conn) { io.Copy(c, c) })
			udpNet := "udp4"
			local := net.IPv4(127, 0, 0, 1)
			if v6 {
				udpNet = "udp6"
				local = net.IPv6loopback
			}
			u, e := net.ListenUDP(udpNet, &net.UDPAddr{IP: local})
			if e != nil {
				t.Fatal(e)
			}
			defer u.Close()
			s := startTest(t, ssIn(), func(c *Config) {
				c.DNS = &DNSOptions{Server: f.address()}
				c.Limits.DialTimeout = Duration(400 * time.Millisecond)
			})
			c, e := s.dial(context.Background(), Address{"partial.example", target.Port})
			if e != nil {
				t.Fatal("partial family TCP lost", e)
			}
			c.SetDeadline(time.Now().Add(time.Second))
			writeAll(c, []byte("ok"))
			b := make([]byte, 2)
			if _, e = io.ReadFull(c, b); e != nil {
				t.Fatal(e)
			}
			c.Close()
			client := localUDP(t)
			endpoint, _ := net.ResolveUDPAddr("udp", s.Addresses()[0].String())
			client.WriteToUDP(udp2022(t, Address{"partial.example", addrFromNet(u.LocalAddr()).Port}, 930, 1, []byte("udp")), endpoint)
			p, out := recvUDP(t, u)
			if string(p) != "udp" {
				t.Fatal("partial family UDP lost")
			}
			u.WriteToUDP([]byte("ok"), out)
			recvUDP(t, client)
			if len(s.dns.cache) != 0 {
				t.Fatal("partial result cached")
			}
			t.Logf("%s actual TCP/UDP succeeded, DNS queries=%d", failure, f.count.Load())
		})
	}
}

func TestDNSRoutingRepresentativeAnyTLSSSTCPAndExplicitSystem(t *testing.T) {
	f := newDNSFixture(t, func(w []byte) []byte { return dnsReply(w, []string{"127.0.0.1"}, 30) })
	target := echoTCP(t)
	cert, roots := testCert(t)
	s := startTest(t, anyIn(cert), func(c *Config) { c.DNS = &DNSOptions{Server: f.address()} })
	c := atBegin(t, s, roots, 2)
	atOpen(t, c, 1, Address{"anytls.example", target.Port}, []byte("anytls"))
	if string(atPayload(t, c, 1, 6)) != "anytls" {
		t.Fatal("AnyTLS custom DNS")
	}
	c.Close()
	var accepts atomic.Int64
	ssTarget := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
		var b [7]byte
		if _, e := io.ReadFull(c, b[:]); e == nil && string(b[:]) == "initial" {
			accepts.Add(1)
		}
	})
	ss := startTest(t, ssIn(), func(c *Config) { c.DNS = &DNSOptions{Server: f.address()} })
	raw := dialPeer(t, ss, nil)
	writeAll(raw, tcp2022(t, Address{"ss.example", ssTarget.Port}, 33))
	waitFor(t, func() bool { return accepts.Load() == 1 })
	raw.Close()
	old := startTest(t, inFor("socks5", nil), nil)
	if old.dns.capacity != 0 {
		t.Fatal("explicit system fast path changed")
	}
	direct, e := old.dial(context.Background(), Address{"localhost", target.Port})
	if e != nil {
		t.Fatal("explicit system TCP", e)
	}
	direct.Close()
	if _, e = old.resolve(context.Background(), Address{"localhost", target.Port}); e != nil {
		t.Fatal("explicit system UDP resolution", e)
	}
}
