package kernel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func chainDNS(t *testing.T, servers ...string) *internalDNS {
	t.Helper()
	r, e := newInternalDNS(&DNSOptions{Servers: servers})
	if e != nil {
		t.Fatal(e)
	}
	r.bootstrap = func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("unexpected system DNS")
		return nil, errDNS
	}
	t.Cleanup(r.close)
	return r
}

func TestDNSChainSchemaAndDefaults(t *testing.T) {
	for _, o := range []*DNSOptions{nil, {}, {CacheEntries: new(int)}} {
		r, e := newInternalDNS(o)
		if e != nil {
			t.Fatal(e)
		}
		got := []dnsEndpoint{}
		for _, u := range r.upstreams {
			got = append(got, u.ep)
		}
		want := []dnsEndpoint{{scheme: "udp", host: "8.8.8.8", port: "53"}, {scheme: "udp", host: "1.1.1.1", port: "53"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("default %v", got)
		}
		if o == nil || o.CacheEntries == nil {
			if r.capacity != 256 {
				t.Fatal(r.capacity)
			}
		}
		r.close()
	}
	good := []string{`{}`, `{"cache_entries":4096}`, `{"server":"system"}`, `{"server":"system","cache_entries":0}`, `{"server":"127.0.0.1:53"}`, `{"servers":["tcp://127.0.0.1:53","udp://[::1]:53","https://dns.google/dns-query"]}`, `{"servers":["1.1.1.1","1.1.1.1"]}`}
	bad := []string{`null`, `{"servers":[]}`, `{"servers":null}`, `{"servers":[null]}`, `{"servers":[""]}`, `{"servers":["system"]}`, `{"servers":["udp://:53"]}`, `{"servers":["tls://x"]}`, `{"server":"system","servers":["1.1.1.1"]}`, `{"server":"","servers":["1.1.1.1"]}`, `{"servers":["1.1.1.1"],"unknown":true}`, `{"server":"system","cache_entries":1}`, `{"cache_entries":4097}`, `{"cache_entries":-1}`}
	for _, group := range []struct {
		xs    []string
		valid bool
	}{{good, true}, {bad, false}} {
		for _, b := range group.xs {
			var o DNSOptions
			e := json.Unmarshal([]byte(b), &o)
			if e == nil {
				_, e = newInternalDNS(&o)
			}
			if (e == nil) != group.valid {
				t.Fatalf("%s: %v", b, e)
			}
		}
	}
	sixteen := make([]string, 16)
	for i := range sixteen {
		sixteen[i] = "1.1.1.1"
	}
	if _, e := newInternalDNS(&DNSOptions{Servers: sixteen}); e != nil {
		t.Fatal(e)
	}
	if _, e := newInternalDNS(&DNSOptions{Servers: append(sixteen, "1.1.1.1")}); e == nil {
		t.Fatal("17 allowed")
	}
	if _, e := newInternalDNS(&DNSOptions{Servers: []string{}}); e == nil {
		t.Fatal("empty Go list allowed")
	}
	r := configuredDNS(t, "system", 0)
	var calls int
	r.bootstrap = func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	for i := 0; i < 2; i++ {
		if _, e := lookupDNS(t, r, "system.example"); e != nil {
			t.Fatal(e)
		}
	}
	if calls != 2 || len(r.cache) != 0 || len(r.upstreams) != 0 {
		t.Fatal("explicit system cached or chained")
	}
}

func familyReply(w []byte, mode string) []byte {
	b := dnsReply(w, nil, 30)
	var m dnsmessage.Message
	_ = m.Unpack(b)
	switch mode {
	case "ip":
		return dnsReply(w, []string{"127.0.0.1", "::1"}, 30)
	case "timeout":
		return nil
	case "nx":
		m.RCode = dnsmessage.RCodeNameError
	case "fail":
		m.RCode = dnsmessage.RCodeServerFailure
	case "bad-id":
		m.RCode = dnsmessage.RCodeNameError
		m.ID++
	case "bad-question":
		m.RCode = dnsmessage.RCodeNameError
		m.Questions[0].Name, _ = dnsmessage.NewName("wrong.example.")
	case "bad-response":
		m.RCode = dnsmessage.RCodeNameError
		m.Response = false
	case "bad-opcode":
		m.RCode = dnsmessage.RCodeNameError
		m.OpCode = 1
	case "bad-body":
		m.RCode = dnsmessage.RCodeNameError
		b, _ = m.Pack()
		b[7] = 1
		return b
	case "bad-cname":
		m.RCode = dnsmessage.RCodeNameError
		q := m.Questions[0]
		m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: q.Name}}}
	}
	b, _ = m.Pack()
	return b
}

func TestDNSChainOrderNegativeAndFamilyCombinations(t *testing.T) {
	cases := []struct {
		a, aaaa              string
		next, success, cache bool
	}{
		{"ip", "empty", false, true, true}, {"ip", "fail", false, true, false}, {"fail", "ip", false, true, false},
		{"ip", "timeout", false, true, false}, {"ip", "nx", false, true, false},
		{"nx", "fail", false, false, false}, {"fail", "nx", false, false, false}, {"nx", "empty", false, false, false},
		{"empty", "empty", false, false, false}, {"empty", "fail", true, true, true}, {"fail", "empty", true, true, true},
		{"fail", "fail", true, true, true}, {"timeout", "empty", true, true, true},
		{"bad-id", "fail", true, true, true}, {"bad-question", "fail", true, true, true}, {"bad-response", "fail", true, true, true},
		{"bad-opcode", "fail", true, true, true}, {"bad-body", "fail", true, true, true}, {"bad-cname", "fail", true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.a+"/"+tc.aaaa, func(t *testing.T) {
			first := newDNSFixture(t, func(w []byte) []byte {
				var m dnsmessage.Message
				_ = m.Unpack(w)
				mode := tc.a
				if m.Questions[0].Type == dnsmessage.TypeAAAA {
					mode = tc.aaaa
				}
				return familyReply(w, mode)
			})
			second := newDNSFixture(t, func(w []byte) []byte {
				if first.count.Load() != 2 {
					t.Error("second started before first joined")
				}
				return dnsReply(w, []string{"127.0.0.2"}, 900)
			})
			r := chainDNS(t, first.address(), second.address())
			ips, e := lookupDNS(t, r, "family.example")
			if (e == nil) != tc.success || (second.count.Load() > 0) != tc.next {
				t.Fatalf("ips=%v err=%v first=%d second=%d", ips, e, first.count.Load(), second.count.Load())
			}
			if tc.success {
				want := "127.0.0.1"
				if tc.a != "ip" {
					want = "::1"
				}
				if tc.next {
					want = "127.0.0.2"
				}
				if ips[0].String() != want {
					t.Fatal("answers mixed", ips)
				}
			}
			if (len(r.cache) > 0) != tc.cache {
				t.Fatal("cache completeness", r.cache)
			}
			if tc.next {
				if r.cache["family.example"].expires.Sub(r.now()) > 300*time.Second {
					t.Fatal("TTL cap")
				}
			}
			if !tc.success {
				_, _ = lookupDNS(t, r, "family.example")
				if first.count.Load() != 4 {
					t.Fatal("negative cached")
				}
			}
		})
	}
}

func TestDNSChainSystemOnceAndNoCache(t *testing.T) {
	f := newDNSFixture(t, func(w []byte) []byte { return familyReply(w, "fail") })
	// Duplicates retain their place: do not silently sort or deduplicate.
	r := chainDNS(t, f.address(), f.address())
	var calls atomic.Int64
	r.bootstrap = func(ctx context.Context, n, h string) ([]netip.Addr, error) {
		if f.count.Load() != calls.Load()*4+4 {
			t.Error("system called early")
		}
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	for i := 0; i < 2; i++ {
		if _, e := lookupDNS(t, r, "fallback.example"); e != nil {
			t.Fatal(e)
		}
	}
	if calls.Load() != 2 || len(r.cache) != 0 {
		t.Fatal("fallback cached/repeated", calls.Load(), r.cache)
	}
	// The legacy server form also gets one final system call.
	single := configuredDNS(t, f.address(), 256)
	single.bootstrap = func(context.Context, string, string) ([]netip.Addr, error) { calls.Add(1); return nil, errDNS }
	if _, e := lookupDNS(t, single, "legacy.example"); e == nil || calls.Load() != 3 {
		t.Fatal("legacy fallback", e, calls.Load())
	}
}

func TestDNSChainBudgetAndCancellation(t *testing.T) {
	for _, n := range []int{1, 2, 16} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			servers := make([]string, n)
			for i := range servers {
				servers[i] = "udp://127.0.0.1:53"
			}
			r := chainDNS(t, servers...)
			var dials, system atomic.Int64
			r.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
				dials.Add(1)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			r.bootstrap = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
				system.Add(1)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, e := r.lookup(ctx, "budget.example")
			elapsed := time.Since(start)
			if e == nil || elapsed > 300*time.Millisecond || elapsed < 150*time.Millisecond || system.Load() != 1 || dials.Load() != int64(n*2) || ctx.Err() != nil {
				t.Fatalf("n=%d elapsed=%v dial=%d system=%d err=%v caller=%v", n, elapsed, dials.Load(), system.Load(), e, ctx.Err())
			}
			t.Logf("%d upstreams + system: %v of 400ms, caller still live", n, elapsed)
		})
	}
	r, _ := newInternalDNS(nil)
	t.Cleanup(r.close)
	var dials, system atomic.Int64
	entered := make(chan struct{}, 2)
	r.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		dials.Add(1)
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	r.bootstrap = func(context.Context, string, string) ([]netip.Addr, error) { system.Add(1); return nil, errDNS }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	done := make(chan error, 1)
	go func() { _, e := r.lookup(ctx, "cancel.example"); done <- e }()
	<-entered
	cancel()
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	before := dials.Load()
	_, e := r.lookup(ctx, "cancel.example")
	if !errors.Is(e, context.Canceled) || dials.Load() != before || system.Load() != 0 || len(r.slots) != 0 {
		t.Fatal("cancellation launched later work")
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	_, e = r.lookup(expired, "expired.example")
	if !errors.Is(e, context.DeadlineExceeded) || system.Load() != 0 {
		t.Fatal("expired fallback")
	}
}

// This starts a real SS inbound and forwards both TCP and native UDP while the
// instance-local dial seam intercepts the *unchanged* public default endpoints.
func TestDNSChainOmittedDefaultRealTCPUDP(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "omitted", true: "empty"}[empty], func(t *testing.T) {
			f := newDNSFixture(t, func(w []byte) []byte { return familyReply(w, "fail") })
			var accepted atomic.Int64
			target := sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
				b := make([]byte, 7)
				if _, e := io.ReadFull(c, b); e == nil && string(b) == "initial" {
					accepted.Add(1)
				}
			})
			udp := localUDP(t)
			s := startTest(t, ssIn(), func(c *Config) {
				c.DNS = nil
				if empty {
					c.DNS = &DNSOptions{}
				}
			})
			var mu sync.Mutex
			var stages []string
			s.dns.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if network != "udp" || addr != "8.8.8.8:53" && addr != "1.1.1.1:53" {
					t.Errorf("unexpected DNS I/O %s %s", network, addr)
					return nil, errDNS
				}
				mu.Lock()
				stages = append(stages, addr)
				mu.Unlock()
				return (&net.Dialer{}).DialContext(ctx, network, f.address())
			}
			s.dns.bootstrap = func(ctx context.Context, n, h string) ([]netip.Addr, error) {
				if h != "default.example" {
					t.Error(h)
				}
				mu.Lock()
				stages = append(stages, "system")
				mu.Unlock()
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			raw := dialPeer(t, s, nil)
			if e := writeAll(raw, tcp2022(t, Address{"default.example", target.Port}, 31)); e != nil {
				t.Fatal(e)
			}
			waitFor(t, func() bool { return accepted.Load() == 1 })
			raw.Close()
			client := localUDP(t)
			endpoint, _ := net.ResolveUDPAddr("udp", s.Addresses()[0].String())
			client.WriteToUDP(udp2022(t, Address{"default.example", addrFromNet(udp.LocalAddr()).Port}, 987, 1, []byte("default")), endpoint)
			b, peer := recvUDP(t, udp)
			if string(b) != "default" {
				t.Fatal(string(b))
			}
			udp.WriteToUDP([]byte("reply"), peer)
			b, _ = recvUDP(t, client)
			idleCheckResponse(t, true, b, "reply")
			mu.Lock()
			got := append([]string(nil), stages...)
			mu.Unlock()
			unit := []string{"8.8.8.8:53", "8.8.8.8:53", "1.1.1.1:53", "1.1.1.1:53", "system"}
			if !reflect.DeepEqual(got, append(append([]string{}, unit...), unit...)) || f.count.Load() != 8 {
				t.Fatal("default not wired", got, f.count.Load())
			}
			t.Logf("actual TCP initial payload + native UDP roundtrip; chain=%v", got)
		})
	}
}

func TestDNSChainReloadOrderAndInflight(t *testing.T) {
	first := newDNSFixture(t, func(w []byte) []byte { return familyReply(w, "fail") })
	second := newDNSFixture(t, func(w []byte) []byte { return dnsReply(w, []string{"127.0.0.1"}, 30) })
	zero := 0
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Servers: []string{first.address(), second.address()}, CacheEntries: &zero}
	next := c
	s := startReloadable(t, c, &next)
	listen := s.Addresses()[0].String()
	target := echoTCP(t)
	oldConn, ok := socksTo(t, listen, Address{"reload.example", target.Port})
	if !ok || !echoOnce(oldConn, "old") {
		t.Fatal("old connection")
	}
	defer oldConn.Close()
	old := s.current()
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	old.dns.dial = func(ctx context.Context, n, a string) (net.Conn, error) {
		if a == first.address() {
			entered <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return (&net.Dialer{}).DialContext(ctx, n, a)
	}
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, e := old.lookup(ctx, "inflight.example")
		done <- e
	}()
	<-entered
	<-entered
	next = socksCfg("127.0.0.1:0")
	next.DNS = &DNSOptions{Servers: []string{second.address(), first.address()}, CacheEntries: &zero}
	next.raw, _ = json.Marshal(next) // Match the raw snapshot supplied by Load.
	if _, e := s.Reload("dns-order"); e != nil {
		t.Fatal(e)
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal("old lookup lost", e)
	}
	if old == s.current() || !echoOnce(oldConn, "continued") {
		t.Fatal("old connection interrupted")
	}
	// Mutating loader input or returned snapshots must not mutate the new list.
	next.DNS.Servers[0] = "127.0.0.1:1"
	snap := s.CurrentConfig()
	snap.DNS.Servers[0] = "127.0.0.1:2"
	a, b := first.count.Load(), second.count.Load()
	fresh, ok := socksTo(t, listen, Address{"new.example", target.Port})
	if !ok || !echoOnce(fresh, "new") {
		t.Fatal("new list")
	}
	fresh.Close()
	if first.count.Load() != a || second.count.Load() != b+2 {
		t.Fatal("new order not visible")
	}
	current := s.current()
	next.DNS = &DNSOptions{Server: "system", Servers: []string{first.address()}}
	if _, e := s.Reload("invalid-dns"); e == nil || s.current() != current || !echoOnce(oldConn, "still-old") {
		t.Fatal("invalid reload touched generation")
	}
	// Provider-triggered rebuild re-decodes the raw ordered list, not mutated input.
	if _, e := s.reload("dns-rebuild", false); e != nil {
		t.Fatal(e)
	}
	if got := s.CurrentConfig().DNS.Servers; !reflect.DeepEqual(got, []string{second.address(), first.address()}) {
		t.Fatal("raw list alias", got)
	}
	oldConn.Close()
	waitFor(t, func() bool { return s.liveGens.Load() == 1 })
}

func TestDNSChainMultipleDoHPoolsClose(t *testing.T) {
	var open atomic.Int64
	makeServer := func(fail bool) *httptest.Server {
		h := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			if fail {
				w.WriteHeader(503)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(dnsReply(b, []string{"127.0.0.1"}, 10))
		}))
		h.Config.ConnState = func(c net.Conn, s http.ConnState) {
			if s == http.StateNew {
				open.Add(1)
			}
			if s == http.StateClosed {
				open.Add(-1)
			}
		}
		h.StartTLS()
		t.Cleanup(h.Close)
		return h
	}
	a, b := makeServer(true), makeServer(false)
	r := chainDNS(t, a.URL+"/dns-query", b.URL+"/dns-query")
	roots := x509.NewCertPool()
	roots.AddCert(a.Certificate())
	roots.AddCert(b.Certificate())
	for _, u := range r.upstreams {
		u.transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	if _, e := lookupDNS(t, r, "two-doh.example"); e != nil {
		t.Fatal(e)
	}
	r.close()
	waitFor(t, func() bool { return open.Load() == 0 })
}

func TestDNSChainWireAddressLimit(t *testing.T) {
	for _, mode := range []string{"positive", "negative"} {
		f := newDNSFixture(t, func(w []byte) []byte {
			ips := make([]string, 0, 34)
			for i := 0; i < 17; i++ {
				ips = append(ips, "127.0.0.1", "::1")
			}
			b := dnsReply(w, ips, 30)
			if mode == "negative" {
				b[3] = b[3]&0xf0 | 3
			}
			return b
		})
		r := configuredDNS(t, f.address(), 256)
		var system atomic.Int64
		r.bootstrap = func(context.Context, string, string) ([]netip.Addr, error) { system.Add(1); return nil, errDNS }
		if _, e := lookupDNS(t, r, strings.ToLower(mode)+".example"); e == nil || len(r.cache) != 0 || system.Load() != 1 {
			t.Fatal("malformed/oversized answer accepted as terminal", mode, e, system.Load())
		}
	}
}

func TestDNSChainDefaultPositiveCacheAndDisabled(t *testing.T) {
	f := newDNSFixture(t, func(w []byte) []byte { return dnsReply(w, []string{"127.0.0.1"}, 30) })
	for _, disabled := range []bool{false, true} {
		var o *DNSOptions
		if disabled {
			zero := 0
			o = &DNSOptions{CacheEntries: &zero}
		}
		r, e := newInternalDNS(o)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(r.close)
		var dials atomic.Int64
		r.dial = func(ctx context.Context, n, addr string) (net.Conn, error) {
			if addr != "8.8.8.8:53" {
				t.Errorf("continued after first success: %s", addr)
				return nil, errDNS
			}
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, n, f.address())
		}
		r.bootstrap = func(context.Context, string, string) ([]netip.Addr, error) {
			t.Error("unnecessary system fallback")
			return nil, errDNS
		}
		for i := 0; i < 2; i++ {
			if _, e := lookupDNS(t, r, "positive-default.example"); e != nil {
				t.Fatal(e)
			}
		}
		want := int64(2)
		if disabled {
			want = 4
		}
		if dials.Load() != want || (len(r.cache) > 0) == disabled {
			t.Fatal("positive/disabled cache", disabled, dials.Load(), r.cache)
		}
	}
}
