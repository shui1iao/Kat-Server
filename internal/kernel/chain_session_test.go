package kernel

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func chainFixture(t *testing.T, via string, nested bool) (*Server, *Server, *Server, outbound.Addr) {
	t.Helper()
	a := groupsStart(t, socksCfg("127.0.0.1:0"))
	b := groupsStart(t, socksCfg("127.0.0.1:0"))
	cert, _ := testCert(t)
	in := inFor("anytls", cert)
	in.AnyTLS = &AnyTLSOptions{Password: "test-password"}
	tail := startTest(t, in, nil)
	cfg := socksCfg("127.0.0.1:0")
	cfg.Outbounds = []OutboundConfig{
		{Name: "a", Type: "socks5", Server: "127.0.0.1", Port: uint16(a.Addresses()[0].(*net.TCPAddr).Port)},
		{Name: "b", Type: "socks5", Server: "127.0.0.1", Port: uint16(b.Addresses()[0].(*net.TCPAddr).Port)},
		{Name: "tail", Type: "anytls", Server: "127.0.0.1", Port: uint16(tail.Addresses()[0].(*net.TCPAddr).Port), Password: "test-password", TLS: &outbound.TLSOptions{CA: cert.Cert}, Via: via},
	}
	cfg.Groups = []GroupConfig{{Name: "g", Type: "select", Members: []string{"a", "b"}, Selected: "a"}}
	if nested {
		cfg.Groups = append(cfg.Groups, GroupConfig{Name: "h", Type: "select", Members: []string{"g"}})
	}
	s := groupsStart(t, cfg)
	return s, a, b, outbound.Addr{Host: "127.0.0.1", Port: rcEchoTCP(t)}
}

func chainRoundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	p := []byte("chain-old-and-new-stream")
	c.SetDeadline(time.Now().Add(time.Second))
	if _, e := c.Write(p); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(p))
	if _, e := io.ReadFull(c, got); e != nil {
		t.Fatal(e)
	}
	if string(got) != string(p) {
		t.Fatal("payload changed")
	}
}

func chainOpen(t *testing.T, ob outbound.Outbound, dst outbound.Addr) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, e := ob.DialTCP(ctx, dst)
	if e != nil {
		t.Fatal(e)
	}
	chainRoundTrip(t, c)
	return c
}

func TestChainAnyTLSSelectionAndOldStreams(t *testing.T) {
	for _, via := range []string{"g", "h"} {
		t.Run(via, func(t *testing.T) {
			s, a, b, dst := chainFixture(t, via, via == "h")
			ob := s.rt.nodes["tail"]
			old := chainOpen(t, ob, dst)
			defer old.Close()
			oldUDP, e := ob.ListenPacket(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer oldUDP.Close()
			udpDst := outbound.Addr{Host: "127.0.0.1", Port: rcEchoUDP(t)}
			if e = rcUDPEcho(oldUDP, udpDst); e != nil {
				t.Fatal(e)
			}
			idle := chainOpen(t, ob, dst)
			idle.Close()
			n := a.Stats().Accepted
			for range 3 {
				c := chainOpen(t, ob, dst)
				c.Close()
			}
			if a.Stats().Accepted != n {
				t.Fatal("stable front did not reuse idle session")
			}
			if e := s.Select("g", "b"); e != nil {
				t.Fatal(e)
			}
			fresh := chainOpen(t, ob, dst)
			defer fresh.Close()
			if b.Stats().Accepted == 0 {
				t.Fatal("new AnyTLS logical stream reused obsolete front a after selecting b")
			}
			chainRoundTrip(t, old)
			if e = rcUDPEcho(oldUDP, udpDst); e != nil {
				t.Fatal("old UDP was interrupted", e)
			}
			chainRoundTrip(t, fresh)
			old.Close()
			// Keep the new-front carrier busy, so the only idle candidate is
			// the just-released pre-switch carrier. It must be rejected too.
			before := b.Stats().Accepted
			afterOld := chainOpen(t, ob, dst)
			if b.Stats().Accepted <= before {
				t.Fatal("released old carrier accepted a new stream")
			}
			afterOld.Close()
			fresh.Close()
			n = b.Stats().Accepted
			again := chainOpen(t, ob, dst)
			again.Close()
			if b.Stats().Accepted != n {
				t.Fatal("new front did not retain efficient reuse")
			}
			udp, e := ob.ListenPacket(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer udp.Close()
			if e = rcUDPEcho(udp, outbound.Addr{Host: "127.0.0.1", Port: rcEchoUDP(t)}); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestChainStaticFrontReuseCancel(t *testing.T) {
	s, a, b, dst := chainFixture(t, "a", false)
	ob := s.rt.nodes["tail"]
	for range 5 {
		c := chainOpen(t, ob, dst)
		c.Close()
	}
	if a.Stats().Accepted != 1 || b.Stats().Accepted != 0 {
		t.Fatalf("static front transports: a=%d b=%d", a.Stats().Accepted, b.Stats().Accepted)
	}
	pc, err := ob.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = rcUDPEcho(pc, outbound.Addr{Host: "127.0.0.1", Port: rcEchoUDP(t)}); err != nil {
		t.Fatal(err)
	}
	pc.Close()
	if a.Stats().Accepted != 1 {
		t.Fatal("static UDP did not reuse carrier")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, e := ob.DialTCP(ctx, dst)
	if c != nil {
		c.Close()
	}
	if !errors.Is(e, context.Canceled) {
		t.Fatalf("canceled stream: %v", e)
	}
	if a.Stats().Accepted != 1 {
		t.Fatal("canceled stream dialed new transport")
	}
	c = chainOpen(t, ob, dst)
	c.Close()
	if a.Stats().Accepted != 1 {
		t.Fatal("already-canceled request destroyed a reusable carrier")
	}
	expired, done := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer done()
	c, e = ob.DialTCP(expired, dst)
	if c != nil {
		c.Close()
	}
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("expired stream: %v", e)
	}
	c = chainOpen(t, ob, dst)
	c.Close()
	if a.Stats().Accepted != 1 {
		t.Fatal("expired budget discarded a reusable carrier")
	}
}

func TestChainAnyTLSAutomaticFrontSwitch(t *testing.T) {
	for _, kind := range []string{"url-test", "fallback"} {
		t.Run(kind, func(t *testing.T) {
			s, a, b, dst := chainFixture(t, "g", false)
			// Real production automatic groups, with deterministic local health
			// evidence. The old live TCP/UDP carriers are never made unreachable.
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
			defer target.Close()
			gr, e := group.New(group.Options{Name: "auto", Type: kind, Fixed: "a", Members: []string{"a", "b"}, Probe: &group.ProbeOptions{URL: target.URL}}, []outbound.Outbound{member{s.rt.nodes["a"]}, member{s.rt.nodes["b"]}}, nil)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			gr.Start(ctx)
			defer gr.Close()
			tail, e := newProtocolOutbound(outbound.Options(s.cfg.Outbounds[2]), underlay{gr})
			if e != nil {
				t.Fatal(e)
			}
			defer tail.Close()
			old := chainOpen(t, tail, dst)
			defer old.Close()
			warm := chainOpen(t, tail, dst)
			warm.Close()
			before := b.Stats().Accepted
			now := time.Now()
			gr.(interface{ RecordProbeRound([]group.ProbeSample) }).RecordProbeRound([]group.ProbeSample{
				{Name: "a", At: now, Started: now, Err: errors.New("local controlled health change")},
				{Name: "b", At: now, Started: now, Latency: time.Millisecond},
			})
			if kind == "fallback" {
				if gr.Current() != "a" {
					t.Fatal("one failure round changed fallback")
				}
				later := now.Add(time.Millisecond)
				gr.(interface{ RecordProbeRound([]group.ProbeSample) }).RecordProbeRound([]group.ProbeSample{
					{Name: "a", At: later, Started: later, Err: errors.New("second independent health round")},
					{Name: "b", At: later, Started: later, Latency: time.Millisecond},
				})
			}
			waitFor(t, func() bool { return gr.Current() == "b" })
			fresh := chainOpen(t, tail, dst)
			defer fresh.Close()
			if b.Stats().Accepted <= before {
				t.Fatal("automatic front change reused old AnyTLS route")
			}
			chainRoundTrip(t, old)
			if a.Stats().Accepted == 0 {
				t.Fatal("old path was not established")
			}
		})
	}
}

func TestChainAnyTLSNestedCarrierRoute(t *testing.T) {
	s, a, b, dst := chainFixture(t, "g", false)
	opts := outbound.Options(s.cfg.Outbounds[2])
	opts.Name = "middle"
	opts.Via = "g"
	middle, e := newProtocolOutbound(opts, underlay{s.rt.nodes["g"]})
	if e != nil {
		t.Fatal(e)
	}
	defer middle.Close()
	opts.Name = "exit"
	opts.Via = "middle"
	exit, e := newProtocolOutbound(opts, underlay{middle})
	if e != nil {
		t.Fatal(e)
	}
	defer exit.Close()
	c := chainOpen(t, exit, dst)
	c.Close()
	n := a.Stats().Accepted
	c = chainOpen(t, exit, dst)
	c.Close()
	if a.Stats().Accepted != n {
		t.Fatal("nested stable carrier did not reuse")
	}
	if e = s.Select("g", "b"); e != nil {
		t.Fatal(e)
	}
	c = chainOpen(t, exit, dst)
	defer c.Close()
	if b.Stats().Accepted == 0 {
		t.Fatal("nested AnyTLS carrier lost actual front association")
	}
}

func TestChainAnyTLSNewUDPSelection(t *testing.T) {
	s, a, b, dst := chainFixture(t, "g", false)
	ob := s.rt.nodes["tail"]
	udpDst := outbound.Addr{Host: "127.0.0.1", Port: rcEchoUDP(t)}
	old, e := ob.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer old.Close()
	if e = rcUDPEcho(old, udpDst); e != nil {
		t.Fatal(e)
	}
	c := chainOpen(t, ob, dst)
	c.Close() // idle carrier on old front
	n := a.Stats().Accepted
	if e = s.Select("g", "b"); e != nil {
		t.Fatal(e)
	}
	fresh, e := ob.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	if e = rcUDPEcho(fresh, udpDst); e != nil {
		t.Fatal(e)
	}
	if b.Stats().Accepted == 0 || a.Stats().Accepted != n {
		t.Fatal("new UDP stream did not use the selected front")
	}
	if e = rcUDPEcho(old, udpDst); e != nil {
		t.Fatal("old UDP session interrupted", e)
	}
}

func TestChainAnyTLSPerConnectionFront(t *testing.T) {
	s, a, b, dst := chainFixture(t, "g", false)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	lazy := false
	gr, e := group.New(group.Options{Name: "rr", Type: "load-balance", Strategy: "round-robin", Lazy: &lazy, Probe: &group.ProbeOptions{URL: target.URL}, Members: []string{"a", "b"}}, []outbound.Outbound{member{s.rt.nodes["a"]}, member{s.rt.nodes["b"]}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gr.Start(ctx)
	defer gr.Close()
	waitFor(t, func() bool {
		snap := gr.(group.Snapshotter).Snapshot()
		return len(snap.Members) == 2 && snap.Members[0].Probed && snap.Members[1].Probed
	})
	beforeA, beforeB := a.Stats().Accepted, b.Stats().Accepted
	tail, e := newProtocolOutbound(outbound.Options(s.cfg.Outbounds[2]), underlay{gr})
	if e != nil {
		t.Fatal(e)
	}
	defer tail.Close()
	for range 2 {
		c := chainOpen(t, tail, dst)
		c.Close()
	}
	if a.Stats().Accepted-beforeA != 1 || b.Stats().Accepted-beforeB != 1 {
		t.Fatalf("new logical streams bypassed per-connection front selection a=%d b=%d", a.Stats().Accepted-beforeA, b.Stats().Accepted-beforeB)
	}
}

func TestChainReferencesFailClosed(t *testing.T) {
	for _, kind := range []string{"missing-via", "missing-member", "via-group-cycle", "five-hops"} {
		t.Run(kind, func(t *testing.T) {
			c := socksCfg("127.0.0.1:0")
			c.Outbounds = []OutboundConfig{{Name: "a", Type: "socks5", Server: "127.0.0.1", Port: 9}}
			switch kind {
			case "missing-via":
				c.Outbounds[0].Via = "missing"
			case "missing-member":
				c.Groups = []GroupConfig{{Name: "g", Type: "select", Members: []string{"missing"}}}
			case "via-group-cycle":
				c.Outbounds[0].Via = "g"
				c.Groups = []GroupConfig{{Name: "g", Type: "select", Members: []string{"a"}}}
			case "five-hops":
				for _, name := range []string{"b", "c", "d", "e"} {
					prev := c.Outbounds[len(c.Outbounds)-1].Name
					c.Outbounds = append(c.Outbounds, OutboundConfig{Name: name, Type: "socks5", Server: "127.0.0.1", Port: 9, Via: prev})
				}
			}
			if e := c.Validate(); e == nil {
				t.Fatal("invalid chain accepted")
			}
		})
	}
}
