package group

import (
	"context"
	"github.com/shui1iao/Kat/internal/outbound"
	"net"
	"testing"
	"time"
)

func urlTestPair(t *testing.T) (*autoGroup, *fakeClock, *fakeOut, *fakeOut) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 50 * ms_, "b": 60 * ms_})
	g := newAuto(t, Options{Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", Interval: outbound.Duration(10 * time.Hour), ClientHead: true}}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	if g.Current() != "a" {
		t.Fatalf("current %q", g.Current())
	}
	return g, clk, a, b
}
func dialPeer(t *testing.T, g *autoGroup, f *fakeOut) (net.Conn, net.Conn) {
	t.Helper()
	c, err := g.DialTCP(context.Background(), outbound.Addr{Host: "t.test", Port: 443})
	if err != nil || ownerOf(c) != f.name {
		t.Fatalf("dial: %v via %s", err, ownerOf(c))
	}
	return c, <-f.peers
}
