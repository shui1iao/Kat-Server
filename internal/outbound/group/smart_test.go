package group

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// long interval: no periodic rounds unless a test advances that far
var smartLong = &ProbeOptions{URL: "http://probe.test/", Interval: outbound.Duration(10 * time.Hour)}

func setEWMA(g *autoGroup, name string, d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, n := range g.cfg.members {
		if n == name {
			g.st[i].real.latency(d, g.clk.Now())
		}
	}
}

func near(a, b time.Duration) bool { return math.Abs(float64(a-b)) <= float64(time.Microsecond) }

func TestSmartColdStartOrder(t *testing.T) {
	clk := newFakeClock()
	a, b, c := newFake("a"), newFake("b"), newFake("c")
	p := newFakeProbe(map[string]time.Duration{"a": 300 * ms_, "b": 100 * ms_, "c": 200 * ms_})
	p.block = make(chan struct{})
	ev := &eventLog{}
	g := newAuto(t, Options{Type: TypeSmart}, members(a, b, c), clk, p, ev)
	g.Start(context.Background())
	if !isProbing(g) {
		t.Fatal("smart did not probe immediately on Start")
	}
	if g.Current() != "" || g.Snapshot().Current != "" {
		t.Fatal("cold Smart reported a zero-valued member as selected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if conn, err := g.DialTCP(ctx, outbound.Addr{Host: "x.test", Port: 443}); conn != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cold request did not wait within its own budget", conn, err)
	}
	if a.dialCount()+b.dialCount()+c.dialCount() != 0 {
		t.Fatal("cold timeout silently attempted an unmeasured member")
	}
	close(p.block)
	waitRounds(t, g, 1)
	if g.Current() != "b" || dial(t, g, "x.test") != "b" {
		t.Fatal("first full round did not select the best member without hysteresis", g.Current())
	}
	if sw := switches(ev); len(sw) != 1 || sw[0] != ">b" {
		t.Fatalf("first choice must come from unselected, not a fictitious a: %v", sw)
	}

	// A failed full first round cannot silently turn into configuration-order
	// business retries. A later partial success is not a new complete round.
	clk2 := newFakeClock()
	a2, b2, c2 := newFake("a"), newFake("b"), newFake("c")
	p2 := newFakeProbe(map[string]time.Duration{})
	g2 := newAuto(t, Options{Type: TypeSmart}, members(c2, a2, b2), clk2, p2, nil)
	for _, n := range []string{"a", "b", "c"} {
		p2.set(n, 0, true)
	}
	g2.Start(context.Background())
	waitRounds(t, g2, 1)
	clk2.Advance(time.Second)
	g2.RecordProbe("a", time.Millisecond, clk2.Now(), nil)
	if g2.Current() != "" || !g2.cold {
		t.Fatal("partial recovery after an all-down round bootstrapped Smart")
	}
	if a2.dialCount()+b2.dialCount()+c2.dialCount() != 0 {
		t.Fatal("failed first round issued business traffic")
	}
}

func TestSmartPriorityChangesChoice(t *testing.T) {
	for _, tc := range []struct {
		prio map[string]float64
		want string
	}{
		{nil, "a"},
		{map[string]float64{"b": 0.5}, "b"},  // 120*0.5 = 60 < 100
		{map[string]float64{"a": 2}, "b"},    // 200 > 120
		{map[string]float64{"b": 1.5}, "a"},  // 180 > 100
		{map[string]float64{"a": 0.01}, "a"}, // tiny factor keeps a
	} {
		clk := newFakeClock()
		a, b := newFake("a"), newFake("b")
		p := newFakeProbe(map[string]time.Duration{"a": 100 * ms_, "b": 120 * ms_})
		g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong, Priority: tc.prio}, members(a, b), clk, p, nil)
		g.Start(context.Background())
		waitRounds(t, g, 1)
		if g.Current() != tc.want || dial(t, g, "x.test") != tc.want {
			t.Fatalf("priority %v: current %q, want %q", tc.prio, g.Current(), tc.want)
		}
	}
}

func TestSmartCurrentFailureSwitchesImmediately(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 100 * ms_, "b": 1000 * ms_})
	ev := &eventLog{}
	g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong}, members(a, b), clk, p, ev)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	a.setErr(&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED})
	// no dwell, and a (100+300) would still score better than b (1000)
	if got := dial(t, g, "x.test"); got != "b" {
		t.Fatalf("retry via %q", got)
	}
	if g.Current() != "b" {
		t.Fatalf("current %q after current failed", g.Current())
	}
	if sw := switches(ev); len(sw) != 2 || sw[0] != ">a" || sw[1] != "a>b" {
		t.Fatalf("switches %v", sw)
	}
}

func TestSiteCacheBoundedLRU(t *testing.T) {
	c := newSiteCache(smartSiteCap)
	defer c.clear()
	now := time.Now()
	for i := 0; i < smartSiteCap+100; i++ {
		c.record(fmt.Sprintf("s%d.test", i), 0, true, now, 0)
	}
	if c.len() != smartSiteCap {
		t.Fatalf("len = %d, want %d", c.len(), smartSiteCap)
	}
	if c.get("s0.test", now) != nil || c.get(fmt.Sprintf("s%d.test", smartSiteCap+99), now) == nil {
		t.Fatal("LRU eviction order wrong")
	}
	if c.get(fmt.Sprintf("s%d.test", smartSiteCap+99), now.Add(time.Hour)) != nil {
		t.Fatal("entry not expired after 1h")
	}
}

// smartPair builds a started smart group whose current member is a.
func smartPair(t *testing.T) (*autoGroup, *fakeClock, *fakeOut, *fakeOut) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 50 * ms_, "b": 60 * ms_})
	g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	if g.Current() != "a" {
		t.Fatalf("current %q", g.Current())
	}
	return g, clk, a, b
}

func TestSmartPausesProbingWhenIdle(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 50 * ms_, "b": 60 * ms_})
	g := newAuto(t, Options{Type: TypeSmart}, members(a, b), clk, p, nil) // interval default 5m
	g.Start(context.Background())
	waitRounds(t, g, 1)
	for k := int64(2); k <= 5; k++ { // t = 5m..20m
		clk.Advance(5 * time.Minute)
		waitRounds(t, g, k)
	}
	clk.Advance(5 * time.Minute) // t = 25m: unused for 5 intervals -> pause
	clk.Advance(2 * time.Hour)
	time.Sleep(20 * ms_)
	if n := g.roundsRun.Load(); n != 5 || isProbing(g) || clk.pending() != 0 {
		t.Fatalf("idle group kept probing: rounds %d probing %v timers %d", n, isProbing(g), clk.pending())
	}
	if p.count("a") != 5 {
		t.Fatalf("probe calls %d", p.count("a"))
	}
	dial(t, g, "x.test") // use resumes probing at once
	waitRounds(t, g, 6)
	clk.Advance(5 * time.Minute)
	waitRounds(t, g, 7)
}
