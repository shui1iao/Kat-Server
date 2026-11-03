package group

import (
	"context"
	"github.com/shui1iao/Kat/internal/outbound"
	"testing"
	"time"
)

func TestR11ClientLazyHasStartupAndTouchedPeriodicChecks(t *testing.T) {
	clk := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": 80 * time.Millisecond, "b": 20 * time.Millisecond})
	g := newAuto(t, Options{Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true, Interval: outbound.Duration(time.Second)}}, members(newFake("a"), newFake("b")), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	if g.Current() != "b" {
		t.Fatal("lazy client skipped startup")
	}
	clk.Advance(time.Second)
	if p.count("a") != 1 {
		t.Fatal("idle lazy did not skip tick")
	}
	g.mu.Lock()
	g.useLocked(clk.Now())
	g.unlock()
	waitRounds(t, g, 2)
	p.set("a", time.Millisecond, false)
	clk.Advance(900 * time.Millisecond)
	g.mu.Lock()
	g.useLocked(clk.Now())
	g.unlock()
	clk.Advance(100 * time.Millisecond)
	waitRounds(t, g, 3)
	if snapMember(g, "a").ProbeLatency != time.Millisecond || g.Current() != "b" {
		t.Fatal("touched lazy did not refresh sample or bypassed stable selection")
	}
}
func TestR11ClientSameURLLatestSampleSelectsAndDifferentURLIgnored(t *testing.T) {
	clk := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": 80 * time.Millisecond, "b": 100 * time.Millisecond})
	g := newAuto(t, Options{Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a"), newFake("b")), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	sample := ProbeSample{Name: "b", Latency: 20 * time.Millisecond, At: clk.Now().Add(time.Second)}
	g.RecordURLProbe("http://other.test/", sample)
	if g.Current() != "a" {
		t.Fatal("foreign URL used")
	}
	g.RecordURLProbe("http://probe.test/", sample)
	if snapMember(g, "b").ProbeLatency != 20*time.Millisecond || g.Current() != "a" {
		t.Fatal("same URL sample missing or single measurement bypassed gate")
	}
	g.RecordURLProbe("http://probe.test/", ProbeSample{Name: "b", Latency: 200 * time.Millisecond, At: clk.Now()})
	if snapMember(g, "b").ProbeLatency != 20*time.Millisecond || g.Current() != "a" {
		t.Fatal("stale sample replaced newest")
	}
}
func TestR11URLTestDefaultToleranceSameOnDesktopAndServer(t *testing.T) {
	for _, client := range []bool{false, true} {
		g := newAuto(t, Options{Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: client}}, members(newFake("a"), newFake("b")), newFakeClock(), nil, nil)
		want := 20 * time.Millisecond // Current URLTest default is identical on both runtimes
		if g.cfg.tolerance != want {
			t.Fatal(g.cfg.tolerance, want)
		}
	}
}
func TestR11NestedClientHealthEmptyFailedAndRecovery(t *testing.T) {
	clk := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond})
	inner := newAuto(t, Options{Name: "inner", Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a")), clk, p, nil)
	inner.Start(context.Background())
	waitRounds(t, inner, 1)
	empty, e := New(Options{Name: "empty", Type: TypeURLTest, IncludeAll: true, Probe: &ProbeOptions{URL: "http://probe.test/"}}, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	g := newAuto(t, Options{Type: TypeFallback, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, []outbound.Outbound{empty, inner, newFake("last")}, clk, newFakeProbe(map[string]time.Duration{"last": time.Millisecond}), nil)
	if g.Current() != "inner" {
		t.Fatal("empty considered healthy")
	}
	inner.RecordURLProbe("http://probe.test/", ProbeSample{Name: "a", At: clk.Now().Add(time.Second), Err: outbound.ErrRejected})
	if g.Current() != "last" {
		t.Fatal("failed inner group considered healthy")
	}
	inner.RecordURLProbe("http://probe.test/", ProbeSample{Name: "a", Latency: time.Millisecond, At: clk.Now().Add(2 * time.Second)})
	if g.Current() != "last" {
		t.Fatal("single nested recovery bypassed gate")
	}
}
