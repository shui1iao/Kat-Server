package group

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"sync"
	"testing"
	"time"
)

func TestClientWeightedURLTest(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	g := newAuto(t, Options{Type: TypeURLTest, Priority: map[string]float64{"a": 4}}, members(a, b), clk, nil, nil)
	now := clk.Now()
	g.RecordProbeRound([]ProbeSample{{Name: "a", Latency: 100 * time.Millisecond, At: now}, {Name: "b", Latency: 200 * time.Millisecond, At: now}})
	if g.Current() != "b" {
		t.Fatal("weighted selection")
	}
	if s := snapMember(g, "a"); s.ProbeLatency != 100*time.Millisecond || s.Priority != 4 {
		t.Fatal("raw latency/priority")
	}
	// Same samples with weight one preserve old selection/tolerance.
	old := newAuto(t, Options{Type: TypeURLTest}, members(a, b), clk, nil, nil)
	old.RecordProbe("a", 100*time.Millisecond, now, nil)
	old.RecordProbe("b", 200*time.Millisecond, now, nil)
	if old.Current() != "a" {
		t.Fatal("old default changed")
	}
}

func TestClientSoftFixedFailoverTCPUDP(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeSmart} {
		t.Run(kind, func(t *testing.T) {
			clk := newFakeClock()
			a, b := newFake("a"), newFake("b")
			a.setErr(errors.New("unavailable"))
			a.lpErr = errors.New("unavailable")
			g := newAuto(t, Options{Type: kind, Fixed: "a", Priority: map[string]float64{"a": 100}}, members(a, b), clk, nil, nil)
			g.RecordProbeRound([]ProbeSample{
				{Name: "a", At: clk.Now(), Err: errors.New("failed")},
				{Name: "b", Latency: time.Millisecond, At: clk.Now()},
			})
			if g.Current() != "b" || g.Snapshot().Fixed != "a" {
				t.Fatal("fixed migrated")
			}
			c, e := g.DialTCP(context.Background(), outbound.Addr{Host: "test", Port: 80})
			if e != nil {
				t.Fatal(e)
			}
			c.Close()
			pc, e := g.ListenPacket(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			pc.Close()
			if b.dialCount() != 1 || b.lps != 1 {
				t.Fatal("soft fixed did not fail over TCP/UDP")
			}
			if g.Snapshot().Fixed != "a" {
				t.Fatal("lost persistent preference")
			}

		})
	}
}

func TestClientFixedValidationAndDisappearance(t *testing.T) {
	for _, o := range []Options{
		{Name: "g", Type: TypeSelect, Members: []string{"a"}, Fixed: "a"},
		{Name: "g", Type: TypeURLTest, Members: []string{"a"}, Fixed: "missing", Probe: probeOpts()},
		{Name: "g", Type: TypeFallback, Members: []string{"a"}, Priority: map[string]float64{"a": 2}, Probe: probeOpts()},
		{Name: "g", Type: TypeURLTest, Members: []string{"a"}, Priority: map[string]float64{"a": 0}, Probe: probeOpts()},
	} {
		if Validate(o) == nil {
			t.Fatal("invalid client fields accepted")
		}
	}
	a := newFake("a")
	g, e := New(Options{Name: "g", Type: TypeSmart, Members: []string{"a"}, Use: []string{"p"}, Expanded: true, Fixed: "gone", Probe: probeOpts()}, members(a), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	if g.Current() != "a" || g.(*autoGroup).Snapshot().Fixed != "gone" || !g.UDP() {
		t.Fatal("missing preference not retained with auto fallback")
	}
	c, e := g.DialTCP(context.Background(), outbound.Addr{Host: "test", Port: 80})
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if a.dialCount() != 1 {
		t.Fatal("missing fixed did not fall back")
	}

}

func TestClientConcurrentRecordSnapshot(t *testing.T) {
	g := newAuto(t, Options{Type: TypeSmart, Fixed: "a"}, members(newFake("a"), newFake("b")), realClock{}, nil, nil)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				g.RecordProbe("b", time.Millisecond, time.Now(), nil)
				_ = g.Snapshot()
				_ = g.Current()
			}
		}()
	}
	wg.Wait()
	if g.Current() != "a" {
		t.Fatal("fixed changed")
	}
}
