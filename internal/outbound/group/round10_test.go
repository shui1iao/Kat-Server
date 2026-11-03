package group

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"testing"
	"time"
)

func TestR10ClientStartupRetryOnceAndOriginalPeriodicDeadline(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeFallback, TypeSmart} {
		t.Run(kind, func(t *testing.T) {
			clk := newFakeClock()
			p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond})
			p.set("a", 0, true)
			p.block = make(chan struct{})
			lazy := false
			g := newAuto(t, Options{Type: kind, Lazy: &lazy, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true, Interval: outbound.Duration(time.Minute)}}, members(newFake("a")), clk, p, nil)
			g.Start(context.Background())
			deadline := time.Now().Add(time.Second)
			for !isProbing(g) {
				if time.Now().After(deadline) {
					t.Fatal("no first round")
				}
				time.Sleep(time.Millisecond)
			}
			if g.Snapshot().Members[0].Probed {
				t.Fatal("unfinished startup published a failure")
			}
			close(p.block)
			waitRounds(t, g, 1)
			clk.Advance(11 * time.Second)
			if g.roundsRun.Load() != 1 {
				t.Fatal("early retry")
			}
			clk.Advance(time.Second)
			waitRounds(t, g, 2)
			clk.Advance(12 * time.Second)
			if g.roundsRun.Load() != 2 || p.count("a") > 6 {
				t.Fatal("retry became a loop")
			}
			p.set("a", 41*time.Millisecond, false)
			clk.Advance(36 * time.Second)
			waitRounds(t, g, 3)
			if !g.Snapshot().Members[0].ProbeOK {
				t.Fatal("original 1m tick moved")
			}
		})
	}
}
func TestR10ClientStartupRetryRecoversPartialFailures(t *testing.T) {
	clk := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond, "b": 2 * time.Millisecond})
	p.set("b", 0, true)
	lazy := false
	g := newAuto(t, Options{Type: TypeFallback, Lazy: &lazy, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a"), newFake("b")), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	p.set("b", 42*time.Millisecond, false)
	clk.Advance(12 * time.Second)
	waitRounds(t, g, 2)
	for _, m := range g.Snapshot().Members {
		if !m.ProbeOK {
			t.Fatal("startup member not recovered")
		}
	}
}
func TestR10StartupRetryNotForServerOrSuccessOrManual(t *testing.T) {
	for _, mode := range []string{"server", "success", "manual"} {
		t.Run(mode, func(t *testing.T) {
			clk := newFakeClock()
			p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond})
			p.set("a", time.Millisecond, mode != "success" && mode != "manual")
			lazy := mode == "manual"
			g := newAuto(t, Options{Type: TypeFallback, Lazy: &lazy, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: mode != "server"}}, members(newFake("a")), clk, p, nil)
			g.Start(context.Background())
			if mode == "manual" {
				waitRounds(t, g, 1)
				g.RecordProbe("a", 0, clk.Now(), errors.New("manual failed"))
			} else {
				waitRounds(t, g, 1)
			}
			if mode == "server" {
				clk.Advance(5*time.Second - time.Nanosecond)
				if g.roundsRun.Load() != 1 {
					t.Fatal("confirmation before 5s")
				}
				clk.Advance(time.Nanosecond)
				waitRounds(t, g, 2)
				if !g.st[0].recovery.down {
					t.Fatal("independent second failure not applied")
				}
			}
			before := g.roundsRun.Load()
			clk.Advance(15 * time.Second)
			time.Sleep(5 * time.Millisecond)
			if g.roundsRun.Load() != before {
				t.Fatal("unwanted retry")
			}
		})
	}
}
func TestR10StartupRetryCanceledByCloseOrParent(t *testing.T) {
	for _, closeGroup := range []bool{true, false} {
		t.Run(map[bool]string{true: "close", false: "parent"}[closeGroup], func(t *testing.T) {
			clk := newFakeClock()
			p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond})
			p.set("a", 0, true)
			lazy := false
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g := newAuto(t, Options{Type: TypeFallback, Lazy: &lazy, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a")), clk, p, nil)
			g.Start(ctx)
			waitRounds(t, g, 1)
			if closeGroup {
				g.Close()
			} else {
				cancel()
			}
			clk.Advance(15 * time.Second)
			time.Sleep(5 * time.Millisecond)
			if g.roundsRun.Load() != 1 {
				t.Fatal("retry survived lifecycle")
			}
		})
	}
}
