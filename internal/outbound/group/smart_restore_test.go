package group

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSmartRestoreIDNATTLAndEqualCosts(t *testing.T) {
	if siteKey("BÜCHER.example.", 443, "tcp") != siteKey("xn--bcher-kva.example", 443, "tcp") {
		t.Fatal("IDNA normalization mismatch")
	}
	if siteKey("::ffff:127.0.0.1", 443, "tcp") != siteKey("127.0.0.1", 443, "tcp") {
		t.Fatal("mapped IP mismatch")
	}
	c := newFakeClock()
	cache := newSiteCache(2)
	defer cache.clear()
	k := siteKey("private.example", 443, "tcp")
	cache.record(k, 0, true, c.Now(), 0)
	c.Advance(smartSiteTTL - time.Nanosecond)
	if cache.get(k, c.Now()) == nil {
		t.Fatal("premature TTL")
	}
	c.Advance(time.Nanosecond)
	if cache.get(k, c.Now()) != nil {
		t.Fatal("TTL access incorrectly renewed lifetime")
	}
	g, clk := v2Group(t, TypeSmart)
	zero := 0.0
	dwell := outboundZeroDuration()
	g.cfg.tolerance = 0
	g.cfg.relative = zero
	g.cfg.dwell = dwell
	for range 12 {
		v2Round(g, clk, 100*time.Millisecond, 100*time.Millisecond)
		g.realSuccess(0, siteKey("same.example", 443, "tcp"), 100*time.Millisecond, true)
		g.realSuccess(1, siteKey("same.example", 443, "tcp"), 100*time.Millisecond, true)
		if g.Current() != "a" {
			t.Fatal("equal cost flapped")
		}
	}
	b, _ := json.Marshal(g.Snapshot())
	if strings.Contains(string(b), "same.example") || strings.Contains(string(b), "private.example") {
		t.Fatal("site key leaked through status")
	}
	t.Log("IDNA/IP normalization; 10m fake-clock TTL with no read renewal; equal-cost zero-tolerance stability; destination privacy")
}
func outboundZeroDuration() time.Duration { return 0 }

func TestSmartRestoreProcessSiteQuota(t *testing.T) {
	before := smartSiteSlots.Load()
	caches := []*siteCache{newSiteCache(smartSiteCap), newSiteCache(smartSiteCap), newSiteCache(smartSiteCap)}
	defer func() {
		for _, c := range caches {
			c.clear()
		}
		if smartSiteSlots.Load() != before {
			t.Error("process quota not released")
		}
	}()
	now := time.Now()
	for i := 0; i < 7000; i++ {
		caches[i/2500].record(fmt.Sprint("quota-", i), 0, true, now, 0)
		if smartSiteSlots.Load() > maxProcessSites {
			t.Fatal("unbounded process site RAM")
		}
	}
	if smartSiteSlots.Load() != maxProcessSites {
		t.Fatal("did not exercise process cap", smartSiteSlots.Load())
	}
}
func TestSmartRestorePreservesFallbackIndependentRounds(t *testing.T) {
	for _, limit := range []int{2, 4} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			clk := newFakeClock()
			g := newAuto(t, Options{Type: TypeFallback, MaxFailedTimes: limit}, members(newFake("a"), newFake("b")), clk, nil, nil)
			round := func(err error) {
				clk.Advance(time.Second)
				at := clk.Now()
				g.RecordProbeRound([]ProbeSample{{Name: "a", Started: at, At: at, Latency: 900 * time.Millisecond, Err: err}, {Name: "b", Started: at, At: at, Latency: time.Millisecond}})
			}
			round(nil)
			if g.Current() != "a" {
				t.Fatal("latency overrode order")
			}
			failure := errors.New("independent round")
			for n := 1; n <= limit; n++ {
				round(failure)
				want := "a"
				if n == limit {
					want = "b"
				}
				if g.Current() != want {
					t.Fatal("wrong confirmation threshold", n, g.Current())
				}
				g.RecordProbeRound([]ProbeSample{{Name: "a", At: clk.Now(), Err: failure}, {Name: "b", At: clk.Now(), Latency: time.Millisecond}})
				for range 8 {
					g.Snapshot()
					g.Current()
				}
				if g.Current() != want {
					t.Fatal("duplicate or reads added evidence")
				}
			}
			round(nil)
			if g.Current() != "b" {
				t.Fatal("recovered on one success")
			}
			clk.Advance(5 * time.Second)
			round(nil)
			if g.Current() != "b" {
				t.Fatal("recovered before hold")
			}
			clk.Advance(5 * time.Second)
			if g.Current() != "a" {
				t.Fatal("ordered recovery missing")
			}
		})
	}
}
