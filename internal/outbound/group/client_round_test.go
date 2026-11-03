package group

import (
	"errors"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestClientSmartManualRoundOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "a-first"
		if reverse {
			name = "b-first"
		}
		t.Run(name, func(t *testing.T) {
			clk := newFakeClock()
			g := newAuto(t, Options{Type: TypeSmart, Priority: map[string]float64{"a": 4}}, members(newFake("a"), newFake("b")), clk, nil, nil)
			results := []ProbeSample{{Name: "a", Latency: 100 * time.Millisecond, At: clk.Now()}, {Name: "b", Latency: 200 * time.Millisecond, At: clk.Now()}}
			if reverse {
				results[0], results[1] = results[1], results[0]
			}
			g.RecordProbeRound(results)
			for _, m := range g.Snapshot().Members {
				want := time.Duration(100) * time.Millisecond
				if m.Name == "b" {
					want = 200 * time.Millisecond
				}
				if !m.Probed || !m.ProbeOK || m.ProbeLatency != want || m.Latency != 0 || m.ScoreParts.ProbeMS == nil || *m.ScoreParts.ProbeMS != ms(want) {
					t.Fatalf("sample/EWMA not retained: %+v", m)
				}
			}
			if got := g.Current(); got != "b" {
				t.Fatalf("same full round: a=100ms*4, b=200ms*1: current=%s, want b", got)
			}
		})
	}
}

// V2 does not mix probe and real EWMA. Atomic manual order is retained;
// median/maturity and repeated rounds are exercised in TestV2StableMedianAndIndependentRounds.
func TestClientManualRoundFailuresFixedAndStale(t *testing.T) {
	for _, kind := range []string{TypeSmart, TypeURLTest} {
		t.Run(kind, func(t *testing.T) {
			clk := newFakeClock()
			g := newAuto(t, Options{Type: kind, Fixed: "a", Priority: map[string]float64{"a": 100}}, members(newFake("a"), newFake("b")), clk, nil, nil)
			failed := errors.New("HTTP probe failed")
			g.RecordProbeRound([]ProbeSample{{Name: "a", At: clk.Now(), Err: failed}, {Name: "b", Latency: time.Millisecond, At: clk.Now()}})
			s := g.Snapshot()
			if s.Current != "b" || s.Fixed != "a" || s.Members[0].ProbeOK || !s.Members[1].ProbeOK || s.Members[1].Priority != 1 {
				t.Fatal("fixed/failed/default weight changed")
			}
			g.RecordProbeRound(nil)
			g.RecordProbeRound([]ProbeSample{{Name: "a", Latency: time.Millisecond, At: clk.Now().Add(-time.Second)}})
			if !reflect.DeepEqual(s, g.Snapshot()) {
				t.Fatal("empty/stale round changed state")
			}
			g.Close()
			g.RecordProbeRound([]ProbeSample{{Name: "a", Latency: time.Millisecond, At: clk.Now().Add(time.Second)}})
			if !reflect.DeepEqual(s, g.Snapshot()) {
				t.Fatal("closed group accepted late round")
			}
			all := newAuto(t, Options{Type: kind}, members(newFake("a"), newFake("b")), clk, nil, nil)
			all.RecordProbeRound([]ProbeSample{{Name: "b", At: clk.Now(), Err: failed}, {Name: "a", At: clk.Now(), Err: failed}})
			for _, m := range all.Snapshot().Members {
				if !m.Probed || m.ProbeOK || m.ProbeLatency != 0 {
					t.Fatal("failed round fabricated success")
				}
			}
		})
	}
}

func TestClientConcurrentManualRounds(t *testing.T) {
	clk := newFakeClock()
	g := newAuto(t, Options{Type: TypeSmart, Fixed: "a"}, members(newFake("a"), newFake("b")), clk, nil, nil)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				g.RecordProbeRound([]ProbeSample{{Name: "a", Latency: time.Millisecond, At: clk.Now()}, {Name: "b", Latency: 2 * time.Millisecond, At: clk.Now()}})
				_ = g.Snapshot()
			}
		}()
	}
	wg.Wait()
	if g.Current() != "a" {
		t.Fatal("fixed changed under concurrent rounds")
	}
}

func TestClientManualPriorityValidation(t *testing.T) {
	for _, kind := range []string{TypeSmart, TypeURLTest} {
		for _, v := range []float64{0, -1, 101, math.NaN(), math.Inf(1), math.Inf(-1)} {
			if Validate(Options{Name: "g", Type: kind, Members: []string{"a"}, Probe: probeOpts(), Priority: map[string]float64{"a": v}}) == nil {
				t.Fatalf("accepted %s priority %v", kind, v)
			}
		}
		for _, v := range []float64{0.01, 1, 100} {
			if e := Validate(Options{Name: "g", Type: kind, Members: []string{"a"}, Probe: probeOpts(), Priority: map[string]float64{"a": v}}); e != nil {
				t.Fatal(e)
			}
		}
	}
}
