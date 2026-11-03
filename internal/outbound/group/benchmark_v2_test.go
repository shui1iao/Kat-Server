package group

import (
	"fmt"
	"github.com/shui1iao/Kat/internal/outbound"
	"testing"
	"time"
)

func BenchmarkSmartV2NewSiteSelection(b *testing.B) {
	for _, n := range []int{25, 1024} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := newFakeClock()
			ms := make([]outbound.Outbound, n)
			names := make([]string, n)
			for i := range ms {
				names[i] = fmt.Sprint("node", i)
				ms[i] = newFake(names[i])
			}
			g, e := newGroup(Options{Name: "bench", Type: TypeSmart, Expanded: true, Members: names, Probe: probeOpts()}, ms, nil, hooks{clk: c})
			if e != nil {
				b.Fatal(e)
			}
			a := g.(*autoGroup)
			defer a.Close()
			samples := make([]ProbeSample, n)
			for i := range samples {
				samples[i] = ProbeSample{Name: names[i], Latency: time.Duration(50+i) * time.Millisecond, At: c.Now()}
			}
			a.RecordProbeRound(samples)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				key := siteKey(fmt.Sprint("site", i%3000, ".example"), 443, "tcp")
				a.mu.Lock()
				_ = a.candidatesLocked(key, false, c.Now())
				a.mu.Unlock()
			}
		})
	}
}
