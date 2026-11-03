package group

import (
	"errors"
	"testing"
	"time"
)

func acceptedFallbackFailure(t *testing.T, g *autoGroup, c *fakeClock, name string) {
	t.Helper()
	for round := 1; round <= g.cfg.maxFailed; round++ {
		c.Advance(time.Second)
		samples := make([]ProbeSample, len(g.cfg.members))
		for i, n := range g.cfg.members {
			samples[i] = ProbeSample{Name: n, Latency: 10 * time.Millisecond, At: c.Now()}
			if n == name {
				samples[i].Err = errors.New("health failure")
			}
		}
		g.RecordProbeRound(samples)
		if round < g.cfg.maxFailed && !g.fallbackUpTest(indexOfName(g.cfg.members, name)) {
			t.Fatal("failure before independent threshold")
		}
	}
}
func indexOfName(a []string, n string) int {
	for i, v := range a {
		if v == n {
			return i
		}
	}
	panic("missing member")
}
