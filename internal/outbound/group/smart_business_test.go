package group

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func TestSmartBootstrapUsesDisplayedProbeAndWeight(t *testing.T) {
	for _, tc := range []struct {
		name   string
		a, b   time.Duration
		weight float64
		want   string
	}{
		{"warm_not_cold", 10 * ms_, 30 * ms_, 1.5, "a"},
		{"weight_applies", 40 * ms_, 70 * ms_, 2, "b"},
		{"no_failure_prior_in_bootstrap", 40 * ms_, 70 * ms_, 1.5, "a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newFakeClock()
			g := newAuto(t, Options{Type: TypeSmart, Priority: map[string]float64{"a": tc.weight}}, members(newFake("a"), newFake("b")), c, nil, nil)
			if c, err := g.DialTCP(context.Background(), outbound.Addr{Host: "before.test", Port: 443}); err == nil || c != nil {
				t.Fatal("cold unstarted Smart guessed a business member", c, err)
			}
			if g.Current() != "" || g.Snapshot().Current != "" {
				t.Fatal("cold status invented a selected member")
			}
			// A pre-existing empty site still adopts the full-round bootstrap.
			g.sites.ensure(siteKey("before.test", 443, "tcp"), c.Now(), g.cur)
			c.Advance(time.Second)
			g.RecordProbeRound([]ProbeSample{{Name: "a", Latency: tc.a, ColdLatency: 250 * ms_, At: c.Now()}, {Name: "b", Latency: tc.b, ColdLatency: 100 * ms_, At: c.Now()}})
			if g.Current() != tc.want {
				t.Fatal("displayed probe * weight not used", g.Current(), tc.want)
			}
			if got := dial(t, g, "before.test"); got != tc.want {
				t.Fatal("unlearned site retained pre-probe default", got, tc.want)
			}
			for _, m := range g.members {
				f := m.(*fakeOut)
				select {
				case peer := <-f.peers:
					peer.Close()
				default:
				}
			}
			if g.st[0].cold != 250*ms_ || g.st[1].cold != 100*ms_ {
				t.Fatal("weak cold prior was discarded")
			}
			for _, st := range g.st {
				if st.real.response.count != 0 {
					t.Fatal("probe became real learning")
				}
			}
		})
	}
}

func TestSmartNodeAndGroupProbeForwardSameMeasurement(t *testing.T) {
	for _, node := range []bool{true, false} {
		t.Run(map[bool]string{true: "node", false: "group"}[node], func(t *testing.T) {
			c := newFakeClock()
			g := newAuto(t, Options{Type: TypeSmart, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a")), c, nil, nil)
			sample := ProbeSample{Name: "a", Latency: 10 * ms_, ColdLatency: 250 * ms_, Started: c.Now(), At: c.Now().Add(time.Second)}
			c.Advance(time.Second)
			if node {
				g.RecordURLProbe("http://probe.test/", sample)
			} else {
				g.RecordProbeRound([]ProbeSample{sample})
			}
			if g.st[0].probeLat != 10*ms_ || g.st[0].cold != 250*ms_ || g.cold {
				t.Fatal("node/group measurement lost", g.st[0])
			}
			c.Advance(time.Second)
			g.st[0].healthAt = c.Now()
			sample.At = c.Now().Add(time.Second)
			sample.Latency = 999 * ms_
			c.Advance(time.Second)
			if node {
				g.RecordURLProbe("http://probe.test/", sample)
			} else {
				g.RecordProbeRound([]ProbeSample{sample})
			}
			if g.st[0].probeLat != 10*ms_ || g.st[0].real.response.count != 0 || g.sites.len() != 0 {
				t.Fatal("stale/probe isolation failed")
			}
		})
	}
}

// Exercise a real write/read exchange through the production observer. The
// fixture controls which member is sampled without fabricating quality data.
func smartBusinessExchange(t *testing.T, g *autoGroup, c *fakeClock, i int, host string, lat time.Duration) {
	t.Helper()
	raw, e := g.members[i].DialTCP(context.Background(), outbound.Addr{Host: host, Port: 443})
	if e != nil {
		t.Fatal(e)
	}
	conn := wrapConn(raw, g.smartObserver(i, siteKey(host, 443, "tcp"), 0))
	peer := <-g.members[i].(*fakeOut).peers
	done := make(chan error, 1)
	go func() {
		defer peer.Close()
		_, e := io.ReadFull(peer, make([]byte, 1))
		if e == nil {
			_, e = peer.Write([]byte{1})
		}
		done <- e
	}()
	if _, e = conn.Write([]byte{1}); e != nil {
		t.Fatal(e)
	}
	c.Advance(lat)
	if _, e = io.ReadFull(conn, make([]byte, 1)); e != nil {
		t.Fatal(e)
	}
	conn.Close()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestSmartOnlyNewBusinessPerformanceCanPromote(t *testing.T) {
	for _, scope := range []string{"site", "group"} {
		t.Run(scope, func(t *testing.T) {
			c := newFakeClock()
			g := newAuto(t, Options{Type: TypeSmart, Smart: &SmartOptions{Scope: scope}}, members(newFake("a"), newFake("b")), c, nil, nil)
			v2Round(g, c, 300*ms_, 400*ms_)
			key := siteKey("business.test", 443, "tcp")
			g.sites.ensure(key, c.Now(), 0)
			// The default dwell applies independently to this site too.
			c.Advance(time.Minute)
			for range 5 {
				v2Round(g, c, 300*ms_, 10*ms_)
			}
			if g.Current() != "a" || g.gate.wins != 0 || g.sites.get(key, c.Now()).gate.wins != 0 || g.challengeStop != nil || g.challengeRuns != 0 {
				t.Fatal("probe-only performance promoted")
			}
			for range 6 {
				for range 4 {
					smartBusinessExchange(t, g, c, 0, "business.test", time.Second)
				}
				for range 4 {
					smartBusinessExchange(t, g, c, 1, "business.test", 20*ms_)
				}
				c.Advance(5 * time.Second)
			}
			if g.Current() != "b" {
				t.Fatal("real Write/Read performance did not promote", g.gate)
			}
			if scope == "site" && g.sites.get(key, c.Now()).current != 1 {
				t.Fatal("site performance did not learn")
			}
			if g.st[0].real.response.count == 0 || g.st[1].real.response.count == 0 {
				t.Fatal("actual observer did not learn")
			}
			c.Advance(time.Minute)
			evidence, wins := g.evidence, g.gate.wins
			at := g.memberEvidenceLocked(0, nil)
			for range 5 {
				v2Round(g, c, time.Millisecond, 3000*ms_)
			}
			if g.Current() != "b" || g.gate.wins != wins || g.evidence != evidence || !g.memberEvidenceLocked(0, nil).Equal(at) {
				t.Fatal("probe borrowed mature business history to promote")
			}
			if scope == "site" && g.sites.get(key, c.Now()).current != 1 {
				t.Fatal("probe promoted learned site")
			}
			parts, _, _ := g.scorePartsLocked(0, nil, c.Now())
			if parts.ProbeMS == nil || *parts.ProbeMS != 1 || parts.RealMS == nil || parts.RealShare <= 0 || parts.RealShare >= 1 {
				t.Fatal("weak probe prior was not retained", parts)
			}
			q := switchGate{candidate: 0, wins: g.cfg.confirms, evidence: g.evidence, currentAt: c.Now(), bestAt: c.Now()}
			if g.gateLocked(&q, 1, 0, 300, 20, true, c.Now().Add(-time.Hour), c.Now(), c.Now(), c.Now()) {
				t.Fatal("stale business evidence reused")
			}
		})
	}
}

func TestSmartProbeOnlyNeverSchedulesPerformanceChallenge(t *testing.T) {
	c := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": 300 * ms_, "b": 400 * ms_})
	g := newAuto(t, Options{Type: TypeSmart}, members(newFake("a"), newFake("b")), c, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	c.Advance(time.Minute)
	p.set("b", 100*ms_, false)
	probeNow(t, g)
	c.Advance(10 * time.Second)
	g.mu.Lock()
	scheduled, runs := g.challengeStop != nil, g.challengeRuns
	g.mu.Unlock()
	if scheduled || runs != 0 || p.count("a") != 2 || p.count("b") != 2 || g.Current() != "a" {
		t.Fatal("Smart probe scheduled active performance confirmation", scheduled, runs, p.count("a"), p.count("b"))
	}
}
