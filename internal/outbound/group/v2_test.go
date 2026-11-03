package group

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"math"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// All new decision tests use the package fake clock and fake outbound; no
// real website, real timer, DNS lookup or external proxy participates.
func v2Round(g *autoGroup, c *fakeClock, a, b time.Duration) {
	c.Advance(time.Second)
	g.RecordProbeRound([]ProbeSample{{Name: "a", Latency: a, At: c.Now()}, {Name: "b", Latency: b, At: c.Now()}})
}
func v2Group(t *testing.T, kind string) (*autoGroup, *fakeClock) {
	c := newFakeClock()
	return newAuto(t, Options{Type: kind}, members(newFake("a"), newFake("b")), c, nil, nil), c
}
func TestV2TolerancePresenceAndCompatibility(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeSmart} {
		for _, val := range []string{"", `,"tolerance":0`, `,"tolerance":50`, `,"tolerance":"0ms"`, `,"tolerance":"50ms"`} {
			var o Options
			b := `{"name":"g","type":"` + kind + `","members":["a"],"probe":{"url":"http://probe.test/"}` + val + `}`
			if err := json.Unmarshal([]byte(b), &o); err != nil {
				t.Fatal(err)
			}
			c, e := normalize(o)
			if e != nil {
				t.Fatal(e)
			}
			want := 20 * time.Millisecond
			if strings.Contains(val, ":0") || strings.Contains(val, `"0ms"`) {
				want = 0
			} else if val != "" {
				want = 50 * time.Millisecond
			}
			if c.tolerance != want {
				t.Fatal(val, c.tolerance, want)
			}
			out, _ := json.Marshal(o)
			var again Options
			_ = json.Unmarshal(out, &again)
			cc, e := normalize(again)
			if e != nil || cc.tolerance != want {
				t.Fatal(string(out), e)
			}
		}
	}
	for _, v := range []string{`{"scope":"legacy"}`, `{"scope":"site","exploration_rate":0.051}`, `{"scope":"site","exploration_rate":-1}`} {
		o := Options{Name: "g", Type: TypeSmart, Members: []string{"a"}, Probe: probeOpts()}
		_ = json.Unmarshal([]byte(v), &o.Smart)
		if Validate(o) == nil {
			t.Fatal("invalid smart accepted", v)
		}
	}
}
func TestV2StableMedianAndIndependentRounds(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeSmart} {
		g, c := v2Group(t, kind)
		v2Round(g, c, 300*ms_, 400*ms_)
		c.Advance(time.Minute)
		// One spectacularly low sample, then repeated reads, cannot promote.
		v2Round(g, c, 300*ms_, time.Millisecond)
		for range 100 {
			g.Current()
			g.Snapshot()
		}
		if g.Current() != "a" {
			t.Fatal(kind, "one sample promoted")
		}
		v2Round(g, c, 300*ms_, 200*ms_)
		wantWins := 1
		if kind == TypeSmart {
			wantWins = 0
		} // probes are not business evidence
		if g.Current() != "a" || g.gate.wins != wantWins {
			t.Fatal(kind, "mature challenge round one", g.gate)
		}
		same := []ProbeSample{{Name: "a", Latency: 300 * ms_, At: c.Now()}, {Name: "b", Latency: 200 * ms_, At: c.Now()}}
		g.RecordProbeRound(same)
		if g.gate.wins != wantWins {
			t.Fatal("duplicate timestamp counted")
		}
		c.Advance(time.Second)
		g.RecordProbe("b", 200*ms_, c.Now(), nil)
		if g.Current() != "a" || g.gate.wins != wantWins {
			t.Fatal("single node bypassed gate")
		}
		v2Round(g, c, 300*ms_, 200*ms_)
		want := "b"
		if kind == TypeSmart {
			want = "a"
		}
		if g.Current() != want {
			t.Fatal(kind, "probe-only selection", g.gate)
		}
	}
}
func TestV2JitterDoesNotSwitch30Minutes(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeSmart} {
		g, c := v2Group(t, kind)
		v2Round(g, c, 100*ms_, 105*ms_)
		for n := range 1800 {
			v2Round(g, c, time.Duration([]int{100, 105, 98, 110}[n%4])*ms_, time.Duration([]int{105, 98, 110, 100}[n%4])*ms_)
			if g.Current() != "a" {
				t.Fatal(kind, n, "jitter switched")
			}
		}
	}
}
func TestV2GateBoundariesAndChallengeReset(t *testing.T) {
	g, c := v2Group(t, TypeURLTest)
	q := switchGate{}
	q.reset()
	now := c.Now()
	g.curSince = now.Add(-time.Minute)
	for _, tc := range []struct {
		a, b float64
		ok   bool
	}{{300, 280, false}, {300, 270, true}, {100, 80, false}, {1000, 910, false}, {1000, 900, true}} {
		q.reset()
		for range 2 {
			g.evidence++
			now = now.Add(time.Second)
			got := g.gateLocked(&q, 0, 1, tc.a, tc.b, true, g.curSince, now, now, now)
			if q.wins == 2 && got != tc.ok {
				t.Fatal(tc, q)
			}
		}
	}
	q.reset()
	g.evidence++
	_ = g.gateLocked(&q, 0, 1, 300, 200, true, now, now, now, now)
	if q.wins != 1 {
		t.Fatal(q)
	}
	g.evidence++
	_ = g.gateLocked(&q, 0, 2, 300, 100, true, now, now.Add(time.Second), now.Add(time.Second), now.Add(time.Second))
	if q.wins != 1 || q.candidate != 2 {
		t.Fatal("challenger streak leaked", q)
	}
	g.evidence++
	_ = g.gateLocked(&q, 0, 2, 300, 100, false, now, now, now, now)
	if q.wins != 0 {
		t.Fatal("lost maturity did not reset")
	}
	r := recovery{}
	r.observe(false, now)
	r.observe(true, now.Add(time.Second))
	r.observe(true, now.Add(time.Second))
	if r.successes != 1 {
		t.Fatal("duplicate recovery")
	}
	r.observe(true, now.Add(6*time.Second))
	if r.ready(now.Add(10 * time.Second)) {
		t.Fatal("hold boundary")
	}
	if !r.ready(now.Add(11 * time.Second)) {
		t.Fatal("hold never completes")
	}
}
func TestV2FailureImmediateAndRecoveryHysteresis(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeSmart, TypeFallback, TypeLoadBalance} {
		t.Run(kind, func(t *testing.T) {
			g, c := v2Group(t, kind)
			v2Round(g, c, 100*ms_, 300*ms_)
			c.Advance(time.Second)
			g.RecordProbe("a", 0, c.Now(), errors.New("down"))
			if kind == TypeFallback {
				if g.Current() != "a" {
					t.Fatal("partial sample convicted fallback")
				}
				acceptedFallbackFailure(t, g, c, "a")
			}
			if kind != TypeLoadBalance && g.Current() != "b" {
				t.Fatal(kind, "not immediate", g.Current())
			}
			c.Advance(time.Second)
			g.RecordProbe("a", 100*ms_, c.Now(), nil)
			if g.fallbackUpTest(0) {
				t.Fatal(kind, "one success recovered")
			}
			c.Advance(5 * time.Second)
			g.RecordProbe("a", 100*ms_, c.Now(), nil)
			if g.fallbackUpTest(0) {
				t.Fatal(kind, "two successes bypass hold")
			}
			c.Advance(5 * time.Second)
			if !g.fallbackUpTest(0) {
				t.Fatal(kind, "recovery not eligible")
			}
			if kind == TypeFallback && g.Current() != "a" {
				t.Fatal("fallback order not restored")
			}
			if (kind == TypeSmart || kind == TypeURLTest) && g.Current() != "b" {
				t.Fatal("health recovery bypassed performance dwell")
			}
		})
	}
}
func (g *autoGroup) fallbackUpTest(i int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fallbackUpLocked(i)
}
func TestV2SignalSeparationDecayAndReliability(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	v2Round(g, c, 250*ms_, 100*ms_)
	if g.st[0].real.response.count != 0 {
		t.Fatal("probe entered real statistics")
	}
	g.RecordProbeRound([]ProbeSample{{Name: "a", Latency: 10 * ms_, ColdLatency: 250 * ms_, At: c.Now().Add(time.Second)}})
	if g.st[0].cold != 250*ms_ {
		t.Fatal("warm replaced cold")
	}
	o := g.smartObserver(0, siteKey("A.Example.", 443, "tcp"), 200*ms_)
	c.Advance(time.Second)
	o.beforeWrite(1)
	c.Advance(50 * ms_)
	o.afterRead(1, nil)
	mean, n, _ := g.st[0].real.response.value(c.Now())
	if math.Abs(mean-250) > .001 || n != 1 {
		t.Fatal(mean, n)
	}
	c.Advance(120 * time.Second)
	_, n, _ = g.st[0].real.response.value(c.Now())
	if math.Abs(n-.5) > .001 {
		t.Fatal("not 2min half life", n)
	}
	c.Advance(10 * time.Minute)
	_, n, _ = g.st[0].real.response.value(c.Now())
	if n != 0 {
		t.Fatal("stale samples alive")
	}
	// Reliability dominates tiny delay advantages, and a low factor cannot
	// resurrect a circuit-open member.
	for i := range 100 {
		g.st[0].real.result(i%5 != 0, c.Now(), true)
		g.st[1].real.result(i%50 != 0, c.Now(), true)
	}
	g.st[0].cold = 50 * ms_
	g.st[1].cold = 100 * ms_
	g.st[0].coldAt = c.Now()
	g.st[1].coldAt = c.Now()
	if g.scoreLocked(0, c.Now()) <= g.scoreLocked(1, c.Now()) {
		t.Fatal("failed fast node won")
	}
	g.cfg.priority[0] = .01
	g.st[0].recovery.observe(false, c.Now())
	order, _ := g.smartRankLocked(c.Now())
	if order[0] != 1 {
		t.Fatal("weight bypassed health")
	}
}
func TestV2SiteScopeIndependentAndGroupMode(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	v2Round(g, c, 100*ms_, 100*ms_)
	keys := []string{siteKey("A.Example.", 443, "tcp"), siteKey("b.example", 443, "tcp")}
	for _, key := range keys {
		g.sites.ensure(key, c.Now(), 0)
	}
	c.Advance(time.Minute)
	for round := range 30 {
		c.Advance(5 * time.Second)
		for k, key := range keys {
			for i := range 2 {
				g.sites.record(key, i, true, c.Now(), g.cur)
				r := g.sites.get(key, c.Now()).recs[i]
				lat := 1000 * ms_
				if i == k {
					lat = 20 * ms_
				}
				r.quality.latency(lat, c.Now())
				r.quality.result(true, c.Now(), true)
			}
		}
		g.evidence++
		// Records above represent real site responses, not probe rounds.
		for _, key := range keys {
			g.siteReevalLocked(g.sites.get(key, c.Now()), c.Now(), true)
		}
		_ = round
	}
	if g.smartOrderLocked(keys[0], c.Now())[0] != 0 || g.smartOrderLocked(keys[1], c.Now())[0] != 1 {
		t.Fatal("site choices contaminated each other")
	}
	g.cfg.scope = "group"
	if g.smartOrderLocked(keys[0], c.Now())[0] != g.smartOrderLocked(keys[1], c.Now())[0] {
		t.Fatal("group performance differed")
	}
	if siteKey("A.Example.", 443, "tcp") != siteKey("a.example", 443, "tcp") || siteKey("a.example", 443, "tcp") == siteKey("a.example", 80, "tcp") || siteKey("a.example", 443, "tcp") == siteKey("a.example", 443, "udp") {
		t.Fatal("normalization/network/port collision")
	}
	g.cfg.fixed = "a"
	g.cfg.fixedIndex = 0
	if g.smartOrderLocked(keys[1], c.Now())[0] != 0 {
		t.Fatal("soft fixed not first")
	}
}
func TestV2UnknownAttributionAndLateSuccess(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	v2Round(g, c, 50*ms_, 100*ms_)
	key := siteKey("x.example", 443, "tcp")
	g.smartAttemptFailure(0, key, false)
	if g.st[0].real.failure != 0 || !g.fallbackUpTest(0) {
		t.Fatal("one target globally punished")
	}
	o := g.smartObserver(1, key, 20*ms_)
	o.beforeWrite(1)
	c.Advance(3 * time.Second)
	if !g.sites.get(key, c.Now()).failedRecently(1, c.Now()) {
		t.Fatal("soft timeout absent")
	}
	c.Advance(time.Second)
	o.afterRead(1, nil)
	o.afterRead(1, nil)
	r := g.sites.get(key, c.Now()).recs[1]
	if r.quality.failure != 0 || r.quality.success != 1 {
		t.Fatal("late success duplicated permanent failure", r.quality)
	}
	if g.st[1].real.failure != 0 {
		t.Fatal("soft failure polluted global rate")
	}
}
func TestV2HedgeUniqueWinnerNoReplayAndNestedBudget(t *testing.T) {
	c := newFakeClock()
	a, b, d := newFake("a"), newFake("b"), newFake("d")
	var active, peak, attempts atomic.Int32
	block := func(ctx context.Context, _ outbound.Addr) (net.Conn, error) {
		n := active.Add(1)
		attempts.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer active.Add(-1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	a.onDial = block
	d.onDial = block
	inner := newAuto(t, Options{Name: "inner", Type: TypeSmart}, members(a, b, d), c, nil, nil)
	inner.RecordProbeRound([]ProbeSample{{Name: "a", Latency: 50 * ms_, At: c.Now()}, {Name: "b", Latency: 100 * ms_, At: c.Now()}, {Name: "d", Latency: 200 * ms_, At: c.Now()}})
	for range 5 {
		inner.st[0].dial.add(50, c.Now())
	}
	outer := newAuto(t, Options{Name: "outer", Type: TypeSmart}, []outbound.Outbound{inner, newFake("other")}, c, nil, nil)
	outer.RecordProbeRound([]ProbeSample{{Name: "inner", Latency: 50 * ms_, At: c.Now()}, {Name: "other", Latency: 300 * ms_, At: c.Now()}})
	result := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		cc, e := outer.DialTCP(context.Background(), outbound.Addr{Host: "x.example", Port: 443})
		result <- cc
		errCh <- e
	}()
	deadline := time.Now().Add(time.Second)
	for a.dialCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no initial dial")
		}
		time.Sleep(time.Millisecond)
	}
	c.Advance(300 * ms_)
	var conn net.Conn
	select {
	case conn = <-result:
	case <-time.After(time.Second):
		t.Fatal("hedge stalled")
	}
	if e := <-errCh; e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	// No application Write is ever issued by the hedge itself.
	if peak.Load() > 2 || attempts.Load() > 3 {
		t.Fatal("nested budget amplified", peak.Load(), attempts.Load())
	}
	var peer net.Conn
	select {
	case peer = <-b.peers:
	case <-time.After(time.Second):
		t.Fatal("nested hedge did not win")
	}
	defer peer.Close()
	peer.SetReadDeadline(time.Now().Add(10 * ms_))
	if n, _ := peer.Read(make([]byte, 1)); n != 0 {
		t.Fatal("application data replayed")
	}
}
func TestV2FixedJustFailedSameRequestFallback(t *testing.T) {
	c := newFakeClock()
	a, b := newFake("a"), newFake("b")
	a.setErr(errors.New("unknown dial failure"))
	g := newAuto(t, Options{Type: TypeSmart, Fixed: "a"}, members(a, b), c, nil, nil)
	conn, e := g.DialTCP(context.Background(), outbound.Addr{Host: "x.example", Port: 443})
	if e != nil {
		t.Fatal(e)
	}
	conn.Close()
	if a.dialCount() != 1 || b.dialCount() != 1 || g.cfg.fixed != "a" {
		t.Fatal("fixed failed without same-request fallback")
	}
}
func TestV2UDPDoesNotInventRTTOrPenalizeSilence(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	v2Round(g, c, 50*ms_, 100*ms_)
	pc, e := g.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	before := g.Snapshot().Members
	_, _ = pc.WriteTo([]byte("one"), outbound.Addr{Host: "x.example", Port: 53})
	c.Advance(4 * time.Second)
	after := g.Snapshot().Members
	if !reflect.DeepEqual(before, after) {
		t.Fatal("UDP silence changed TCP statistics")
	}
}
func TestV2SiteBoundsAndPrivacy(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	for i := range 2500 {
		key := siteKey(strings.Repeat("a", i%30)+string(rune(1000+i)), 443, "tcp")
		for j := range 12 {
			g.sites.record(key, j, true, c.Now(), g.cur)
		}
		if len(g.sites.get(key, c.Now()).recs) > 8 {
			t.Fatal("member cap")
		}
	}
	if g.sites.len() > 2048 {
		t.Fatal("site cap")
	}
	b, _ := json.Marshal(g.Snapshot())
	if strings.Contains(string(b), "key") || strings.Contains(string(b), "https://") {
		t.Fatal("private site table exported")
	}
}
func TestV2ChallengeBoundedAndLazyStops(t *testing.T) {
	c := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": 300 * ms_, "b": 400 * ms_})
	g := newAuto(t, Options{Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a"), newFake("b")), c, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	// Pass the default dwell while still inside the 60s lazy-use window.
	c.Advance(30 * time.Second)
	p.set("b", 100*ms_, false)
	probeNow(t, g)
	for range 3 {
		c.Advance(2 * time.Second)
		deadline := time.Now().Add(time.Second)
		for {
			g.mu.Lock()
			busy := g.probing
			g.mu.Unlock()
			if !busy {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("pair stuck")
			}
			time.Sleep(time.Millisecond)
		}
	}
	if g.challengeRuns > 3 || p.count("a") > 5 || p.count("b") > 5 {
		t.Fatal("unbounded challenge", g.challengeRuns)
	}
	if g.Current() != "b" {
		t.Fatal("paired evidence did not promote")
	}
}

func TestV2ExplorationBoundedFixedAndZero(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	v2Round(g, c, 100*ms_, 101*ms_)
	g.random = func() float64 { return 0 }
	k := siteKey("new.example", 443, "tcp")
	if g.smartOrderLocked(k, c.Now())[0] != 0 || g.exploring != "" {
		t.Fatal("zero exploration explored")
	}
	g.cfg.exploration = .02
	k = siteKey("fresh.example", 443, "tcp")
	if g.smartOrderLocked(k, c.Now())[0] != 1 || g.exploring != k {
		t.Fatal("bounded near-optimal exploration missing")
	}
	if g.smartOrderLocked(siteKey("parallel.example", 443, "tcp"), c.Now())[0] != 0 {
		t.Fatal("parallel exploration exceeded one")
	}
	g.exploring = ""
	g.cfg.fixed = "a"
	g.cfg.fixedIndex = 0
	if g.smartOrderLocked(siteKey("fixed.example", 443, "tcp"), c.Now())[0] != 0 {
		t.Fatal("exploration overrode fixed")
	}
}
func TestV2SlowSiteTrialConvergesAndStops(t *testing.T) {
	c := newFakeClock()
	g := newAuto(t, Options{Type: TypeSmart}, members(newFake("a"), newFake("b"), newFake("c"), newFake("d"), newFake("e")), c, nil, nil)
	for i := range g.st {
		g.st[i].cold = 50 * ms_
		g.st[i].coldAt = c.Now()
	}
	key := siteKey("slow.example", 443, "tcp")
	e := g.sites.ensure(key, c.Now(), 0)
	for range 3 {
		g.sites.record(key, 0, true, c.Now(), g.cur)
		e.recs[0].quality.latency(time.Second, c.Now())
	}
	for round := range 3 {
		for range 3 {
			e.recs[0].quality.latency(time.Second, c.Now())
		}
		i := g.slowTrialLocked(e, c.Now(), []int{0, 1, 2, 3, 4})
		if i != round+1 {
			t.Fatal("wrong bounded trial", i, round)
		}
		g.sites.record(key, i, true, c.Now(), g.cur)
		e.recs[i].quality.latency(time.Second, c.Now())
		c.Advance(time.Minute)
	}
	for range 3 {
		e.recs[0].quality.latency(time.Second, c.Now())
	}
	if i := g.slowTrialLocked(e, c.Now(), []int{0, 1, 2, 3, 4}); i != -1 || e.quietUntil.IsZero() {
		t.Fatal("slow target kept trying entire pool")
	}
}
func TestV2ObservationCapCancelAndServerFirst(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	start := smartObservationSlots.Load()
	obs := make([]*observer, 0, 4100)
	for range 4100 {
		obs = append(obs, g.smartObserver(0, siteKey("cap.example", 443, "tcp"), 0))
	}
	if smartObservationSlots.Load() > 4096 || smartObservationsDropped.Load() == 0 {
		t.Fatal("observation bound")
	}
	for _, o := range obs {
		o.close()
	}
	if smartObservationSlots.Load() != start {
		t.Fatal("observation slot leak")
	}
	o := g.smartObserver(0, siteKey("first.example", 443, "tcp"), 20*ms_)
	c.Advance(time.Second)
	o.afterRead(1, nil)
	if g.st[0].real.response.count != 0 || g.st[0].real.success != 1 {
		t.Fatal("server-first invented response latency")
	}
	key := siteKey("canceled.example", 443, "tcp")
	o = g.smartObserver(0, key, 0)
	o.beforeWrite(1)
	o.close()
	c.Advance(20 * time.Second)
	if e := g.sites.get(key, c.Now()); e != nil {
		t.Fatal("caller close penalized")
	}
}
func TestV2DialBudgetCancellationAndThreshold(t *testing.T) {
	c := newFakeClock()
	a := newFake("a")
	a.onDial = func(ctx context.Context, _ outbound.Addr) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	g := newAuto(t, Options{Type: TypeSmart, Fixed: "a"}, members(a, newFake("b")), c, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := g.DialTCP(ctx, outbound.Addr{Host: "x.example", Port: 443})
	if !errors.Is(e, context.Canceled) || g.st[0].real.failure != 0 {
		t.Fatal("caller cancel punished member", e)
	}
	for range 5 {
		g.st[0].dial.add(50, c.Now())
	}
	if g.hedgeAfterLocked(0, c.Now()) != 300*ms_ {
		t.Fatal("adaptive threshold")
	}
	g.st[0].dial = decayMean{}
	if g.hedgeAfterLocked(0, c.Now()) != 1500*ms_ {
		t.Fatal("cold threshold")
	}
}
func TestV2AllUnavailableSingleFlightAndNoDirect(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	v2Round(g, c, 100*ms_, 200*ms_)
	g.mu.Lock()
	for i := range g.st {
		g.st[i].probed = true
		g.st[i].probeOK = false
		g.st[i].recovery.observe(false, c.Now())
	}
	g.halfOpen = true
	g.mu.Unlock()
	_, e := g.DialTCP(context.Background(), outbound.Addr{Host: "x.example", Port: 443})
	if e == nil || !strings.Contains(e.Error(), "ALL_UNAVAILABLE") {
		t.Fatal("all-down was not bounded", e)
	}
	for _, m := range g.members {
		if m.(*fakeOut).dialCount() != 0 {
			t.Fatal("parallel half-open storm")
		}
	}
}
func TestV2PreferenceEditKeepsMeasurementsNotChallenge(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	v2Round(g, c, 100*ms_, 200*ms_)
	o := g.smartObserver(0, siteKey("keep.example", 443, "tcp"), 20*ms_)
	o.beforeWrite(1)
	c.Advance(40 * ms_)
	o.afterRead(1, nil)
	newer := newAuto(t, Options{Type: TypeSmart, Fixed: "b", Priority: map[string]float64{"a": 1.5}}, members(newFake("a"), newFake("b")), c, nil, nil)
	newer.InheritLearning(g)
	if newer.st[0].real.response.count != 1 || newer.st[0].cold != 100*ms_ || newer.cfg.priority[0] != 1.5 || newer.Current() != "b" || newer.gate.wins != 0 {
		t.Fatal("preference edit lost measurement or preference")
	}
	key := siteKey("keep.example", 443, "tcp")
	newer.sites.get(key, c.Now()).recs[0].quality.success = 99
	if g.sites.get(key, c.Now()).recs[0].quality.success == 99 {
		t.Fatal("old connection can mutate new learning")
	}
	foreign := newAuto(t, Options{Type: TypeSmart, Probe: &ProbeOptions{URL: "http://different.invalid/"}}, members(newFake("a"), newFake("b")), c, nil, nil)
	foreign.InheritLearning(g)
	if foreign.st[0].probed {
		t.Fatal("changed URL inherited observations")
	}
}
func TestV2UnknownFailureRequiresTwoHostsAndProbe(t *testing.T) {
	for _, hosts := range []int{1, 2} {
		c := newFakeClock()
		p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond})
		p.set("a", 0, true)
		lazy := true
		g := newAuto(t, Options{Type: TypeSmart, Lazy: &lazy}, members(newFake("a")), c, p, nil)
		g.Start(context.Background())
		for i := range hosts {
			g.smartAttemptFailure(0, siteKey(string(rune('a'+i))+".example", 443, "tcp"), false)
		}
		c.Advance(5 * time.Second)
		deadline := time.Now().Add(time.Second)
		for p.count("a") < 1 {
			if time.Now().After(deadline) {
				t.Fatal("no directed verification")
			}
			time.Sleep(time.Millisecond)
		}
		// Lock observes the completed commit, not just the fake prober entrance.
		deadline = time.Now().Add(time.Second)
		for {
			g.mu.Lock()
			down := g.st[0].recovery.down
			step := g.st[0].recoveryStep
			g.mu.Unlock()
			if down || step > 0 {
				if down != (hosts == 2) {
					t.Fatal("ambiguous failure attribution", hosts, down)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("verification not recorded")
			}
			time.Sleep(time.Millisecond)
		}
	}
}
func TestV2BudgetSharedThroughFallbackAndLoadBalance(t *testing.T) {
	for _, kind := range []string{TypeFallback, TypeURLTest, TypeLoadBalance} {
		c := newFakeClock()
		fs := []*fakeOut{newFake("a"), newFake("b"), newFake("c"), newFake("d")}
		for _, f := range fs {
			f.setErr(errors.New("unavailable"))
		}
		inner := newAuto(t, Options{Name: "inner", Type: kind}, members(fs[0], fs[1], fs[2]), c, nil, nil)
		outer := newAuto(t, Options{Name: "outer", Type: TypeSmart}, []outbound.Outbound{inner, fs[3]}, c, nil, nil)
		outer.RecordProbeRound([]ProbeSample{{Name: "inner", Latency: 50 * ms_, At: c.Now()}, {Name: "d", Latency: 200 * ms_, At: c.Now()}})
		_, _ = outer.DialTCP(context.Background(), outbound.Addr{Host: "x.example", Port: 443})
		count := 0
		for _, f := range fs {
			count += f.dialCount()
		}
		if count > 3 {
			t.Fatal("nested non-smart bypassed attempt budget", kind, count)
		}
	}
}
func TestV2NestedProbeDoesNotLearnSitesOrRealSamples(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	v2Round(g, c, 50*ms_, 100*ms_)
	conn, e := g.DialTCP(WithProbeMeasurement(context.Background(), &ProbeMeasurement{}), outbound.Addr{Host: "synthetic.invalid", Port: 443})
	if e != nil {
		t.Fatal(e)
	}
	conn.Close()
	if g.sites.len() != 0 || g.mostUsedLocked(c.Now()) != "" || g.st[0].real.response.count != 0 {
		t.Fatal("nested probe became business learning")
	}
}
func TestV2InFlightOldProbeCannotEraseNewRealFailure(t *testing.T) {
	c := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond})
	g := newAuto(t, Options{Type: TypeFallback}, members(newFake("a")), c, p, nil)
	sample := g.measuredProbe(context.Background(), 0)
	g.realFailure(0, "x.example", false)
	g.realFailure(0, "x.example", false)
	g.mu.Lock()
	g.addProbeLocked(0, sample)
	g.mu.Unlock()
	if g.fallbackUpTest(0) || g.st[0].consec != 2 {
		t.Fatal("old successful probe erased fresher real failures")
	}
}
func TestV2RecoveryEpochClearsPenaltyAndRepeatedCooldown(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	for count, want := range []time.Duration{30, 60, 120, 300, 300} {
		g.mu.Lock()
		g.smartFailLocked(0, c.Now())
		until := g.st[0].openUntil
		g.mu.Unlock()
		if until.Sub(c.Now()) != want*time.Second {
			t.Fatal(count, until.Sub(c.Now()), want)
		}
		c.Advance(time.Second)
		g.RecordProbe("a", 50*ms_, c.Now(), nil)
		c.Advance(5 * time.Second)
		g.RecordProbe("a", 50*ms_, c.Now(), nil)
		c.Advance(5 * time.Second)
		if !g.fallbackUpTest(0) || g.st[0].real.failure != 0 || !g.st[0].openUntil.IsZero() {
			t.Fatal("recovery did not begin fresh epoch")
		}
	}
}
func TestV2ClockRollbackAndSamplingLimit(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	for range 3 {
		v2Round(g, c, 300*ms_, 400*ms_)
	}
	c.Advance(-10 * time.Second)
	if _, n := g.medianLocked(0, c.Now()); n != 0 {
		t.Fatal("future evidence usable after clock rollback")
	}
	q := switchGate{}
	q.reset()
	g.evidence++
	if g.gateLocked(&q, 0, 1, 300, 100, true, c.Now().Add(time.Minute), c.Now(), c.Now(), c.Now()) {
		t.Fatal("clock rollback bypassed dwell")
	}
	quality := quality{}
	for range 100 {
		quality.latency(100*ms_, c.Now())
		quality.result(true, c.Now(), true)
	}
	quality.result(false, c.Now(), true)
	if quality.response.count != 20 || quality.failure != 1 {
		t.Fatal("latency sampling dropped hard fault or exceeded cap")
	}
}
func TestV2CallerCloseReleasesSiteRecoveryAndExploration(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	key := siteKey("closed.example", 443, "tcp")
	g.sites.record(key, 0, false, c.Now(), g.cur)
	e := g.sites.get(key, c.Now())
	e.recs[0].halfOpen = true
	e.trialBusy = true
	g.exploring = key
	e.flight = 123
	o := g.smartObserver(0, key, 0, 123)
	o.close()
	if e.recs[0].halfOpen || e.trialBusy || g.exploring != "" {
		t.Fatal("caller close leaked trial / half-open permit")
	}
	if e.recs[0].quality.failure != 0 {
		t.Fatal("close counted as a new failure")
	}
}
func TestV2OlderFlowCannotReleaseOtherValidationFlight(t *testing.T) {
	g, c := v2Group(t, TypeSmart)
	key := siteKey("halfopen.example", 443, "tcp")
	g.sites.record(key, 0, false, c.Now(), g.cur)
	g.sites.record(key, 1, false, c.Now(), g.cur)
	c.Advance(31 * time.Second)
	_ = g.smartOrderLocked(key, c.Now())
	e := g.sites.get(key, c.Now())
	flight := e.flight
	if flight == 0 {
		t.Fatal("no validation permit")
	}
	_ = g.smartOrderLocked(key, c.Now())
	if e.flight != flight || e.recs[1].halfOpen {
		t.Fatal("two half-open validations for one site")
	}
	old := g.smartObserver(0, key, 0)
	old.close()
	if e.flight != flight {
		t.Fatal("unrelated caller released validation")
	}
	g.releaseSiteFlight(key, flight)
	_ = g.smartOrderLocked(key, c.Now())
	next := e.flight
	g.releaseSiteFlight(key, flight)
	if next == 0 || next == flight || e.flight != next {
		t.Fatal("old owner released newer validation")
	}
	g.cfg.fixed = "a"
	g.cfg.fixedIndex = 0
	g.releaseSiteFlight(key, next)
	g.sites.record(key, 0, true, c.Now(), g.cur)
	if g.smartOrderLocked(key, c.Now())[0] != 0 {
		t.Fatal("other-member half-open bypassed healthy soft fixed")
	}
	g.sites.record(key, 0, false, c.Now(), g.cur)
	c.Advance(31 * time.Second)
	_ = g.smartOrderLocked(key, c.Now())
	if !e.recs[0].halfOpen || e.flight == 0 {
		t.Fatal("soft fixed site recovery could not validate naturally")
	}
}
