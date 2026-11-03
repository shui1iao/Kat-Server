package group

import (
	"container/list"
	"golang.org/x/net/idna"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Smart v2: separated cold probe, dial, TCP transport-first-response and UDP
// health. Scores are equivalent decision costs, never claimed to be HTTPS
// application TTFB, bandwidth or retransmission estimates. State is RAM only.
const (
	smartAlpha           = 0.3 // old test source compatibility; not a v2 algorithm knob
	smartPenaltyBaseMS   = 300.0
	smartPenaltyCapMS    = 10000.0
	smartPenaltyHalfLife = 120 * time.Second
	smartSwitchRatio     = 0.8
	smartSwitchMinMS     = 30.0
	smartDwell           = 60 * time.Second
	smartSiteTTL         = 10 * time.Minute
	smartSiteCap         = 2048
	smartSiteSlack       = 1.5
	smartIdleFactor      = 5
)

func msDur(v float64) time.Duration { return time.Duration(math.Round(v * float64(time.Millisecond))) }

type decayMean struct {
	sum, count, dev float64
	at              time.Time
}

func (m decayMean) value(now time.Time) (mean, n, jitter float64) {
	if m.count < 0.25 || now.Sub(m.at) > 10*time.Minute {
		return 0, 0, 0
	}
	d := math.Exp2(-float64(max(time.Duration(0), now.Sub(m.at))) / float64(120*time.Second))
	n = m.count * d
	if n < 0.25 {
		return 0, 0, 0
	}
	return m.sum / m.count, n, m.dev / m.count
}
func (m *decayMean) add(v float64, now time.Time) {
	mean, n, _ := m.value(now)
	if n == 0 {
		*m = decayMean{sum: v, count: 1, at: now}
		return
	}
	d := math.Exp2(-float64(max(time.Duration(0), now.Sub(m.at))) / float64(120*time.Second))
	m.sum = m.sum*d + v
	m.count = m.count*d + 1
	m.dev = m.dev*d + math.Abs(v-mean)
	m.at = now
}

type resultBucket struct {
	minute          int64
	success, failed int
}
type quality struct {
	response         decayMean
	success, failure float64
	at               time.Time
	sampleSecond     int64
	inSecond         int
	buckets          [10]resultBucket
}

func (q quality) outcomes(now time.Time) (s, f float64) {
	if q.at.IsZero() || now.Sub(q.at) > 10*time.Minute {
		return 0, 0
	}
	d := math.Exp2(-float64(max(time.Duration(0), now.Sub(q.at))) / float64(120*time.Second))
	return q.success * d, q.failure * d
}
func (q *quality) result(ok bool, at time.Time, attributed bool) {
	s, f := q.outcomes(at)
	q.success, q.failure, q.at = s, f, at
	if attributed {
		if ok {
			q.success++
		} else {
			q.failure++
		}
	}
	minute := at.Unix() / 60
	b := &q.buckets[minute%10]
	if b.minute != minute {
		*b = resultBucket{minute: minute}
	}
	if ok {
		b.success++
	} else {
		b.failed++
	}
}
func (q *quality) latency(v time.Duration, at time.Time) {
	second := at.Unix()
	if q.sampleSecond != second {
		q.sampleSecond = second
		q.inSecond = 0
	}
	q.inSecond++
	if q.inSecond <= 20 {
		q.response.add(math.Max(1, math.Min(10000, ms(v))), at)
	}
}
func (q quality) rate(now time.Time) (*float64, int) {
	s, f := 0, 0
	minute := now.Unix() / 60
	for _, b := range q.buckets {
		if b.minute <= minute && minute-b.minute < 10 {
			s += b.success
			f += b.failed
		}
	}
	if s+f < 3 {
		return nil, s + f
	}
	v := float64(s) / float64(s+f)
	return &v, s + f
}

type ScoreParts struct {
	ResponseMS float64  `json:"response_ms"`
	FailureMS  float64  `json:"failure_ms"`
	JitterMS   float64  `json:"jitter_ms"`
	ProbeMS    *float64 `json:"probe_ms"`
	RealMS     *float64 `json:"real_ms"`
	RealShare  float64  `json:"real_share"`
	Weight     float64  `json:"weight"`
}

func (g *autoGroup) scorePartsLocked(i int, site *siteEntry, now time.Time) (ScoreParts, float64, bool) {
	s := &g.st[i]
	r, n, j := s.real.response.value(now)
	p := ScoreParts{Weight: g.cfg.priority[i]}
	age := max(2*g.cfg.interval, 10*time.Minute)
	age = min(age, 30*time.Minute)
	if !s.coldAt.IsZero() && now.Sub(s.coldAt) <= age {
		v := ms(s.cold)
		p.ProbeMS = &v
	}
	if n > 0 {
		p.RealMS = &r
		p.RealShare = n / (n + 5)
	}
	_, probeCount := g.medianLocked(i, now)
	known := n >= 3 || probeCount >= 3
	switch {
	case n > 0 && p.ProbeMS != nil:
		p.ResponseMS = p.RealShare*r + (1-p.RealShare)**p.ProbeMS
	case n > 0:
		p.ResponseMS = r
	case p.ProbeMS != nil:
		p.ResponseMS = *p.ProbeMS
	default:
		p.ResponseMS = ms(g.cfg.timeout)
	}
	a, b := s.real.outcomes(now)
	q := (b + 0.04) / (a + b + 2)
	if site != nil && g.cfg.scope == "site" {
		if sr := site.recs[i]; sr != nil {
			rr, nn, jj := sr.quality.response.value(now)
			beta := nn / (nn + 5)
			if nn > 0 {
				p.ResponseMS = beta*rr + (1-beta)*p.ResponseMS
				j = beta*jj + (1-beta)*j
			}
			ss, ff := sr.quality.outcomes(now)
			q = (ff + 5*q) / (ss + ff + 5)
		}
	}
	p.FailureMS, p.JitterMS = 2000*q, 0.25*j
	return p, n, known
}
func (g *autoGroup) scoreLocked(i int, now time.Time) float64 {
	p, _, _ := g.scorePartsLocked(i, nil, now)
	return (p.ResponseMS + p.FailureMS + p.JitterMS) * p.Weight
}
func (g *autoGroup) siteScoreLocked(i int, e *siteEntry, now time.Time) float64 {
	p, _, _ := g.scorePartsLocked(i, e, now)
	return (p.ResponseMS + p.FailureMS + p.JitterMS) * p.Weight
}
func (g *autoGroup) penaltyLocked(i int, now time.Time) float64 {
	p, _, _ := g.scorePartsLocked(i, nil, now)
	return p.FailureMS
}

// These narrow entry points remain for observer/probe callers, but never mix
// active latency into real response history.
func (g *autoGroup) smartSuccessLocked(i int, lat time.Duration, sample bool, now time.Time) {
	s := &g.st[i]
	s.consec = 0
	s.real.result(true, now, true)
	if sample {
		s.real.latency(lat, now)
	}
}
func (g *autoGroup) smartFailLocked(i int, now time.Time) {
	g.markOpenLocked(i, now)
	g.st[i].observationEpoch++
	g.st[i].real.result(false, now, true)
	g.st[i].consec++
	g.hardDirty = true
	g.st[i].recovery.observe(false, now)
	g.scheduleRecoveryLocked(i, now)
}
func (g *autoGroup) smartRankLocked(now time.Time) ([]int, []float64) {
	if len(g.rankOrder) == len(g.st) && !g.hardDirty && now.Sub(g.rankAt) >= 0 && now.Sub(g.rankAt) < time.Second {
		return g.rankOrder, g.rankScores
	}

	order := make([]int, len(g.st))
	score := make([]float64, len(g.st))
	for i := range order {
		order[i] = i
		score[i] = g.scoreLocked(i, now)
	}
	sort.SliceStable(order, func(a, b int) bool {
		ia, ib := order[a], order[b]
		ua, ub := g.fallbackUpLocked(ia), g.fallbackUpLocked(ib)
		if ua != ub {
			return ua
		}
		return score[ia] < score[ib]
	})
	g.rankOrder, g.rankScores, g.rankAt, g.hardDirty = order, score, now, false
	return order, score
}
func (g *autoGroup) matureLocked(i int, e *siteEntry, now time.Time) bool {
	_, n, _ := g.st[i].real.response.value(now)
	if e != nil {
		n = 0
		if r := e.recs[i]; r != nil {
			_, n, _ = r.quality.response.value(now)
		}
	}
	// Probe priors inform cost, never business-performance maturity.
	return n >= 3
}

// Only a newly accepted full round may bootstrap. An earlier all-down round
// must not allow a later partial/fastest result to become an automatic choice.
func (g *autoGroup) smartBootstrapLocked(now time.Time) {
	best := -1
	for i, s := range g.st {
		if s.probeOK && g.fallbackUpLocked(i) && (best < 0 || float64(s.probeLat)*g.cfg.priority[i] < float64(g.st[best].probeLat)*g.cfg.priority[best]) {
			best = i
		}
	}
	if best < 0 {
		return
	}
	g.switchToLocked(best, now)
	g.cold = false
	close(g.firstReady)
	for _, e := range g.sitesElementsLocked() {
		if len(e.recs) == 0 {
			e.current, e.since = best, now
			e.gate.reset()
		}
	}
}

// business is true only while accepting a new real access observation.
// Probes may bootstrap or change health, but cannot promote performance.
func (g *autoGroup) smartReevalLocked(now time.Time, business bool) {
	if g.cold {
		return
	}
	order, score := g.smartRankLocked(now)
	b := order[0]
	if !g.fallbackUpLocked(b) {
		return
	}
	if !g.fallbackUpLocked(g.cur) {
		g.switchToLocked(b, now)
		g.gate.reset()
		return
	}
	if g.cold || !business || now.Before(g.freezeUntil) {
		return
	}
	if g.gateLocked(&g.gate, g.cur, b, score[g.cur], score[b], g.matureLocked(g.cur, nil, now) && g.matureLocked(b, nil, now), g.curSince, now, g.memberEvidenceLocked(g.cur, nil), g.memberEvidenceLocked(b, nil)) {
		g.switchToLocked(b, now)
		g.gate.reset()
	}
}

// Site keys contain only normalized host/IP, network and port, never URL,
// headers or payload. UDP ListenPacket has no target: it remains group scoped.
func siteKey(host string, port uint16, network string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip, e := netip.ParseAddr(host); e == nil {
		host = ip.Unmap().String()
	} else if h, e := idna.Lookup.ToASCII(host); e == nil {
		host = h
	}
	return network + "|" + net.JoinHostPort(host, strconv.Itoa(int(port)))
}
func (g *autoGroup) smartOrderLocked(key string, now time.Time) []int {
	order, _ := g.smartRankLocked(now)
	if key == "" {
		return orderCurrent(order, g.cur)
	}
	e := g.sites.ensure(key, now, g.cur)
	e.last = now
	choice := g.cur
	if g.cfg.scope == "site" {
		g.siteReevalLocked(e, now, false)
		choice = e.current
	}
	if i, ok := g.fixedHealthyLocked(); ok && !e.failedRecently(i, now) {
		choice = i
	} else if e.failedRecently(choice, now) || !g.fallbackUpLocked(choice) {
		for _, i := range order {
			if g.fallbackUpLocked(i) && !e.failedRecently(i, now) {
				choice = i
				break
			}
		}
	}
	// At most one natural half-open per site. Generic probes never clear site
	// failures. No synthetic request is made to a user's destination.
	special := false
	half := -1
	fixedIndex, fixedHealthy := g.fixedHealthyLocked()
	for i, r := range e.recs {
		if e.flight == 0 && (!fixedHealthy || i == fixedIndex) && !r.failAt.IsZero() && !now.Before(r.retryAt) && !r.halfOpen && g.fallbackUpLocked(i) && (half < 0 || i < half) {
			half = i
		}
	}
	if half >= 0 {
		e.recs[half].halfOpen = true
		special = true
		choice = half
	}

	if e.flight == 0 && !special && g.cfg.scope == "site" && g.cfg.fixed == "" {
		if trial := g.slowTrialLocked(e, now, order); trial >= 0 {
			choice = trial
			special = true
		}
		if !special && !e.stable && g.cfg.exploration > 0 && g.random() < g.cfg.exploration && g.exploring == "" {
			best := g.siteScoreLocked(order[0], e, now)
			for _, i := range order {
				if i != choice && g.fallbackUpLocked(i) && g.siteScoreLocked(i, e, now) <= 1.15*best+30 {
					choice = i
					g.exploring = key
					special = true
					break
				}
			}
		}
	}
	if special {
		g.siteFlightSeq++
		e.flight = g.siteFlightSeq
	}
	// Group ranking is cached. A site scores only a bounded sparse set,
	// never sorts all 1024 configured members for every new connection.
	pool := map[int]bool{}
	for _, i := range order {
		if i != choice && g.fallbackUpLocked(i) {
			pool[i] = true
			if len(pool) >= 8 {
				break
			}
		}
	}
	for i := range e.recs {
		if i != choice && g.fallbackUpLocked(i) {
			pool[i] = true
		}
	}
	rest := make([]int, 0, len(pool))
	for i := range pool {
		rest = append(rest, i)
	}
	sort.Slice(rest, func(a, b int) bool {
		ia, ib := rest[a], rest[b]
		fa, fb := e.failedRecently(ia, now), e.failedRecently(ib, now)
		if fa != fb {
			return !fa
		}
		sa, sb := g.siteScoreLocked(ia, e, now), g.siteScoreLocked(ib, e, now)
		if sa == sb {
			return ia < ib
		}
		return sa < sb
	})
	out := []int{choice}
	out = append(out, rest[:min(maxAttempts-1, len(rest))]...)

	return out
}
func (g *autoGroup) siteReevalLocked(e *siteEntry, now time.Time, business bool) {
	best := e.current
	candidates := map[int]bool{e.current: true}
	if order, _ := g.smartRankLocked(now); len(order) > 0 {
		candidates[order[0]] = true
	}
	for i := range e.recs {
		candidates[i] = true
	}
	for i := range candidates {
		if !g.fallbackUpLocked(i) || e.failedRecently(i, now) {
			continue
		}
		if !g.fallbackUpLocked(best) || e.failedRecently(best, now) || g.siteScoreLocked(i, e, now) < g.siteScoreLocked(best, e, now) {
			best = i
		}
	}
	if !g.fallbackUpLocked(e.current) || e.failedRecently(e.current, now) {
		e.current = best
		e.since = now
		e.gate.reset()
		return
	}
	if business && !now.Before(g.freezeUntil) && g.gateLocked(&e.gate, e.current, best, g.siteScoreLocked(e.current, e, now), g.siteScoreLocked(best, e, now), g.matureLocked(e.current, e, now) && g.matureLocked(best, e, now), e.since, now, g.memberEvidenceLocked(e.current, e), g.memberEvidenceLocked(best, e)) {
		e.current = best
		e.since = now
		e.stable = true
		e.gate.reset()
	}
}
func (g *autoGroup) reevaluateSitesLocked(now time.Time) {
	for _, e := range g.sitesElementsLocked() {
		g.siteReevalLocked(e, now, false)
	}
}
func (g *autoGroup) sitesElementsLocked() []*siteEntry {
	if g.sites == nil {
		return nil
	}
	out := make([]*siteEntry, 0, g.sites.len())
	for _, el := range g.sites.m {
		out = append(out, el.Value.(*siteEntry))
	}
	return out
}
func (g *autoGroup) slowTrialLocked(e *siteEntry, now time.Time, order []int) int {
	if e.trialBusy || now.Before(e.quietUntil) || now.Sub(e.lastTrial) < time.Minute {
		return -1
	}
	r := e.recs[e.current]
	if r == nil {
		return -1
	}
	mean, n, _ := r.quality.response.value(now)
	if n < 3 {
		return -1
	}
	group := g.st[e.current].real.response
	_, gn, _ := group.value(now)
	reference := float64(0)
	if gn-n >= 3 {
		gs := group.sum * math.Exp2(-float64(max(time.Duration(0), now.Sub(group.at)))/float64(120*time.Second))
		ss := r.quality.response.sum * math.Exp2(-float64(max(time.Duration(0), now.Sub(r.quality.response.at)))/float64(120*time.Second))
		reference = (gs - ss) / (gn - n)
	} else if p, _, _ := g.scorePartsLocked(e.current, nil, now); p.ProbeMS != nil {
		reference = *p.ProbeMS
	}
	if reference <= 0 || mean <= max(2.5*reference, reference+300) {
		return -1
	}
	if len(e.tried) >= 3 {
		e.quietUntil = now.Add(10 * time.Minute)
		return -1
	}
	for _, i := range order {
		if i != e.current && !e.tried[i] && g.fallbackUpLocked(i) && !e.failedRecently(i, now) {
			e.tried[i] = true
			e.lastTrial = now
			e.trialBusy = true
			return i
		}
	}
	return -1
}

type siteRec struct {
	okAt, failAt, retryAt time.Time
	failures              int
	halfOpen              bool
	quality               quality
}
type siteEntry struct {
	flight                uint64
	key                   string
	recs                  map[int]*siteRec
	current               int
	since, last           time.Time
	gate                  switchGate
	stable, trialBusy     bool
	tried                 map[int]bool
	lastTrial, quietUntil time.Time
}

func (e *siteEntry) failedRecently(i int, now time.Time) bool {
	r := e.recs[i]
	return r != nil && !r.failAt.IsZero() && now.Sub(r.failAt) < smartSiteTTL
}
func (e *siteEntry) succeededRecently(i int, now time.Time) bool {
	r := e.recs[i]
	return r != nil && !r.okAt.IsZero() && now.Sub(r.okAt) < smartSiteTTL && r.failAt.IsZero()
}

type siteCache struct {
	scratch *siteEntry
	cap     int
	ll      *list.List
	m       map[string]*list.Element
}

func newSiteCache(n int) *siteCache {
	return &siteCache{cap: n, ll: list.New(), m: map[string]*list.Element{}}
}
func (c *siteCache) get(key string, now time.Time) *siteEntry {
	el := c.m[key]
	if el == nil {
		if c.scratch != nil && c.scratch.key == key && now.Sub(c.scratch.last) < smartSiteTTL {
			return c.scratch
		}
		return nil
	}
	e := el.Value.(*siteEntry)
	if now.Sub(e.last) >= smartSiteTTL {
		c.ll.Remove(el)
		smartSiteSlots.Add(-1)
		delete(c.m, key)
		return nil
	}
	c.ll.MoveToFront(el)
	return e
}

var smartSiteSlots atomic.Int64

const maxProcessSites = 4096

func (c *siteCache) ensure(key string, now time.Time, current int) *siteEntry {
	if e := c.get(key, now); e != nil {
		return e
	}
	e := &siteEntry{key: key, recs: map[int]*siteRec{}, current: current, since: now, last: now, tried: map[int]bool{}}
	e.gate.reset()
	if smartSiteSlots.Add(1) > maxProcessSites {
		smartSiteSlots.Add(-1)
		if old := c.ll.Back(); old != nil {
			c.ll.Remove(old)
			delete(c.m, old.Value.(*siteEntry).key)
			smartSiteSlots.Add(-1)
		} else {
			c.scratch = e
			return e
		}
		smartSiteSlots.Add(1)
	}
	c.m[key] = c.ll.PushFront(e)
	for c.ll.Len() > c.cap {
		old := c.ll.Back()
		c.ll.Remove(old)
		smartSiteSlots.Add(-1)
		delete(c.m, old.Value.(*siteEntry).key)
	}
	return e
}

// record retains an existing site's choice. When an old flow reports after
// eviction, seed the rebuilt entry from the group's current decision, just as
// a new dial does; neither member zero nor this single reported member is a
// new learned preference.
func (c *siteCache) record(key string, i int, ok bool, now time.Time, current int) {
	e := c.ensure(key, now, current)
	e.last = now
	r := e.recs[i]
	if r == nil {
		if len(e.recs) >= 8 {
			old := -1
			var at time.Time
			for j, v := range e.recs {
				t := maxTime(v.okAt, v.failAt)
				if old < 0 || t.Before(at) {
					old = j
					at = t
				}
			}
			delete(e.recs, old)
		}
		r = &siteRec{}
		e.recs[i] = r
	}
	r.halfOpen = false
	e.trialBusy = false
	if ok {
		r.okAt = now
		r.failAt = time.Time{}
		r.failures = 0
		r.retryAt = time.Time{}
	} else {
		r.failAt = now
		r.failures++
		r.retryAt = now.Add(circuitBackoff(r.failures))
	}
}
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
func (c *siteCache) len() int { return c.ll.Len() }
func defaultRandom() float64  { return rand.Float64() }

func (g *autoGroup) memberEvidenceLocked(i int, e *siteEntry) time.Time {
	if g.cfg.kind != TypeSmart {
		return g.st[i].probeAt
	}
	if e != nil {
		if r := e.recs[i]; r != nil {
			return r.quality.response.at
		}
		return time.Time{}
	}
	return g.st[i].real.response.at
}

func (c *siteCache) clear() {
	c.scratch = nil
	smartSiteSlots.Add(-int64(c.ll.Len()))
	c.ll.Init()
	clear(c.m)
}

func (g *autoGroup) markOpenLocked(i int, now time.Time) {
	s := &g.st[i]
	if !s.recovery.down {
		s.openCount++
		s.openUntil = now.Add(circuitBackoff(s.openCount))
	}
}

func circuitBackoff(n int) time.Duration {
	return []time.Duration{30, 60, 120, 300}[min(max(n-1, 0), 3)] * time.Second
}
