package group

import (
	"context"
	"errors"
	"time"
)

// Stability is independent from the display latency and from health. One
// transaction contributes at most one sample (cold/warm HEADs are not rounds).
type latencySample struct {
	at    time.Time
	value time.Duration
}
type recovery struct {
	down                  bool
	first, last, observed time.Time
	successes             int
}

func (r *recovery) observe(ok bool, at time.Time) bool {
	if ok && (at.Before(r.observed) || (at.Equal(r.observed) && r.successes > 0)) {
		return !r.down
	}
	r.observed = at
	if !ok {
		r.down = true
		r.first = time.Time{}
		r.last = time.Time{}
		r.successes = 0
		return false
	}
	if !r.down {
		return true
	}
	if r.first.IsZero() {
		r.first = at
		r.last = at
		r.successes = 1
	} else if at.Sub(r.last) >= 5*time.Second {
		r.successes++
		r.last = at
	}
	return r.ready(at)
}
func (r *recovery) ready(now time.Time) bool {
	if r.down && r.successes >= 2 && now.Sub(r.first) >= 10*time.Second {
		r.down = false
	}
	return !r.down
}

type switchGate struct {
	currentAt, bestAt time.Time
	candidate         int
	wins              int
	evidence          uint64
	since             time.Time
}

func (q *switchGate) reset() {
	q.candidate = -1
	q.wins = 0
	q.currentAt = time.Time{}
	q.bestAt = time.Time{}
}
func (g *autoGroup) gateLocked(q *switchGate, current, best int, currentCost, bestCost float64, mature bool, since, now, currentAt, bestAt time.Time) bool {
	if best == current || !mature || currentCost-bestCost <= ms(g.cfg.tolerance) || bestCost > (1-g.cfg.relative)*currentCost {
		q.reset()
		q.evidence = g.evidence
		return false
	}
	if q.candidate != best {
		q.reset()
		q.candidate = best
	}
	fresh := g.evidence != q.evidence && currentAt.After(q.currentAt) && bestAt.After(q.bestAt)
	if fresh {
		q.currentAt, q.bestAt = currentAt, bestAt
		q.wins++
		q.evidence = g.evidence
	}
	return (g.cfg.kind != TypeSmart || fresh) && q.wins >= g.cfg.confirms && now.Sub(since) >= g.cfg.dwell
}
func (g *autoGroup) medianLocked(i int, now time.Time) (time.Duration, int) {
	window := min(30*time.Minute, max(3*g.cfg.interval, 30*time.Second))
	s := g.st[i].samples
	var buffer [3]time.Duration
	vals := buffer[:0]
	for _, v := range s {
		if now.Sub(v.at) >= 0 && now.Sub(v.at) <= window {
			vals = append(vals, v.value)
		}
	}
	if len(vals) == 0 {
		return 0, 0
	}
	for i := 1; i < len(vals); i++ {
		for j := i; j > 0 && vals[j] < vals[j-1]; j-- {
			vals[j], vals[j-1] = vals[j-1], vals[j]
		}
	}
	return vals[len(vals)/2], len(vals)
}
func (g *autoGroup) addProbeLocked(i int, r ProbeSample) {
	// Admission/dependency failures never observed a target. This guard also
	// covers the recovery path, which does not go through acceptSamplesLocked.
	if r.At.IsZero() {
		return
	}
	s := &g.st[i]
	if r.versioned && r.observationEpoch != s.observationEpoch {
		return
	}
	if !r.Started.IsZero() && r.Started.Before(s.healthAt) {
		return
	}
	g.hardDirty = true
	s.observationEpoch++
	s.probed, s.probeOK, s.probeAt, s.probeLat = true, r.Err == nil, r.At, 0
	s.healthAt = r.At
	wasDown := s.recovery.down
	if r.Err != nil && g.cfg.kind == TypeSmart {
		g.markOpenLocked(i, r.At)
	}
	healthy := s.recovery.observe(r.Err == nil, r.At)
	if r.Err != nil {
		s.samples = nil
		s.consec = max(1, s.consec)
		g.scheduleRecoveryLocked(i, r.At)
	} else {
		s.consec = 0
		s.probeFailures = 0
		s.probeLat = r.Latency
		cold := r.ColdLatency
		if cold <= 0 {
			cold = r.Latency
		}
		value := r.Latency
		if g.cfg.kind == TypeSmart {
			value = cold
		}
		s.samples = append(s.samples, latencySample{r.At, value})
		if len(s.samples) > 3 {
			s.samples = s.samples[len(s.samples)-3:]
		}

		if g.cfg.kind == TypeSmart {
			s.coldAt = r.At
			s.cold, _ = g.medianLocked(i, r.At)
		}
	}
	if wasDown && healthy && g.cfg.kind == TypeSmart {
		s.real = quality{}
		s.dial = decayMean{}
		s.epoch = r.At
		s.openUntil = time.Time{}
	}
}

// The evidence set is committed atomically, including manual rounds. Partial
// node measurements refresh priors/health but cannot themselves win a round.
func (g *autoGroup) acceptSamplesLocked(results []ProbeSample) {
	independentFallbackRound := g.fallbackIndependentRoundLocked(results)
	now := g.lastRound
	accepted := map[int]bool{}
	allFailed := len(results) > 1
	for _, r := range results {
		if r.At.IsZero() || r.Err == nil {
			allFailed = false
		}
	}
	if allFailed {
		g.freezeUntil = g.clk.Now().Add(10 * time.Second)
	}
	for _, r := range results {
		for i, n := range g.cfg.members {
			if n != r.Name {
				continue
			}
			s := &g.st[i]
			if r.At.IsZero() || (!s.probeAt.IsZero() && !r.At.After(s.probeAt)) {
				break
			}
			// Correlated failures are observations, not proof that the entire pool is
			// broken. Keep existing usable health; freeze performance promotion.
			if allFailed && s.probeOK {
				s.probeAt = r.At
				accepted[i] = true
				break
			}
			if r.versioned && r.observationEpoch != s.observationEpoch {
				break
			}
			if !r.Started.IsZero() && r.Started.Before(s.healthAt) {
				break
			}
			// Fallback health failure requires the configured number of independent
			// complete rounds. Preserve the last usable state on one-off noise; do
			// not feed that tentative failure to recovery or the business counter.
			if g.cfg.kind == TypeFallback {
				if r.Err == nil {
					s.probeFailures = 0
				} else if !s.recovery.down && (!s.probed || s.probeOK) {
					if !independentFallbackRound {
						break
					}
					s.probeFailures++
					if s.probeFailures < g.cfg.maxFailed {
						// Do not fabricate a fresh successful RTT from tentative failure.
						s.healthAt = r.At
						s.observationEpoch++
						accepted[i] = true
						if r.At.After(now) {
							now = r.At
						}
						g.scheduleFallbackConfirmationLocked()
						break
					}
				}
			}
			g.addProbeLocked(i, r)
			accepted[i] = true
			if r.At.After(now) {
				now = r.At
			}
			break
		}
	}
	if len(accepted) == 0 {
		return
	}
	if len(accepted) == len(g.members) {
		g.markCompleteLocked()
		g.hasRound = true
		if g.cfg.kind == TypeSmart && g.cold {
			g.smartBootstrapLocked(now)
		}
	}
	g.lastRound = now
	// A pair must include current and the best challenger. A one-node result
	// must not manufacture evidence against an old value on the other side.
	if g.cfg.kind != TypeSmart {
		g.evidence++
	}
	if g.cfg.kind != TypeSmart && len(accepted) < 2 {
		g.gate.evidence = g.evidence
		for _, el := range g.sitesElementsLocked() {
			el.gate.evidence = g.evidence
		}
	}
	g.reevaluateLocked(now)
	if g.cfg.kind == TypeSmart {
		g.reevaluateSitesLocked(now)
	}
	g.scheduleChallengeLocked(now)
}

var backgroundProbeSlots = make(chan struct{}, probeConcurrency)

func (g *autoGroup) measuredProbe(ctx context.Context, i int) ProbeSample {
	sample := ProbeSample{Name: g.cfg.members[i]}
	// One bounded preflight window: dependency readiness and admission share
	// the configured timeout, independently of the real target HTTP window.
	// In particular, NEVER hold a slot while waiting for a cold child's round.
	prep, stopPrep := context.WithTimeout(ctx, g.cfg.timeout)
	defer stopPrep()
	if g.cfg.prepare != nil {
		if err := g.cfg.prepare(prep, sample.Name); err != nil {
			sample.Err = err
			return sample // At remains unset: not target health evidence
		}
	}
	select {
	case backgroundProbeSlots <- struct{}{}:
		defer func() { <-backgroundProbeSlots }()
	case <-prep.Done():
		sample.Err = prep.Err()
		return sample
	}
	if err := prep.Err(); err != nil {
		sample.Err = err
		return sample
	}
	stopPrep()
	// The lifecycle still bounds/cancels this window, but local queueing and
	// dependency work cannot consume the target's configured HTTP timeout.
	pctx, cancel := context.WithTimeout(ctx, g.cfg.timeout)
	defer cancel()
	g.mu.Lock()
	sample.observationEpoch = g.st[i].observationEpoch
	sample.versioned = true
	g.mu.Unlock()
	sample.Started = g.clk.Now()
	m := &ProbeMeasurement{}
	pctx = WithProbeMeasurement(pctx, m)
	pctx = context.WithValue(pctx, preparedProbeKey{}, true)
	sample.Latency, sample.Err = g.probe(pctx, g.members[i])
	sample.ColdLatency = m.Cold
	if !errors.Is(sample.Err, errProbeDependencyUnready) && !errors.Is(sample.Err, context.Canceled) {
		sample.At = g.clk.Now()
	}
	return sample
}
func (g *autoGroup) challengeCandidateLocked(now time.Time) int {
	if g.cfg.kind != TypeURLTest {
		return -1
	}
	cur, best := g.cur, -1
	for i := range g.st {
		if i == cur || !g.fallbackUpLocked(i) {
			continue
		}
		if best < 0 || g.potentialCostLocked(i, now) < g.potentialCostLocked(best, now) {
			best = i
		}
	}
	if best < 0 || !g.fallbackUpLocked(cur) {
		return -1
	}
	a, b := g.comparisonCostLocked(cur, now), g.potentialCostLocked(best, now)
	if a-b > ms(g.cfg.tolerance) && b <= (1-g.cfg.relative)*a {
		return best
	}
	return -1
}

// A single lower value can request evidence, but cannot win the gate.
func (g *autoGroup) potentialCostLocked(i int, now time.Time) float64 {
	cost := g.comparisonCostLocked(i, now)
	s := g.st[i]
	if !s.probeOK || len(s.samples) == 0 {
		return cost
	}
	recent := ms(s.samples[len(s.samples)-1].value) * g.cfg.priority[i]
	if g.cfg.kind == TypeSmart {
		recent += g.penaltyLocked(i, now) * g.cfg.priority[i]
	}
	return min(cost, recent)
}
func (g *autoGroup) comparisonCostLocked(i int, now time.Time) float64 {
	if g.cfg.kind == TypeSmart {
		return g.scoreLocked(i, now)
	}
	v, n := g.medianLocked(i, now)
	if n == 0 {
		return ms(g.cfg.timeout) * g.cfg.priority[i]
	}
	return ms(v) * g.cfg.priority[i]
}
func (g *autoGroup) scheduleChallengeLocked(now time.Time) {
	if !g.activeLocked() || g.challengeStop != nil || g.probing || g.cfg.fixed != "" || now.Before(g.freezeUntil) {
		return
	}
	b := g.challengeCandidateLocked(now)
	if b < 0 {
		g.challengeActive = false
		return
	}
	if !g.challengeActive {
		if !g.lastChallenge.IsZero() && now.Sub(g.lastChallenge) < 30*time.Second {
			return
		}
		g.challengeActive = true
		g.challengeRuns = 0
		g.lastChallenge = now
	}
	if g.challengeRuns >= 3 {
		g.challengeActive = false
		return
	}
	g.challengeStop = g.clk.AfterFunc(2*time.Second, g.runChallenge)
}
func (g *autoGroup) runChallenge() {
	g.mu.Lock()
	g.challengeStop = nil
	now := g.clk.Now()
	if !g.activeLocked() || (g.cfg.lazy && now.Sub(g.lastUse) >= g.cfg.interval) {
		g.challengeActive = false
		g.mu.Unlock()
		return
	}
	b := g.challengeCandidateLocked(now)
	if b < 0 {
		g.challengeActive = false
		g.mu.Unlock()
		return
	}
	if g.probing {
		g.scheduleChallengeLocked(now)
		g.mu.Unlock()
		return
	}
	a := g.cur
	g.challengeRuns++
	g.probing = true
	ctx := g.ctx
	g.wg.Add(1)
	g.mu.Unlock()
	go func() {
		defer g.wg.Done()
		res := make([]ProbeSample, 2)
		done := make(chan struct{})
		go func() { res[0] = g.measuredProbe(ctx, a); close(done) }()
		res[1] = g.measuredProbe(ctx, b)
		<-done
		g.mu.Lock()
		g.probing = false
		if ctx.Err() == nil && !g.closed {
			g.acceptSamplesLocked(res)
		}
		g.unlock()
	}()
}
