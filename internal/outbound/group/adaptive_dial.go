package group

import (
	"context"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"math"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

type branchForkKey struct{}
type BranchFork func(context.Context) (context.Context, func())

func WithBranchFork(ctx context.Context, f BranchFork) context.Context {
	return context.WithValue(ctx, branchForkKey{}, f)
}
func forkTrace(ctx context.Context) (context.Context, func()) {
	if f, ok := ctx.Value(branchForkKey{}).(BranchFork); ok {
		return f(ctx)
	}
	return ctx, func() {}
}

type smartDialResult struct {
	conn   net.Conn
	err    error
	i      int
	dial   time.Duration
	commit func()
}

func (g *autoGroup) hedgeAfterLocked(i int, now time.Time) time.Duration {
	mean, n, dev := g.st[i].dial.value(now)
	if n < 5 {
		return 1500 * time.Millisecond
	}
	return msDur(min(1500, max(300, max(1.5*mean, mean+2*dev))))
}
func ignoredFailure(ctx context.Context, err error) bool {
	return errors.Is(err, errProbeDependencyUnready) || errors.Is(err, outbound.ErrRejected) || errors.Is(err, direct.ErrBlocked) || ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ENETDOWN) || errors.Is(err, syscall.EHOSTUNREACH)
}
func (g *autoGroup) smartDialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := g.awaitFirst(ctx); e != nil {
		return nil, e
	}
	key := siteKey(dst.Host, dst.Port, "tcp")
	if isProbe(ctx) {
		key = ""
	}
	g.mu.Lock()
	now := g.clk.Now()
	g.useLocked(now)
	g.reevaluateLocked(now)
	priorFlight := g.siteFlightSeq
	cands := g.candidatesLocked(key, false, now)
	var flight uint64
	if e := g.sites.get(key, now); e != nil && e.flight > priorFlight {
		flight = e.flight
	}
	ownsHalfOpen := false
	if len(cands) == 0 && !g.halfOpen && (g.allRetry.IsZero() || now.Sub(g.allRetry) >= 10*time.Second) {
		earliest := 0
		for i := range g.st {
			if g.st[i].openUntil.Before(g.st[earliest].openUntil) {
				earliest = i
			}
		}
		if !now.Before(g.st[earliest].openUntil) {
			g.halfOpen = true
			ownsHalfOpen = true
			g.allRetry = now
			cands = []int{earliest}
		}
	}

	g.unlock()
	if len(cands) == 0 {
		return nil, fmt.Errorf("ALL_UNAVAILABLE: %w", noMember(g.cfg.name, "TCP"))
	}
	if ownsHalfOpen {
		defer func() { g.mu.Lock(); g.halfOpen = false; g.mu.Unlock() }()
	}
	handed := false
	if !isProbe(ctx) {
		defer func() {
			if !handed {
				g.releaseSiteFlight(key, flight)
			}
		}()
	}
	if isProbe(ctx) {
		for _, i := range cands {
			c, e := g.members[i].DialTCP(ctx, dst)
			if e == nil {
				return c, nil
			}
			if errors.Is(e, errProbeDependencyUnready) {
				return nil, e // preserve local readiness through nested Smart probes
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, noMember(g.cfg.name, "TCP")
	}
	b, shared := ctx.Value(budgetKey{}).(*dialBudget)
	if !shared {
		b = &dialBudget{active: 1, total: 1}
		ctx = context.WithValue(ctx, budgetKey{}, b)
	}
	results := make(chan smartDialResult, 3)
	active, next := 0, 0
	cancels := map[int]context.CancelFunc{}
	launch := func(extra bool) bool {
		if next >= len(cands) {
			return false
		}
		if extra && !b.acquire() {
			return false
		}
		i := cands[next]
		next++
		active++
		branch, commit := forkTrace(ctx)
		branch, cancel := context.WithCancel(branch)
		cancels[i] = cancel
		go func() {
			start := g.clk.Now()
			c, e := g.members[i].DialTCP(branch, dst)
			d := g.clk.Now().Sub(start)
			if extra {
				b.release()
			}
			results <- smartDialResult{c, e, i, d, commit}
		}()
		return true
	}
	launch(false)
	g.mu.Lock()
	after := g.hedgeAfterLocked(cands[0], now)
	g.mu.Unlock()
	timer := make(chan struct{}, 1)
	if g.cfg.adaptiveDial {
		stop := g.clk.AfterFunc(after, func() {
			select {
			case timer <- struct{}{}:
			default:
			}
		})
		defer stop()
	}
	var errs []error
	cleanup := func(winner int) {
		for i, c := range cancels {
			if i != winner {
				c()
			}
		}
		go func(n int) {
			for range n {
				r := <-results
				if r.conn != nil {
					r.conn.Close()
				}
			}
		}(active)
	}
	for active > 0 {
		select {
		case <-ctx.Done():
			cleanup(-1)
			return nil, ctx.Err()
		case <-timer:
			if !launch(true) && next < len(cands) {
				b.mu.Lock()
				pending := b.total < 3
				b.mu.Unlock()
				if pending {
					retryStop := g.clk.AfterFunc(50*time.Millisecond, func() {
						select {
						case timer <- struct{}{}:
						default:
						}
					})
					defer retryStop()
				}
			}
		case r := <-results:
			active--
			if r.err == nil && r.conn != nil {
				cleanup(r.i)
				r.commit()
				g.recordDial(r.i, key, r.dial)
				handed = true
				return wrapConn(r.conn, g.smartObserver(r.i, key, r.dial, flight)), nil
			}
			cancels[r.i]()
			errs = append(errs, r.err)
			if !ignoredFailure(ctx, r.err) {
				g.smartAttemptFailure(r.i, key, confirmedProxyFailure(g.members[r.i], r.err))
			}
			if next < len(cands) {
				if active == 0 {
					if b.retry() {
						launch(false)
					}
				} else {
					launch(true)
				}
			}
		}
	}
	cleanup(-1)
	return nil, fmt.Errorf("group %q: %d member(s) failed: %w", g.cfg.name, len(errs), errors.Join(errs...))
}
func (g *autoGroup) recordDial(i int, key string, d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	now := g.clk.Now()
	g.st[i].dial.add(ms(d), now)
	minute := now.Unix() / 60
	b := &g.st[i].usage[minute%10]
	if b.minute != minute {
		*b = resultBucket{minute: minute}
	}
	b.success++
}
func (g *autoGroup) mostUsedLocked(now time.Time) string {
	best, count := -1, 0
	minute := now.Unix() / 60
	for i := range g.st {
		n := 0
		for _, b := range g.st[i].usage {
			if b.minute <= minute && minute-b.minute < 10 {
				n += b.success
			}
		}
		if n > count {
			best, count = i, n
		}
	}
	if best < 0 {
		return ""
	}
	return g.cfg.members[best]
}
func (g *autoGroup) learnedSitesLocked(now time.Time) int {
	n := 0
	for _, e := range g.sitesElementsLocked() {
		if now.Sub(e.last) < smartSiteTTL {
			n++
		}
	}
	return n
}
func (g *autoGroup) smartAttemptFailure(i int, key string, proxy bool) {
	g.mu.Lock()
	defer g.unlock()
	if g.closed {
		return
	}
	now := g.clk.Now()
	s := &g.st[i]
	if proxy {
		g.smartFailLocked(i, now)
	} else {
		s.real.result(false, now, false)
		g.addSuspectLocked(i, key, now)
	}
	g.sites.record(key, i, false, now, g.cur)
	e := g.sites.get(key, now)
	e.recs[i].quality.result(false, now, true)
	g.reevaluateLocked(now)
	g.siteReevalLocked(e, now, false)
	g.scheduleRecoveryLocked(i, now)
}

var smartObservationSlots atomic.Int64
var smartObservationsDropped atomic.Uint64

func (g *autoGroup) smartObserver(i int, key string, dial time.Duration, owned ...uint64) *observer {
	var flight uint64
	if len(owned) > 0 {
		flight = owned[0]
	}
	g.mu.Lock()
	p, _, _ := g.scorePartsLocked(i, nil, g.clk.Now())
	g.mu.Unlock()
	observing := smartObservationSlots.Add(1) <= 4096
	if !observing {
		smartObservationSlots.Add(-1)
		smartObservationsDropped.Add(1)
	}
	threshold := 3 * time.Second
	if p.RealMS != nil {
		threshold = msDur(min(10000, max(3000, 3**p.RealMS)))
	}
	var confirmed atomic.Bool
	var soft bool
	var softAt time.Time
	if !observing {
		threshold = 0
	}
	return &observer{clk: g.clk, onDone: func() {
		if observing {
			smartObservationSlots.Add(-1)
		}
		g.releaseSiteFlight(key, flight)
	}, noReply: threshold, lateWindow: 10 * time.Second, onError: func(err error) {
		if confirmedProxyFailure(g.members[i], err) {
			confirmed.Store(true)
		}
	}, report: func(ok bool, first time.Duration, has bool) {
		g.mu.Lock()
		defer g.unlock()
		if g.closed {
			return
		}
		now := g.clk.Now()
		s := &g.st[i]
		if !ok {
			if soft {
				return
			}
			soft = true
			softAt = now
			if !confirmed.Load() {
				g.addSuspectLocked(i, key, now)
			}
			if confirmed.Load() {
				g.smartFailLocked(i, now)
			}
			g.sites.record(key, i, false, now, g.cur)
			e := g.sites.get(key, now)
			e.recs[i].quality.result(false, now, true)
			if !confirmed.Load() {
				s.real.result(false, now, false)
			}
			g.scheduleRecoveryLocked(i, now)
		} else {
			if soft {
				correctOutcome(&s.real, softAt, now)
				if e := g.sites.get(key, now); e != nil && e.recs[i] != nil {
					correctOutcome(&e.recs[i].quality, softAt, now)
				}
			}
			g.sites.record(key, i, true, now, g.cur)
			e := g.sites.get(key, now)
			r := e.recs[i]
			s.real.result(true, now, true)
			r.quality.result(true, now, true)
			if has && observing {
				s.real.latency(dial+first, now)
				r.quality.latency(dial+first, now)
			}
			s.healthAt = now
			s.observationEpoch++
		}
		bucket := now.Unix() / 5
		if bucket != g.passiveBucket {
			g.passiveBucket = bucket
			g.evidence++
		}
		g.smartReevalLocked(now, true)
		if e := g.sites.get(key, now); e != nil {
			g.siteReevalLocked(e, now, true)
		}
	}}
}
func correctOutcome(q *quality, at, now time.Time) {
	s, f := q.outcomes(now)
	q.success, q.failure, q.at = s, max(0, f-math.Exp2(-float64(max(time.Duration(0), now.Sub(at)))/float64(120*time.Second))), now
	minute := at.Unix() / 60
	b := &q.buckets[minute%10]
	if b.minute == minute && b.failed > 0 {
		b.failed--
	}
}
func (g *autoGroup) addSuspectLocked(i int, key string, now time.Time) {
	s := &g.st[i]
	if s.suspectHosts == nil {
		s.suspectHosts = map[string]time.Time{}
	}
	g.suspectCountLocked(i, now)
	host := strings.TrimPrefix(key, "tcp|")
	if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	}
	if len(s.suspectHosts) < 2 || !s.suspectHosts[host].IsZero() {
		s.suspectHosts[host] = now
	}
}
func (g *autoGroup) suspectCountLocked(i int, now time.Time) int {
	m := g.st[i].suspectHosts
	for k, at := range m {
		if now.Sub(at) > 30*time.Second {
			delete(m, k)
		}
	}
	return len(m)
}

// Canceled dials and caller closes are not failures, but still release the
// single-flight natural validation/trial/exploration permit.
func (g *autoGroup) releaseSiteFlight(key string, flight uint64) {
	if flight == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	if e := g.sites.get(key, g.clk.Now()); e != nil && e.flight == flight {
		e.flight = 0
		e.trialBusy = false
		for _, r := range e.recs {
			r.halfOpen = false
		}
		if g.exploring == key {
			g.exploring = ""
		}
	}
}
