package group

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// memberState is the per-member bookkeeping shared by the automatic groups.
type memberState struct {
	openCount        int
	openUntil        time.Time
	observationEpoch uint64
	suspectHosts     map[string]time.Time
	udpRecovery      recovery
	samples          []latencySample
	recovery         recovery
	real             quality
	dial             decayMean
	cold             time.Duration
	coldAt, epoch    time.Time
	recoveryStop     func() bool
	recoveryStep     int
	usage            [10]resultBucket
	// last probe round
	probed   bool
	probeOK  bool
	probeLat time.Duration
	probeAt  time.Time
	healthAt time.Time

	probeFailures int         // confirmed independent full-round failures, not business failures
	consec        int         // consecutive real failures (fallback)
	failTimes     []time.Time // url-test: real failures of this member within the window

	ewma      time.Duration
	hasEWMA   bool
	penalty   float64
	penaltyAt time.Time
}

// autoGroup implements url-test, fallback and load-balance.
type autoGroup struct {
	rankAt        time.Time
	rankOrder     []int
	rankScores    []float64
	hardDirty     bool
	passiveBucket int64
	siteFlightSeq uint64
	exploring     string
	random        func() float64
	allRetry      time.Time
	halfOpen      bool
	paused        bool
	sites         *siteCache
	cfg           config
	members       []outbound.Outbound
	events        outbound.EventSink
	clk           clock
	probe         probeFunc

	gate            switchGate
	evidence        uint64
	freezeUntil     time.Time
	challengeStop   func() bool
	challengeActive bool
	challengeRuns   int
	lastChallenge   time.Time
	mu              sync.Mutex
	st              []memberState
	cur             int
	curSince        time.Time
	cold            bool        // no probe round has completed yet
	pending         [][2]string // switch events to emit after unlocking

	firstReady      chan struct{} // URLTest: full round; Smart: successful full bootstrap
	roundDone       chan struct{} // current automatic round terminal, even if incomplete/down
	completeRound   bool
	hasRound        bool
	lastRound       time.Time
	fallbackRoundAt time.Time // end of last independent full fallback evidence set
	probing         bool
	started         bool
	closed          bool
	ctx             context.Context
	cancel          context.CancelFunc
	stopCtx         func() bool
	lastUse         time.Time
	startupDone     bool        // first automatic round only; manual rounds do not consume it
	retryStop       func() bool // client-only one-shot startup recovery
	tickStop        func() bool // pending periodic tick
	lb              *lbState    // load-balance
	wg              sync.WaitGroup
	roundsRun       atomic.Int64 // completed probe rounds (tests)
}

func newAutoGroup(c config, ms []outbound.Outbound, events outbound.EventSink, h hooks) *autoGroup {
	g := &autoGroup{
		cfg: c, members: ms, events: events, clk: h.clk, probe: h.probe,
		st: make([]memberState, len(ms)), cold: true, firstReady: make(chan struct{}),
	}
	g.curSince = g.clk.Now()
	g.gate.reset()
	g.random = defaultRandom
	if c.kind == TypeSmart {
		g.sites = newSiteCache(smartSiteCap)
	}
	if c.kind == TypeLoadBalance {
		g.lb = newLBState()
	}
	return g
}

func (g *autoGroup) Name() string      { return g.cfg.name }
func (g *autoGroup) Type() string      { return g.cfg.kind }
func (g *autoGroup) Members() []string { return append([]string(nil), g.cfg.members...) }

func (g *autoGroup) UDP() bool {

	for _, m := range g.members {
		if m.UDP() {
			return true
		}
	}
	return false
}

func (g *autoGroup) Current() string {
	g.mu.Lock()
	defer g.unlock()
	if i, ok := g.fixedHealthyLocked(); ok {
		return g.cfg.members[i]
	}
	if g.cfg.kind == TypeSmart && g.cold && g.cfg.fixed == "" {
		return "" // no automatic selection before a valid full bootstrap
	}
	if (g.cfg.kind == TypeFallback) || (g.cfg.kind == TypeLoadBalance && g.cfg.fixed != "" && !g.fallbackUpLocked(g.cur)) {
		g.switchToLocked(g.fallbackPickLocked(), g.clk.Now())
	}
	return g.cfg.members[g.cur]
}

// unlock releases g.mu and then emits queued switch events, so an event sink
// may call back into the group.
func (g *autoGroup) unlock() {
	ev := g.pending
	g.pending = nil
	g.mu.Unlock()
	for _, e := range ev {
		emitSwitch(g.events, g.cfg.name, e[0], e[1])
	}
}

func (g *autoGroup) switchToLocked(i int, now time.Time) {
	from := g.cfg.members[g.cur]
	if g.cfg.kind == TypeSmart && g.cold && g.cfg.fixed == "" {
		from = ""
	}
	if i == g.cur && from != "" {
		return
	}
	g.pending = append(g.pending, [2]string{from, g.cfg.members[i]})
	g.cur, g.curSince = i, now
	g.gate.reset()
}

// ---- lifecycle and probe scheduling ----

// Start enables background probing. url-test and fallback probe lazily (only
// when the group is used and results are missing or older than the interval);
// smart probes immediately and then every interval while it is being used.
func (g *autoGroup) Start(ctx context.Context) {
	g.mu.Lock()
	defer g.unlock()
	if g.started || g.closed {
		return
	}
	g.started = true
	g.ctx, g.cancel = context.WithCancel(ctx)
	g.stopCtx = context.AfterFunc(g.ctx, g.stopTimers)
	switch {
	case g.cfg.kind == TypeSmart && g.cfg.lazy:
		// lazy smart: nothing until the first use resumes probing.
		g.paused = true
	case g.cfg.kind == TypeSmart, !g.cfg.lazy, g.cfg.head:
		now := g.clk.Now()
		g.lastUse = now
		g.triggerRoundLocked()
		g.scheduleTickLocked()
	}
}

// Close stops probing and waits for in-flight probe rounds. Members and
// connections handed out earlier are not closed.
func (g *autoGroup) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	if g.sites != nil {
		g.sites.clear()
	}
	if g.stopCtx != nil {
		g.stopCtx() // Close stops the timers itself
	}
	if g.cancel != nil {
		g.cancel()
	}
	if g.challengeStop != nil {
		g.challengeStop()
		g.challengeStop = nil
	}
	for i := range g.st {
		if stop := g.st[i].recoveryStop; stop != nil {
			stop()
			g.st[i].recoveryStop = nil
		}
	}
	if g.retryStop != nil {
		g.retryStop()
		g.retryStop = nil
	}
	if g.tickStop != nil {
		g.tickStop()
		g.tickStop = nil
	}
	g.mu.Unlock()
	g.wg.Wait()
	return nil
}

func (g *autoGroup) stopTimers() {
	g.mu.Lock()
	if g.challengeStop != nil {
		g.challengeStop()
		g.challengeStop = nil
	}
	for i := range g.st {
		if stop := g.st[i].recoveryStop; stop != nil {
			stop()
			g.st[i].recoveryStop = nil
		}
	}
	if g.retryStop != nil {
		g.retryStop()
		g.retryStop = nil
	}
	if g.tickStop != nil {
		g.tickStop()
		g.tickStop = nil
	}
	g.mu.Unlock()
}

func (g *autoGroup) activeLocked() bool {
	return g.started && !g.closed && g.ctx.Err() == nil
}

func (g *autoGroup) triggerRoundLocked() {
	if !g.activeLocked() || g.probing {
		return
	}
	g.probing = true
	done := make(chan struct{})
	g.roundDone = done
	g.wg.Add(1)
	go g.runRound(g.ctx, done)
}

func (g *autoGroup) scheduleTickLocked() {
	if !g.activeLocked() {
		return
	}
	if g.tickStop != nil {
		g.tickStop()
	}
	g.tickStop = g.clk.AfterFunc(g.cfg.interval, g.tick)
}

// tick is the smart group's periodic probe. Probing pauses when the group has
// not been used for smartIdleFactor intervals and resumes on the next use.
func (g *autoGroup) tick() {
	g.mu.Lock()
	defer g.unlock()
	g.tickStop = nil
	if !g.activeLocked() {
		return
	}
	if g.cfg.kind != TypeSmart {
		if g.cfg.head && g.cfg.lazy && g.clk.Now().Sub(g.lastUse) >= g.cfg.interval {
			g.scheduleTickLocked()
			return
		}
		// Non-lazy groups probe every interval; desktop lazy groups always
		// have a startup round and tick only when touched in the last interval.
		g.triggerRoundLocked()
		g.scheduleTickLocked()
		return
	}
	if g.clk.Now().Sub(g.lastUse) >= smartIdleFactor*g.cfg.interval {
		g.paused = true
		return
	}
	g.triggerRoundLocked()
	g.scheduleTickLocked()
}

// useLocked records that the group is selecting a member for traffic.
func (g *autoGroup) useLocked(now time.Time) {
	g.lastUse = now
	switch g.cfg.kind {
	case TypeURLTest, TypeFallback, TypeLoadBalance:
		if !g.hasRound || now.Sub(g.lastRound) >= g.cfg.interval {
			g.triggerRoundLocked()
		}
	case TypeSmart:
		if g.paused && g.activeLocked() {
			g.paused = false
			if !g.hasRound || now.Sub(g.lastRound) >= g.cfg.interval {
				g.triggerRoundLocked()
			}
			g.scheduleTickLocked()
		}
	}
}

func (g *autoGroup) runRound(ctx context.Context, done chan struct{}) {
	defer g.wg.Done()
	defer close(done)
	res := make([]ProbeSample, len(g.members))
	var wg sync.WaitGroup
	jobs := make(chan int)
	for range min(probeConcurrency, len(g.members)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				res[i] = g.measuredProbe(ctx, i)
			}
		}()
	}
	for i := range g.members {
		select {
		case jobs <- i:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	g.mu.Lock()
	g.probing = false
	if ctx.Err() == nil && !g.closed {
		first := !g.startupDone
		g.startupDone = true
		if first && g.cfg.head {
			for _, r := range res {
				if r.Err != nil {
					g.retryStop = g.clk.AfterFunc(12*time.Second, g.retryStartup)
					break
				}
			}
		}
		g.acceptSamplesLocked(res)
	}
	g.unlock()
	g.roundsRun.Add(1)
}

func (g *autoGroup) retryStartup() {
	g.mu.Lock()
	defer g.unlock()
	g.retryStop = nil
	g.triggerRoundLocked() // lifecycle/overlap gates are unchanged
}

// ---- selection ----

// reevaluateLocked recomputes the group-level current member.
func (g *autoGroup) reevaluateLocked(now time.Time) {
	switch g.cfg.kind {
	case TypeURLTest:
		g.urlTestReevalLocked(now)
	case TypeFallback:
		g.switchToLocked(g.fallbackPickLocked(), now)
	case TypeSmart:
		g.smartReevalLocked(now, false)
	}
}

// url-test: switch only when the current member failed its last probe, or the
// best member is faster by more than the tolerance. If every probe failed the
// current member is kept.
func (g *autoGroup) urlTestReevalLocked(now time.Time) {
	best := -1
	for i, s := range g.st {
		if s.probeOK && g.fallbackUpLocked(i) && (best < 0 || g.comparisonCostLocked(i, now) < g.comparisonCostLocked(best, now)) {
			best = i
		}
	}
	if best < 0 {
		return
	}
	if g.cold && !g.hasRound {
		return
	}
	if g.cold && g.hasRound {
		g.cold = false
		g.switchToLocked(best, now)
		return
	}
	if !g.fallbackUpLocked(g.cur) {
		g.switchToLocked(best, now)
		g.gate.reset()
		return
	}
	if now.Before(g.freezeUntil) {
		return
	}
	_, a := g.medianLocked(g.cur, now)
	_, b := g.medianLocked(best, now)
	if g.gateLocked(&g.gate, g.cur, best, g.comparisonCostLocked(g.cur, now), g.comparisonCostLocked(best, now), a >= 3 && b >= 3, g.curSince, now, g.memberEvidenceLocked(g.cur, nil), g.memberEvidenceLocked(best, nil)) {
		g.switchToLocked(best, now)
	}
}
func (g *autoGroup) fallbackUpLocked(i int) bool {
	s := &g.st[i]
	if g.cfg.head {
		alive, at, known := false, time.Time{}, false
		if nested, ok := g.members[i].(interface {
			ClientGroupHealth() (bool, time.Time, bool)
		}); ok {
			alive, at, known = nested.ClientGroupHealth()
		}
		if nested, ok := g.members[i].(interface{ ClientHealth() (bool, time.Time) }); ok {
			alive, at = nested.ClientHealth()
			known = true
		}
		if known && (!s.probed || !s.probeAt.After(at)) {
			// An unknown empty child is not a usable member. Repeated Current /
			// Snapshot reads never count the same child timestamp twice.
			if at.IsZero() {
				return alive && !s.recovery.down
			}
			s.recovery.observe(alive, at)
			if !alive {
				return false
			}
		}
	}
	limit := g.cfg.maxFailed
	if limit == 0 {
		limit = 1
	}
	wasDown := s.recovery.down
	ready := s.recovery.ready(g.clk.Now())
	if wasDown && ready && g.cfg.kind == TypeSmart {
		s.real = quality{}
		s.dial = decayMean{}
		s.epoch = g.clk.Now()
		s.openUntil = time.Time{}
		g.hardDirty = true
	}
	return (!s.probed || s.probeOK) && s.consec < limit && ready
}

// fallback: first member (in order) whose last probe succeeded (or that was
// not probed yet) and that has not failed fallbackFailLimit real connections
// in a row; the first member when none qualifies.
func (g *autoGroup) fallbackPickLocked() int {
	for i := range g.st {
		if g.fallbackUpLocked(i) {
			return i
		}
	}
	return 0
}

// fallbackIndependentRoundLocked rejects duplicate, overlapping, partial and
// stale evidence sets. A node retry or a status read is never a failure round.
func (g *autoGroup) fallbackIndependentRoundLocked(results []ProbeSample) bool {
	if g.cfg.kind != TypeFallback || len(results) != len(g.members) {
		return false
	}
	seen := map[string]bool{}
	end := g.fallbackRoundAt
	for _, r := range results {
		if seen[r.Name] || r.At.IsZero() || errors.Is(r.Err, context.Canceled) {
			return false
		}
		seen[r.Name] = true
		i := -1
		for j, n := range g.cfg.members {
			if n == r.Name {
				i = j
				break
			}
		}
		if i < 0 {
			return false
		}
		st := &g.st[i]
		if !r.At.After(st.probeAt) || !r.At.After(g.fallbackRoundAt) || (r.versioned && r.observationEpoch != st.observationEpoch) || (!r.Started.IsZero() && (r.Started.Before(st.healthAt) || r.Started.Before(g.fallbackRoundAt))) {
			return false
		}
		if r.At.After(end) {
			end = r.At
		}
	}
	g.fallbackRoundAt = end
	return true
}

// Use the existing verification spacing and lifecycle retry slot to request a
// new complete round, rather than waiting a desktop interval after tentative
// failure. It remains distinct evidence, not the same sample counted twice.
func (g *autoGroup) scheduleFallbackConfirmationLocked() {
	if !g.activeLocked() || g.retryStop != nil {
		return
	}
	g.retryStop = g.clk.AfterFunc(5*time.Second, g.retryStartup)
}

// candidatesLocked returns the member order for one connection (at most
// maxAttempts entries); udp restricts it to UDP-capable members.
func (g *autoGroup) candidatesLocked(host string, udp bool, now time.Time) []int {
	fixed, fixedOK := g.fixedHealthyLocked()
	if udp && fixedOK && !g.members[fixed].UDP() {
		fixedOK = false
	}
	var order []int
	switch g.cfg.kind {
	case TypeURLTest:
		// current, then members with a successful probe by latency, then the rest in order
		order = append(order, g.cur)
		rest := make([]int, 0, len(g.st))
		for i := range g.st {
			if i != g.cur {
				rest = append(rest, i)
			}
		}
		sort.SliceStable(rest, func(a, b int) bool {
			sa, sb := g.st[rest[a]], g.st[rest[b]]
			if sa.probeOK != sb.probeOK {
				return sa.probeOK
			}
			return sa.probeOK && g.weightedLatency(rest[a]) < g.weightedLatency(rest[b])
		})
		order = append(order, rest...)
	case TypeFallback:
		order = append(order, g.cur)
		for _, up := range []bool{true, false} {
			for i := range g.st {
				if i != g.cur && g.fallbackUpLocked(i) == up {
					order = append(order, i)
				}
			}
		}
	case TypeSmart:
		order = g.smartOrderLocked(host, now)
	}
	if fixedOK {
		order = orderCurrent(order, fixed)
	}
	out := make([]int, 0, maxAttempts)
	for _, i := range order {
		if (!g.fallbackUpLocked(i) && g.cfg.kind == TypeSmart) || (udp && (!g.members[i].UDP() || !g.st[i].udpRecovery.ready(now))) {
			continue
		}
		out = append(out, i)
		if len(out) == maxAttempts {
			break
		}
	}
	return out
}

// ---- traffic ----

// DialTCP dials through the selected member. When a member's dial fails (no
// client data has been sent yet) the next candidate is tried, at most
// maxAttempts members in total, within ctx. Failures after the connection is
// returned are reported to the caller and never retried.
// Cold URL-test requests share the lifecycle-owned first full round. A
// caller can leave without canceling other callers; no lock is held waiting.
func (g *autoGroup) markCompleteLocked() {
	if !g.completeRound {
		g.completeRound = true
		if g.cfg.kind != TypeSmart || !g.cold {
			close(g.firstReady)
		}
	}
}

// WaitReady prepares nested/via/relay dependencies before target HTTP admission.
// Automatic Smart and URLTest share their lifecycle-owned full first round;
// explicit fixed keeps its existing manual preference/no-wait semantics.
func (g *autoGroup) WaitReady(ctx context.Context) error { return g.awaitFirst(ctx) }

func (g *autoGroup) awaitFirst(ctx context.Context) error {
	g.mu.Lock()
	fixed := g.cfg.fixed != ""
	smart := g.cfg.kind == TypeSmart
	g.mu.Unlock()
	if (g.cfg.kind != TypeURLTest && !smart) || fixed {
		return nil
	}
	// Keep the original context cause visible, while marking a cold Smart
	// wait as local readiness work rather than a failed target observation.
	waitError := func(err error) error {
		if smart && err != nil {
			return errors.Join(errProbeDependencyUnready, err)
		}
		return err
	}
	if e := ctx.Err(); e != nil {
		return waitError(e)
	}
	g.mu.Lock()
	// This is a cold-admission gate only. Stopping background probing after
	// a valid bootstrap must not invalidate the existing hot traffic path.
	if smart && !g.cold {
		g.mu.Unlock()
		return nil
	}
	if g.closed {
		g.mu.Unlock()
		return waitError(context.Canceled)
	}
	// A complete successful manual bootstrap is usable even for the standalone
	// API. An unstarted cold Smart must not silently dial its zero-valued cur.
	if !g.started {
		ready := !smart || !g.cold
		g.mu.Unlock()
		if ready {
			return nil
		}
		return errProbeDependencyUnready
	}
	life := g.ctx
	if life.Err() != nil {
		g.mu.Unlock()
		return waitError(life.Err())
	}
	if (smart && !g.cold) || (!smart && g.completeRound) {
		g.mu.Unlock()
		return nil
	}
	g.lastUse = g.clk.Now()
	g.triggerRoundLocked()
	ready := g.firstReady
	var roundDone <-chan struct{}
	if smart {
		roundDone = g.roundDone
	}
	g.mu.Unlock()
	// A background target may discover a newly cold dependency after preflight.
	// Never wait for that child's round while holding a shared HTTP slot.
	if prepared, _ := ctx.Value(preparedProbeKey{}).(bool); prepared {
		return errProbeDependencyUnready
	}
	select {
	case <-ctx.Done():
		return waitError(ctx.Err())
	case <-life.Done():
		return waitError(life.Err())
	case <-ready:
		if e := ctx.Err(); e != nil {
			return waitError(e)
		}
		return waitError(life.Err())
	case <-roundDone:
		if e := ctx.Err(); e != nil {
			return waitError(e)
		}
		if e := life.Err(); e != nil {
			return waitError(e)
		}
		g.mu.Lock()
		usable := !g.cold || g.cfg.fixed != ""
		g.mu.Unlock()
		if usable {
			return nil
		}
		// Incomplete/admission-only/all-down first rounds are not readiness.
		// A later caller may share/request a new bounded round, not a partial
		// success or an implicit first-member business attempt.
		return errProbeDependencyUnready
	}
}

func (g *autoGroup) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	ctx = withDialBudget(ctx)
	if g.cfg.kind == TypeLoadBalance {
		return g.lbDialTCP(ctx, dst)
	}
	if g.cfg.kind == TypeSmart {
		return g.smartDialTCP(ctx, dst)
	}
	if e := g.awaitFirst(ctx); e != nil {
		return nil, e
	}
	g.mu.Lock()
	now := g.clk.Now()
	g.useLocked(now)
	g.reevaluateLocked(now)
	cands := g.candidatesLocked(dst.Host, false, now)
	g.unlock()
	var errs []error
	for attempt, i := range cands {
		if attempt > 0 && !retryBudget(ctx) {
			break
		}
		if ctx.Err() != nil {
			break
		}
		c, err := g.members[i].DialTCP(ctx, dst)
		if err == nil {
			if isProbe(ctx) {
				return c, nil
			}
			return wrapConn(c, g.newObserver(i, dst.Host)), nil
		}
		errs = append(errs, err)
		if !isProbe(ctx) && !isCanceled(ctx) && !errors.Is(err, errProbeDependencyUnready) {
			g.realFailure(i, dst.Host, g.cfg.kind == TypeURLTest && serverRefused(g.members[i], err))
		}
	}
	if len(cands) == 0 {
		return nil, noMember(g.cfg.name, "TCP")
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("group %q: %w", g.cfg.name, ctx.Err())
	}
	return nil, fmt.Errorf("group %q: %d member(s) failed: %w", g.cfg.name, len(errs), errors.Join(errs...))
}

// ListenPacket picks among UDP-capable members only. The returned session
// stays on that member for its whole life.
func (g *autoGroup) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	if g.cfg.kind == TypeLoadBalance {
		return g.lbListenPacket(ctx)
	}
	if e := g.awaitFirst(ctx); e != nil {
		return nil, e
	}
	g.mu.Lock()
	now := g.clk.Now()
	g.useLocked(now)
	g.reevaluateLocked(now)
	cands := g.candidatesLocked("", true, now)
	g.unlock()
	if len(cands) == 0 {
		return nil, noMember(g.cfg.name, "UDP")
	}
	var errs []error
	for _, i := range cands {
		if ctx.Err() != nil {
			break
		}
		pc, err := g.members[i].ListenPacket(ctx)
		if err == nil {
			if g.cfg.kind != TypeSmart {
				return pc, nil
			}
			return &obsPacket{PacketConn: pc, clk: g.clk, noReply: 0,
				report: func(ok bool) { g.udpResult(i, ok) }}, nil
		}
		errs = append(errs, err)
		if g.cfg.kind == TypeSmart && !ignoredFailure(ctx, err) {
			g.udpResult(i, false)
		}
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("group %q: %w", g.cfg.name, ctx.Err())
	}
	return nil, fmt.Errorf("group %q: %d member(s) failed: %w", g.cfg.name, len(errs), errors.Join(errs...))
}

func (g *autoGroup) newObserver(i int, host string) *observer {
	o := &observer{clk: g.clk}
	if g.cfg.kind == TypeSmart {
		o.noReply = noReplyTimeout
	}
	o.report = func(ok bool, ttfb time.Duration, has bool) {
		if ok {
			g.realSuccess(i, host, ttfb, has)
		} else {
			g.realFailure(i, host, false)
		}
	}
	return o
}

// realFailure: a dial error, or data written and the connection closed/errored
// with zero bytes back. Smart v2 attribution/soft timeout uses smartObserver.
// refused (url-test only) marks a dial error where the member's proxy server
// itself refused the TCP connection (see serverRefused): it triggers the
// re-test at once instead of after urlTestFailCount failures.
func (g *autoGroup) realFailure(i int, host string, refused bool) {
	g.mu.Lock()
	defer g.unlock()
	now := g.clk.Now()
	s := &g.st[i]
	s.healthAt = now
	s.observationEpoch++
	switch g.cfg.kind {
	case TypeURLTest:
		if i != g.cur && (g.cfg.fixed == "" || i != g.cfg.fixedIndex) {
			return
		}
		kept := s.failTimes[:0]
		for _, t := range s.failTimes {
			if now.Sub(t) < urlTestFailWindow {
				kept = append(kept, t)
			}
		}
		s.failTimes = append(kept, now)
		if len(s.failTimes) >= g.cfg.maxFailed || refused {
			s.probed = true
			s.probeOK = false
			s.recovery.observe(false, now)
			g.reevaluateLocked(now)
			s.failTimes = nil
			g.triggerRoundLocked()
		}
	case TypeFallback:
		s.consec++
		if s.consec >= g.cfg.maxFailed || refused {
			s.recovery.observe(false, now)
		}
		g.reevaluateLocked(now)
	case TypeLoadBalance:
		s.consec++
		if s.consec >= g.cfg.maxFailed || refused {
			s.recovery.observe(false, now)
		}
		if s.consec == g.cfg.maxFailed {
			// The member is now skipped; re-test at once so that it can
			// come back as soon as it answers probes again.
			g.triggerRoundLocked()
		}
	case TypeSmart:
		g.smartFailLocked(i, now)
		if host != "" {
			g.sites.record(host, i, false, now, g.cur)
		}
		g.reevaluateLocked(now)
	}
}

func (g *autoGroup) realSuccess(i int, host string, ttfb time.Duration, hasTTFB bool) {
	if g.cfg.kind == TypeURLTest {
		return
	}
	g.mu.Lock()
	defer g.unlock()
	now := g.clk.Now()
	g.st[i].healthAt = now
	g.st[i].observationEpoch++
	switch g.cfg.kind {
	case TypeFallback:
		g.st[i].consec = 0
		g.st[i].recovery.observe(true, now)
		g.reevaluateLocked(now)
	case TypeLoadBalance:
		g.st[i].consec = 0
		g.st[i].probeOK = true
		g.st[i].recovery.observe(true, now)
	case TypeSmart:
		g.smartSuccessLocked(i, ttfb, hasTTFB, now)
		if host != "" {
			g.sites.record(host, i, true, now, g.cur)
		}
		g.smartReevalLocked(now, true)
	}
}

func (g *autoGroup) udpResult(i int, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.st[i].udpRecovery.observe(ok, g.clk.Now())
}

// Snapshot reports per-member state without any destination information.
func (g *autoGroup) Snapshot() Snapshot {
	g.mu.Lock()
	defer g.unlock()
	now := g.clk.Now()
	if (g.cfg.kind == TypeFallback) || (g.cfg.kind == TypeLoadBalance && g.cfg.fixed != "" && !g.fallbackUpLocked(g.cur)) {
		g.switchToLocked(g.fallbackPickLocked(), now)
	}
	s := Snapshot{Name: g.cfg.name, Type: g.cfg.kind, Current: g.cfg.members[g.cur], Fixed: g.cfg.fixed}
	if g.cfg.kind == TypeSmart && g.cold && g.cfg.fixed == "" {
		s.Current = ""
	}
	if g.cfg.fixed != "" {
		if i, ok := g.fixedHealthyLocked(); ok {
			s.Current = g.cfg.members[i]
		}
	}
	if g.cfg.kind == TypeSmart {
		s.SelectionMode = g.cfg.scope
		s.LearnedSites = g.learnedSitesLocked(now)
		s.MostUsedMember = g.mostUsedLocked(now)
		s.Reason = "lowest_cost"
		if s.MostUsedMember == "" {
			s.Reason = "insufficient_data"
		}
	}
	if g.cfg.fixed != "" {
		if s.Current == g.cfg.fixed {
			s.Reason = "fixed"
		} else {
			s.Reason = "fixed_fallback"
		}
	}
	s.ConfirmRequired = g.cfg.confirms
	s.ConfirmProgress = g.gate.wins
	if g.gate.candidate >= 0 && g.gate.wins > 0 {
		s.Candidate = g.cfg.members[g.gate.candidate]
	}
	s.RemainingDwell = max(time.Duration(0), g.cfg.dwell-now.Sub(g.curSince))
	for i, st := range g.st {
		m := MemberSnapshot{
			Name: g.cfg.members[i], UDP: g.members[i].UDP(),
			Probed: st.probed, ProbeOK: st.probeOK, ProbeLatency: st.probeLat, ProbeAt: st.probeAt,
			Failures: st.consec,
		}
		switch g.cfg.kind {
		case TypeURLTest:
			m.Priority = g.cfg.priority[i]
			m.Failures = 0
			for _, t := range st.failTimes {
				if now.Sub(t) < urlTestFailWindow {
					m.Failures++
				}
			}
		case TypeSmart:
			m.ScoreParts, m.EffectiveSamples, m.DecisionKnown = g.scorePartsLocked(i, nil, now)
			if m.ScoreParts.RealMS != nil {
				m.Latency = msDur(*m.ScoreParts.RealMS)
			}
			m.SuccessRate, m.SampleCount = st.real.rate(now)
			d, _, _ := st.dial.value(now)
			m.DialLatency = msDur(d)
			m.HealthState = "healthy"
			if g.suspectCountLocked(i, now) > 0 {
				m.HealthState = "suspect"
			}
			if !g.fallbackUpLocked(i) {
				m.HealthState = "open"
				m.CooldownUntil = st.openUntil
				if m.CooldownUntil.IsZero() {
					m.CooldownUntil = st.recovery.observed.Add(15 * time.Second)
				}
				if st.recovery.successes > 0 {
					m.HealthState = "recovering"
					m.CooldownUntil = st.recovery.first.Add(10 * time.Second)
				}
			}

			m.Penalty = msDur(g.penaltyLocked(i, now))
			m.Priority = g.cfg.priority[i]
			m.Score = msDur(g.scoreLocked(i, now))
		}
		s.Members = append(s.Members, m)
	}
	return s
}

// weightedLatency preserves exact old url-test arithmetic at weight 1.
func (g *autoGroup) weightedLatency(i int) time.Duration {
	v, n := g.medianLocked(i, g.clk.Now())
	if n == 0 {
		v = g.st[i].probeLat
	}
	return time.Duration(float64(v) * g.cfg.priority[i])
}

// ProbeSample is one member's real HTTP(S) result within a manual round.
// A failed sample must carry Err; Latency is not used on failure.
type ProbeSample struct {
	observationEpoch uint64
	versioned        bool
	Started          time.Time
	Name             string
	Latency          time.Duration
	ColdLatency      time.Duration
	At               time.Time
	Err              error
}

// RecordProbe retains the single-result API for existing callers.
func (g *autoGroup) RecordProbe(name string, lat time.Duration, at time.Time, err error) {
	g.RecordProbeRound([]ProbeSample{{Name: name, Latency: lat, At: at, Err: err}})
}

// RecordProbeRound installs one collected manual round atomically and evaluates
// selection only after all accepted samples have updated health and active priors. In
// particular, Smart's cold-start choice must see the whole round, not whichever
// member happened to finish first. Callers must discard canceled rounds.
func (g *autoGroup) RecordProbeRound(results []ProbeSample) {
	g.mu.Lock()
	defer g.unlock()
	if g.closed {
		return
	}
	g.acceptSamplesLocked(results)
}

// Same-URL manual samples are proxy health, not private to the probed group.
func (g *autoGroup) RecordURLProbe(url string, sample ProbeSample) {
	if g.cfg.head && g.cfg.url == url && (g.cfg.kind == TypeURLTest || g.cfg.kind == TypeFallback || g.cfg.kind == TypeSmart || g.cfg.kind == TypeLoadBalance) {
		g.RecordProbeRound([]ProbeSample{sample})
	}
}

// Runtime group graph is acyclic (validated by the kernel). Unknown health is
// optimistic for ordinary leaves, but an empty or wholly failed group is down.
// ClientHealth returns the latest underlying health observation time as well
// as OR health. The validated graph is acyclic; parent and child locks never
// form a cycle. A parent's newer probe must not be overwritten by stale child data.
func (g *autoGroup) ClientHealth() (bool, time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	alive := false
	var at time.Time
	for i := range g.members {
		if g.fallbackUpLocked(i) {
			alive = true
		}
		t := g.st[i].probeAt
		if g.st[i].healthAt.After(t) {
			t = g.st[i].healthAt
		}
		if child, ok := g.members[i].(interface {
			ClientGroupHealth() (bool, time.Time, bool)
		}); ok {
			_, ct, _ := child.ClientGroupHealth()
			if ct.After(t) {
				t = ct
			}
		}
		if child, ok := g.members[i].(interface{ ClientHealth() (bool, time.Time) }); ok {
			_, ct := child.ClientHealth()
			if ct.After(t) {
				t = ct
			}
		}
		if t.After(at) {
			at = t
		}
	}
	return alive, at
}
func (g *autoGroup) ClientAlive() bool { alive, _ := g.ClientHealth(); return alive }

// Fixed is a persistent preference, never cleared by transient health. Runtime
// selection falls back to the group's normal algorithm until it recovers.
func (g *autoGroup) fixedHealthyLocked() (int, bool) {
	i := g.cfg.fixedIndex
	return i, g.cfg.fixed != "" && i >= 0 && i < len(g.members) && g.fallbackUpLocked(i)
}

// SetFixed updates only the manual preference; learned scores, member objects,
// live sessions and active probes belong to this same group and are retained.
func (g *autoGroup) SetFixed(name string) error {
	g.mu.Lock()
	defer g.unlock()
	i := -1
	if name != "" {
		for n, m := range g.cfg.members {
			if m == name {
				i = n
				break
			}
		}
		if i < 0 {
			return fmt.Errorf("fixed target is not a member")
		}
	}
	g.cfg.fixed = name
	g.cfg.fixedIndex = i
	g.gate.reset()
	g.rankAt = time.Time{}
	g.hardDirty = true
	if g.challengeStop != nil {
		g.challengeStop()
		g.challengeStop = nil
	}
	g.challengeActive = false
	if i >= 0 && g.fallbackUpLocked(i) {
		g.switchToLocked(i, g.clk.Now())
	}
	return nil
}
