package group

import (
	"context"
	"sync"
	"time"
)

// One request shares its bounded retry budget through nested groups/via hops.
type dialBudget struct {
	mu            sync.Mutex
	active, total int
}
type budgetKey struct{}

func (b *dialBudget) acquire() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active >= 2 || b.total >= 3 {
		return false
	}
	b.active++
	b.total++
	return true
}
func (b *dialBudget) release() { b.mu.Lock(); b.active--; b.mu.Unlock() }

func (b *dialBudget) retry() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.total >= 3 {
		return false
	}
	b.total++
	return true
}

func withDialBudget(ctx context.Context) context.Context {
	if isProbe(ctx) || ctx.Value(budgetKey{}) != nil {
		return ctx
	}
	return context.WithValue(ctx, budgetKey{}, &dialBudget{active: 1, total: 1})
}
func retryBudget(ctx context.Context) bool {
	b, _ := ctx.Value(budgetKey{}).(*dialBudget)
	return b == nil || b.retry()
}

func (g *autoGroup) scheduleRecoveryLocked(i int, now time.Time) {
	s := &g.st[i]
	if !g.activeLocked() || s.recoveryStop != nil {
		return
	}
	waits := []time.Duration{5, 15, 30, 60, 300}
	delay := waits[min(s.recoveryStep, len(waits)-1)] * time.Second
	s.recoveryStop = g.clk.AfterFunc(delay, func() {
		g.mu.Lock()
		g.st[i].recoveryStop = nil
		if !g.activeLocked() {
			g.mu.Unlock()
			return
		}
		ctx := g.ctx
		g.wg.Add(1)
		g.mu.Unlock()
		go func() {
			defer g.wg.Done()
			r := g.measuredProbe(ctx, i)
			g.mu.Lock()
			defer g.unlock()
			if ctx.Err() != nil || g.closed {
				return
			}
			// Do not convict a healthy member from a stale verification.
			if r.Err != nil && !g.st[i].recovery.down && (g.cfg.kind != TypeSmart || g.suspectCountLocked(i, g.clk.Now()) < 2) {
				g.st[i].recoveryStep++
				g.scheduleRecoveryLocked(i, g.clk.Now())
				return
			}
			g.addProbeLocked(i, r)
			if r.Err != nil {
				g.st[i].recoveryStep++
			} else {
				g.st[i].recoveryStep = 0
			}
			if g.st[i].recovery.down {
				g.scheduleRecoveryLocked(i, g.clk.Now())
			} else {
				g.st[i].recoveryStep = 0
			}
			g.reevaluateLocked(g.clk.Now())
		}()
	})
}
