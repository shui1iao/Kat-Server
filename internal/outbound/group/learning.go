package group

import "time"

// InheritLearning carries only in-memory observations across a same-identity
// document edit (not restart). The kernel verifies the proxy graph/network
// identity first. Timers, contexts and connection observers never transfer.
func (g *autoGroup) InheritLearning(previous Group) {
	old, ok := previous.(*autoGroup)
	if !ok || old == g {
		return
	}
	old.mu.Lock()
	defer old.mu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cfg.kind != old.cfg.kind || g.cfg.url != old.cfg.url || g.cfg.unified != old.cfg.unified || g.cfg.head != old.cfg.head || len(g.cfg.members) != len(old.cfg.members) {
		return
	}
	for i, n := range g.cfg.members {
		if old.cfg.members[i] != n {
			return
		}
	}
	for i, s := range old.st {
		s.recoveryStop = nil
		s.recoveryStep = 0
		s.samples = append([]latencySample(nil), s.samples...)
		s.failTimes = append([]time.Time(nil), s.failTimes...)
		if s.suspectHosts != nil {
			copy := map[string]time.Time{}
			for k, v := range s.suspectHosts {
				copy[k] = v
			}
			s.suspectHosts = copy
		}
		g.st[i] = s
	}
	g.cur, g.curSince, g.cold = old.cur, old.curSince, old.cold
	g.hasRound, g.lastRound = old.hasRound, old.lastRound
	if old.completeRound {
		g.markCompleteLocked()
	}
	g.gate.reset()
	g.hardDirty = true
	if g.sites != nil && old.sites != nil {
		// Copy MRU records first, bounded by the same process-wide quota. No map or
		// quality record is shared with observers on existing old-generation flows.
		for el := old.sites.ll.Back(); el != nil; el = el.Prev() {
			e := el.Value.(*siteEntry)
			n := g.sites.ensure(e.key, e.last, e.current)
			*n = *e
			n.recs = map[int]*siteRec{}
			for i, r := range e.recs {
				v := *r
				v.halfOpen = false
				n.recs[i] = &v
			}
			n.gate.reset()
			n.trialBusy = false
			n.flight = 0
			n.tried = map[int]bool{}
			for i, v := range e.tried {
				n.tried[i] = v
			}
		}
	}
}
