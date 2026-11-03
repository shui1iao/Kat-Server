package kernel

import (
	"context"
	"errors"

	"github.com/shui1iao/Kat/internal/outbound/group"
)

// prepareManualProbe waits for the same full first URLTest/Smart round that a real
// dial would await. It does not dial the target, choose a first-success member,
// override fixed/selected members, or change any group's probe policy. The
// caller owns a manual permit and the bounded parent round context throughout.
// Resolve against the captured generation's expanded config/runtime (including
// provider Via and relay clones), never against the next generation.
func (s *Server) prepareManualProbe(ctx context.Context, name string) error {
	return s.prepareProbeDependencies(ctx, s.rt, name)
}

// Both probe paths resolve the captured generation's expanded dependency graph.
// Background callers run this BEFORE shared HTTP admission; manual callers keep
// their existing bounded round/permit ownership and target-budget boundary.
func (s *Server) prepareProbeDependencies(ctx context.Context, rt *routingRuntime, name string) error {
	outs := make(map[string]OutboundConfig, len(s.cfg.Outbounds))
	groups := make(map[string]GroupConfig, len(s.cfg.Groups))
	for _, o := range s.cfg.Outbounds {
		outs[o.Name] = o
	}
	for _, g := range s.cfg.Groups {
		groups[g.Name] = g
	}
	seen := map[string]bool{}
	var prepare func(string) error
	prepare = func(name string) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if s.superseded.Load() {
			return context.Canceled
		}
		if name == "" || name == "direct" || name == "reject" || seen[name] {
			return nil
		}
		seen[name] = true
		if o, ok := outs[name]; ok {
			return prepare(o.Via)
		}
		cfg, ok := groups[name]
		if !ok {
			return errors.New("probe dependency unavailable")
		}
		node := rt.nodes[name]
		if node == nil {
			return errors.New("probe dependency unavailable")
		}
		members := cfg.Members
		// Explicit choices must remain explicit; unrelated alternatives are not
		// warmed for a select/fixed group. Automatic groups need all candidates for
		// their unchanged full-round health/weighted selection.
		if cfg.Type == group.TypeSelect {
			members = []string{node.(group.Group).Current()}
		} else if cfg.Fixed != "" {
			members = []string{cfg.Fixed}
		}
		for _, m := range members {
			if e := prepare(m); e != nil {
				return e
			}
		}
		if ready, ok := node.(interface{ WaitReady(context.Context) error }); ok {
			return ready.WaitReady(ctx)
		}
		return nil
	}
	return prepare(name)
}
