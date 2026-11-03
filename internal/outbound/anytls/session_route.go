package anytls

import (
	"context"
	"sync"
)

// sessionRoute is only collected while dialing an AnyTLS physical carrier.
// Checks describe the actual successful underlay path, not configured names.
// Once copied onto a session they are immutable and are checked outside pool locks.
type sessionRoute struct {
	mu     sync.Mutex
	checks []func() bool
}
type sessionRouteKey struct{}

// SessionRouteBranch isolates a dial attempt. Only a successful branch commits
// its checks; failed alternatives must not invalidate a different carrier.
// With no AnyTLS carrier being built it is an allocation-free no-op.
func SessionRouteBranch(ctx context.Context) (context.Context, func()) {
	parent, _ := ctx.Value(sessionRouteKey{}).(*sessionRoute)
	if parent == nil {
		return ctx, nil
	}
	child := &sessionRoute{}
	return context.WithValue(ctx, sessionRouteKey{}, child), func() {
		parent.mu.Lock()
		defer parent.mu.Unlock()
		child.mu.Lock()
		parent.checks = append(parent.checks, child.checks...)
		child.mu.Unlock()
	}
}

// RecordSessionRoute associates a successful underlay choice with an AnyTLS
// carrier. Ordinary protocol dials do not collect or retain these checks.
func RecordSessionRoute(ctx context.Context, valid func() bool) {
	if r, _ := ctx.Value(sessionRouteKey{}).(*sessionRoute); r != nil {
		r.mu.Lock()
		r.checks = append(r.checks, valid)
		r.mu.Unlock()
	}
}

func (s *session) routeValid() bool {
	for _, valid := range s.route {
		if !valid() {
			return false
		}
	}
	return true
}

func (s *session) recordRoute(ctx context.Context) {
	if len(s.route) == 0 {
		return
	}
	if r, _ := ctx.Value(sessionRouteKey{}).(*sessionRoute); r != nil {
		r.mu.Lock()
		r.checks = append(r.checks, s.route...)
		r.mu.Unlock()
	}
}
