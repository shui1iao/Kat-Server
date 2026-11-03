package anytls

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	A "github.com/shui1iao/Kat/internal/anytls"
	"github.com/shui1iao/Kat/internal/outbound"
)

func TestSessionRouteSuccessfulBranchesOnly(t *testing.T) {
	parent := &sessionRoute{}
	ctx := context.WithValue(context.Background(), sessionRouteKey{}, parent)
	failed, _ := SessionRouteBranch(ctx)
	RecordSessionRoute(failed, func() bool { return false }) // no commit on dial error
	good, commit := SessionRouteBranch(ctx)
	RecordSessionRoute(good, func() bool { return true })
	commit()
	s := &session{route: parent.checks}
	if len(s.route) != 1 || !s.routeValid() {
		t.Fatal("failed dial branch contaminated carrier route")
	}
	outer := &sessionRoute{}
	s.recordRoute(context.WithValue(context.Background(), sessionRouteKey{}, outer))
	if len(outer.checks) != 1 {
		t.Fatal("nested reused carrier lost its route")
	}
	if next, commit := SessionRouteBranch(context.Background()); next != context.Background() || commit != nil {
		t.Fatal("ordinary dial unexpectedly tracks route")
	}
}

// Validating a route can call a group event sink which reenters an outbound.
// It must never run with the AnyTLS pool lock held.
func TestSessionRouteValidationOutsidePoolLock(t *testing.T) {
	cert, ks := katFixture(t, A.Config{})
	o := newTestOutbound(t, baseOptions(ks.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert.pin}), &countingDialer{})
	dst := tcpEchoServer(t)
	c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), dst)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	waitIdle(t, o, 1)
	var checked atomic.Int32
	o.mu.Lock()
	o.sessions[0].route = []func() bool{func() bool {
		if !o.mu.TryLock() {
			t.Error("route validator called under pool lock")
			return false
		}
		o.mu.Unlock()
		checked.Add(1)
		return true
	}}
	o.mu.Unlock()
	c, e = o.DialTCP(ctxTimeout(t, 5*time.Second), dst)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if checked.Load() != 1 {
		t.Fatal("route validator not used")
	}
}
