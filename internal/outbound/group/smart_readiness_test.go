package group

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func TestSmartFirstRoundWaitsForAllAndWeightsNormalProbe(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	g := newAuto(t, Options{Type: TypeSmart, Priority: map[string]float64{"a": .01}}, members(a, b), clk, nil, nil)
	release, fast := make(chan struct{}), make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	defer free()
	g.probe = func(ctx context.Context, m outbound.Outbound) (time.Duration, error) {
		if m.Name() == "b" {
			close(fast)
			return 20 * time.Millisecond, nil
		}
		select {
		case <-release:
			return 300 * time.Millisecond, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	g.Start(context.Background())
	<-fast
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if c, err := g.DialTCP(ctx, outbound.Addr{Host: "cold.example", Port: 443}); c != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("partial/fastest result admitted a business dial", c, err)
	}
	if a.dialCount()+b.dialCount() != 0 || g.Current() != "" || g.Snapshot().Current != "" {
		t.Fatal("cold selection/traffic fabricated")
	}
	free()
	waitRounds(t, g, 1)
	if got := dial(t, g, "warm.example"); got != "a" {
		t.Fatal("full normal-probe weighted winner lost", got)
	}
	(<-a.peers).Close()
	if g.Snapshot().Current != "a" {
		t.Fatal("first actual selection not projected")
	}
}

func TestSmartIncompleteOrFailedFirstRoundIsNotReady(t *testing.T) {
	for _, mode := range []string{"all_failed", "preflight_failed"} {
		t.Run(mode, func(t *testing.T) {
			p := &ProbeOptions{URL: "http://probe.test/"}
			if mode == "preflight_failed" {
				p.Prepare = func(context.Context, string) error { return errors.New("no admission") }
			}
			a, b := newFake("a"), newFake("b")
			g := newAuto(t, Options{Type: TypeSmart, Probe: p}, members(a, b), newFakeClock(), nil, nil)
			g.probe = func(context.Context, outbound.Outbound) (time.Duration, error) { return 0, errors.New("probe down") }
			g.Start(context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := g.WaitReady(ctx); !errors.Is(err, errProbeDependencyUnready) {
				t.Fatal("failed/incomplete round became ready or waited forever", err)
			}
			if g.Current() != "" || g.Snapshot().Current != "" || a.dialCount()+b.dialCount() != 0 {
				t.Fatal("failed first round fell back to index zero")
			}
			select {
			case <-g.firstReady:
				t.Fatal("failed round closed successful-readiness signal")
			default:
			}
		})
	}
}

func TestSmartExplicitFixedAndWarmInheritanceKeepNoWait(t *testing.T) {
	p := newFakeProbe(nil)
	p.block = make(chan struct{})
	g := newAuto(t, Options{Type: TypeSmart, Fixed: "b"}, members(newFake("a"), newFake("b")), newFakeClock(), p, nil)
	g.Start(context.Background())
	defer close(p.block)
	if got := dial(t, g, "fixed.example"); got != "b" || g.Current() != "b" || g.Snapshot().Current != "b" {
		t.Fatal("manual fixed was hidden or forced to wait", got)
	}
	(<-g.members[1].(*fakeOut).peers).Close()

	old, clk := v2Group(t, TypeSmart)
	v2Round(old, clk, 200*time.Millisecond, 20*time.Millisecond)
	warm := newAuto(t, Options{Type: TypeSmart, Priority: map[string]float64{"a": 1.5}}, members(newFake("a"), newFake("b")), clk, nil, nil)
	warm.InheritLearning(old)
	if warm.cold || warm.Current() != "b" || warm.WaitReady(context.Background()) != nil {
		t.Fatal("same-identity inheritance reopened cold gate")
	}
	select {
	case <-warm.firstReady:
	default:
		t.Fatal("inherited bootstrap lost ready state")
	}
	if got := dial(t, warm, "inherited.example"); got != "b" {
		t.Fatal("warm path retested/changed member", got)
	}
	(<-warm.members[1].(*fakeOut).peers).Close()
}

func TestSmartDependencyPreflightAndPreparedRace(t *testing.T) {
	child := newAuto(t, Options{Name: "child", Type: TypeSmart}, members(newFake("leaf")), realClock{}, nil, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	defer free()
	child.probe = func(ctx context.Context, _ outbound.Outbound) (time.Duration, error) {
		close(entered)
		select {
		case <-release:
			return time.Millisecond, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	child.Start(context.Background())
	<-entered
	preparing := make(chan struct{})
	parent := newAuto(t, Options{Type: TypeFallback, Probe: &ProbeOptions{URL: "http://probe.test/", Prepare: func(ctx context.Context, _ string) error { close(preparing); return child.WaitReady(ctx) }}}, members(newFake("route")), realClock{}, nil, nil)
	parent.probe = func(context.Context, outbound.Outbound) (time.Duration, error) { return time.Millisecond, nil }
	done := make(chan ProbeSample, 1)
	go func() { done <- parent.measuredProbe(context.Background(), 0) }()
	<-preparing
	// The newly-cold race must return before child readiness, not hold a
	// parent's HTTP capacity waiting for the same child's first round.
	prepared := context.WithValue(context.Background(), preparedProbeKey{}, true)
	if err := child.WaitReady(prepared); !errors.Is(err, errProbeDependencyUnready) {
		t.Fatal("prepared target waited for cold Smart", err)
	}
	if n := len(backgroundProbeSlots); n != 1 {
		t.Fatal("preflight held parent HTTP slot", n)
	}
	free()
	r := <-done
	if r.Err != nil || r.At.IsZero() || child.Current() != "leaf" {
		t.Fatal("preflight did not prepare full child bootstrap", r)
	}
}
