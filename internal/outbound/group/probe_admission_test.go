package group

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func TestBackgroundQueueRetainsFullTargetWindow(t *testing.T) {
	for range cap(backgroundProbeSlots) {
		backgroundProbeSlots <- struct{}{}
	}
	var release sync.Once
	free := func() {
		release.Do(func() {
			for range cap(backgroundProbeSlots) {
				<-backgroundProbeSlots
			}
		})
	}
	defer free()
	prepared := make(chan struct{})
	g := newAuto(t, Options{Type: TypeFallback, Probe: &ProbeOptions{URL: "http://probe.test/", Timeout: outbound.Duration(time.Second), Prepare: func(context.Context, string) error { close(prepared); return nil }}}, members(newFake("a")), realClock{}, nil, nil)
	var remaining time.Duration
	g.probe = func(ctx context.Context, _ outbound.Outbound) (time.Duration, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return 0, errors.New("target not bounded")
		}
		remaining = time.Until(deadline)
		return time.Millisecond, nil
	}
	done := make(chan ProbeSample, 1)
	go func() { done <- g.measuredProbe(context.Background(), 0) }()
	<-prepared
	time.Sleep(250 * time.Millisecond)
	free()
	r := <-done
	if r.Err != nil || r.At.IsZero() || remaining < 900*time.Millisecond || remaining > time.Second {
		t.Fatalf("local queue consumed target window: remaining=%s result=%+v", remaining, r)
	}
}

func TestBackgroundPreflightIsNotHealthEvidence(t *testing.T) {
	for _, mode := range []string{"queue", "dependency", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			p := &ProbeOptions{URL: "http://probe.test/", Timeout: outbound.Duration(30 * time.Millisecond)}
			if mode == "queue" {
				for range cap(backgroundProbeSlots) {
					backgroundProbeSlots <- struct{}{}
				}
				defer func() {
					for range cap(backgroundProbeSlots) {
						<-backgroundProbeSlots
					}
				}()
			}
			if mode == "dependency" {
				p.Prepare = func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() }
			}
			g := newAuto(t, Options{Type: TypeFallback, Probe: p}, members(newFake("a")), realClock{}, nil, nil)
			calls := 0
			g.probe = func(context.Context, outbound.Outbound) (time.Duration, error) {
				calls++
				return 0, errors.New("must not reach target")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			for range 2 {
				r := g.measuredProbe(ctx, 0)
				if !r.At.IsZero() || r.Err == nil {
					t.Fatalf("preflight manufactured target evidence: %+v", r)
				}
				g.RecordProbeRound([]ProbeSample{r})
				g.mu.Lock()
				g.addProbeLocked(0, r) // recovery's direct acceptance path must also reject it
				g.mu.Unlock()
			}
			if calls != 0 || g.st[0].probed || g.st[0].consec != 0 || g.st[0].probeFailures != 0 || g.completeRound || !g.freezeUntil.IsZero() {
				t.Fatalf("local preflight changed health/readiness: calls=%d state=%+v", calls, g.st[0])
			}
		})
	}
}

func TestBackgroundColdDependencyPreparesWithoutHoldingSlots(t *testing.T) {
	child := newAuto(t, Options{Name: "child", Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", Timeout: outbound.Duration(3 * time.Second)}}, members(newFake("leaf")), realClock{}, nil, nil)
	childEntered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	defer free()
	child.probe = func(ctx context.Context, _ outbound.Outbound) (time.Duration, error) {
		close(childEntered)
		select {
		case <-release:
			return time.Millisecond, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	child.Start(context.Background()) // lazy; WaitReady triggers the complete first round
	preparing := make(chan struct{}, 4)
	p := &ProbeOptions{URL: "http://probe.test/", Timeout: outbound.Duration(3 * time.Second), Prepare: func(ctx context.Context, _ string) error {
		preparing <- struct{}{}
		return child.WaitReady(ctx)
	}}
	parent := newAuto(t, Options{Name: "parent", Type: TypeFallback, Probe: p}, members(newFake("a"), newFake("b"), newFake("c"), newFake("d")), realClock{}, nil, nil)
	parent.probe = func(context.Context, outbound.Outbound) (time.Duration, error) {
		child.mu.Lock()
		ready := child.completeRound
		child.mu.Unlock()
		if !ready {
			return 0, errors.New("parent bypassed full first-round gate")
		}
		return time.Millisecond, nil
	}
	done := make(chan ProbeSample, 4)
	for i := range 4 {
		go func() { done <- parent.measuredProbe(context.Background(), i) }()
	}
	for range 4 {
		select {
		case <-preparing:
		case <-time.After(5 * time.Second):
			t.Fatal("preparation blocked")
		}
	}
	select {
	case <-childEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("child starved behind parents")
	}
	if n := len(backgroundProbeSlots); n != 1 {
		t.Fatalf("parents held shared HTTP slots during dependency wait: %d", n)
	}
	free()
	for range 4 {
		r := <-done
		if r.Err != nil || r.At.IsZero() {
			t.Fatalf("parent failed after ready dependency: %+v", r)
		}
	}
}

func TestBackgroundNewlyColdDependencyDoesNotConvictTarget(t *testing.T) {
	child := newAuto(t, Options{Name: "newly-selected", Type: TypeURLTest}, members(newFake("leaf")), realClock{}, nil, nil)
	child.probe = func(ctx context.Context, _ outbound.Outbound) (time.Duration, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	child.Start(context.Background())
	parent := newAuto(t, Options{Type: TypeFallback}, members(newFake("route")), realClock{}, nil, nil)
	// A selected/fixed path may change after successful preflight. Simulate the
	// eventual dial reaching a URLTest that was not cold at preflight time.
	parent.probe = func(ctx context.Context, _ outbound.Outbound) (time.Duration, error) { return 0, child.awaitFirst(ctx) }
	r := parent.measuredProbe(context.Background(), 0)
	if !errors.Is(r.Err, errProbeDependencyUnready) || !r.At.IsZero() {
		t.Fatalf("target waited under shared capacity or acquired false health: %+v", r)
	}
	parent.RecordProbeRound([]ProbeSample{r})
	if parent.st[0].probed || parent.st[0].consec != 0 {
		t.Fatal("dependency race became target failure")
	}
}
