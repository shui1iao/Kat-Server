package group

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"testing"
	"time"
)

func TestURLTestColdSharedTCPUDPAndCancellation(t *testing.T) {
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond, "b": 2 * time.Millisecond})
	p.set("a", 0, true)
	p.block = make(chan struct{})
	g := newAuto(t, Options{Type: TypeURLTest}, members(a, b), newFakeClock(), p, nil)
	g.Start(context.Background())
	// Two TCP callers and a UDP caller share one round; a short caller may
	// leave without killing the round needed by the other callers.
	ctx, cancel := context.WithCancel(context.Background())
	short := make(chan error, 1)
	go func() {
		c, e := g.DialTCP(ctx, outbound.Addr{Host: "x.test", Port: 443})
		if c != nil {
			c.Close()
		}
		short <- e
	}()
	results := make(chan string, 2)
	go func() {
		c, e := g.DialTCP(context.Background(), outbound.Addr{Host: "x.test", Port: 443})
		if e != nil {
			results <- "error"
			return
		}
		defer c.Close()
		results <- ownerOf(c)
	}()
	go func() {
		pc, e := g.ListenPacket(context.Background())
		if e != nil {
			results <- "error"
			return
		}
		defer pc.Close()
		results <- pc.(*fakePC).owner
	}()
	deadline := time.Now().Add(time.Second)
	for !isProbing(g) {
		if time.Now().After(deadline) {
			t.Fatal("no shared round")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if e := <-short; !errors.Is(e, context.Canceled) {
		t.Fatal("short caller did not cancel")
	}
	select {
	case <-results:
		t.Fatal("unprobed member used")
	default:
	}
	close(p.block)
	for i := 0; i < 2; i++ {
		select {
		case got := <-results:
			if got != "b" {
				t.Fatal("did not select healthy member")
			}
		case <-time.After(time.Second):
			t.Fatal("shared wait stuck")
		}
	}
	waitRounds(t, g, 1)
	if p.count("a") != 1 || p.count("b") != 1 || a.dialCount() != 0 {
		t.Fatal("duplicate round or failed first member used")
	}
}
func TestURLTestColdWaitReleasedByLifecycle(t *testing.T) {
	for _, closeGroup := range []bool{false, true} {
		t.Run(map[bool]string{false: "parent", true: "close"}[closeGroup], func(t *testing.T) {
			p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond})
			p.block = make(chan struct{})
			g := newAuto(t, Options{Type: TypeURLTest}, members(newFake("a")), newFakeClock(), p, nil)
			life, cancel := context.WithCancel(context.Background())
			defer cancel()
			g.Start(life)
			done := make(chan error, 1)
			go func() { _, e := g.ListenPacket(context.Background()); done <- e }()
			deadline := time.Now().Add(time.Second)
			for !isProbing(g) {
				if time.Now().After(deadline) {
					t.Fatal("not probing")
				}
				time.Sleep(time.Millisecond)
			}
			if closeGroup {
				g.Close()
			} else {
				cancel()
			}
			select {
			case e := <-done:
				if !errors.Is(e, context.Canceled) {
					t.Fatal("wait not canceled")
				}
			case <-time.After(time.Second):
				t.Fatal("lifecycle wait leaked")
			}
		})
	}
}
func TestURLTestPartialManualRoundDoesNotAdmitColdRequest(t *testing.T) {
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond, "b": 2 * time.Millisecond})
	p.set("a", 0, true)
	p.block = make(chan struct{})
	g := newAuto(t, Options{Type: TypeURLTest}, members(a, b), newFakeClock(), p, nil)
	g.Start(context.Background())
	g.RecordProbe("a", time.Millisecond, time.Now(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, e := g.ListenPacket(ctx)
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("partial manual round was mistaken for complete readiness")
	}
	close(p.block)
	waitRounds(t, g, 1)
}
func TestURLTestFixedDoesNotWaitForColdProbe(t *testing.T) {
	p := newFakeProbe(nil)
	p.block = make(chan struct{})
	g := newAuto(t, Options{Type: TypeURLTest, Fixed: "b"}, members(newFake("a"), newFake("b")), newFakeClock(), p, nil)
	g.Start(context.Background())
	defer close(p.block)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, e := g.DialTCP(ctx, outbound.Addr{Host: "x.test", Port: 443})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if ownerOf(c) != "b" {
		t.Fatal("fixed changed")
	}
}
