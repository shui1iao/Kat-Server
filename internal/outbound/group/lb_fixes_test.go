package group

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func TestLBFixedTransientDialFallbackAllStrategies(t *testing.T) {
	for _, strategy := range []string{StrategyRoundRobin, StrategyConsistentHashing, StrategyStickySessions} {
		t.Run(strategy, func(t *testing.T) {
			a, b := newFake("a"), newFake("b")
			a.setErr(errors.New("temporary fixed dial failure"))
			g := newAuto(t, Options{Type: TypeLoadBalance, Strategy: strategy, Fixed: "a"}, members(a, b), newFakeClock(), nil, nil)
			c, err := g.DialTCP(context.Background(), outbound.Addr{Host: "target.test", Port: 80})
			if err != nil {
				t.Fatalf("fixed failed without live alternative: a=%d b=%d err=%v", a.dialCount(), b.dialCount(), err)
			}
			c.Close()
			(<-b.peers).Close()
			if a.dialCount() != 1 || b.dialCount() != 1 || g.Snapshot().Fixed != "a" || g.cur != 0 {
				t.Fatal("transient fallback changed fixed/current or retry order", g.Snapshot())
			}
			a.setErr(nil)
			c, err = g.DialTCP(context.Background(), outbound.Addr{Host: "target.test", Port: 80})
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
			(<-a.peers).Close()
			if a.dialCount() != 2 || b.dialCount() != 1 || g.Current() != "a" {
				t.Fatal("available fixed did not regain first preference")
			}
		})
	}
}

func TestLBFixedRetriesKeepThreeAndSharedBudget(t *testing.T) {
	for _, strategy := range []string{StrategyRoundRobin, StrategyConsistentHashing, StrategyStickySessions} {
		for _, exhausted := range []bool{false, true} {
			var ms []outbound.Outbound
			var fs []*fakeOut
			for _, name := range []string{"a", "b", "c", "d", "e"} {
				f := newFake(name)
				f.setErr(errors.New("down"))
				fs = append(fs, f)
				ms = append(ms, f)
			}
			g := newAuto(t, Options{Type: TypeLoadBalance, Strategy: strategy, Fixed: "a"}, ms, newFakeClock(), nil, nil)
			ctx := withDialBudget(context.Background())
			want := 3
			if exhausted {
				retryBudget(ctx)
				retryBudget(ctx)
				want = 1
			}
			if _, err := g.DialTCP(ctx, outbound.Addr{Host: "target.test", Port: 80}); err == nil {
				t.Fatal("all-down succeeded")
			}
			total := 0
			for _, f := range fs {
				total += f.dialCount()
				if f.dialCount() > 1 {
					t.Fatal("member retried", f.Name())
				}
			}
			if total != want || fs[0].dialCount() != 1 || g.Snapshot().Fixed != "a" {
				t.Fatalf("strategy=%s exhausted=%v attempts=%d want=%d", strategy, exhausted, total, want)
			}
		}
	}
}

func TestLBProbeBusinessAndCancelFailureOwnership(t *testing.T) {
	for _, strategy := range []string{StrategyRoundRobin, StrategyConsistentHashing, StrategyStickySessions} {
		t.Run(strategy, func(t *testing.T) {
			clk := newFakeClock()
			a, b := newFake("a"), newFake("b")
			a.setErr(errors.New("down"))
			b.setErr(errors.New("down"))
			g := newAuto(t, Options{Type: TypeLoadBalance, Strategy: strategy, Fixed: "a"}, members(a, b), clk, nil, nil)
			dst := outbound.Addr{Host: "target.test", Port: 80}
			if _, err := g.DialTCP(WithProbeMeasurement(context.Background(), &ProbeMeasurement{}), dst); err == nil {
				t.Fatal("failed probe unexpectedly succeeded")
			}
			if g.st[0].consec != 0 || g.st[1].consec != 0 {
				t.Fatal("probe failure counted as business", g.Snapshot())
			}
			if _, err := g.DialTCP(context.Background(), dst); err == nil {
				t.Fatal("failed business unexpectedly succeeded")
			}
			if g.st[0].consec != 1 || g.st[1].consec != 1 {
				t.Fatal("real business failures were suppressed", g.Snapshot())
			}
			ctx, cancel := context.WithCancel(context.Background())
			a.onDial = func(context.Context, outbound.Addr) (net.Conn, error) { cancel(); return nil, context.Canceled }
			g.DialTCP(ctx, dst)
			if g.st[0].consec != 1 || g.st[1].consec != 1 {
				t.Fatal("caller cancellation changed business health")
			}
			a.onDial = nil
			a.setErr(nil)
			c, err := g.DialTCP(WithProbeMeasurement(context.Background(), &ProbeMeasurement{}), dst)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
			(<-a.peers).Close()
			if g.st[0].consec != 1 {
				t.Fatal("probe dial success changed business evidence")
			}
			// Explicit valid HTTP health evidence must NOT be disabled by probe
			// business isolation: it still recovers the measured member normally.
			at := clk.Now().Add(time.Second)
			g.RecordProbeRound([]ProbeSample{{Name: "a", At: at, Latency: time.Millisecond}, {Name: "b", At: at, Latency: time.Millisecond}})
			if !g.st[0].probed || !g.st[0].probeOK || g.st[0].consec != 0 {
				t.Fatal("valid probe health was suppressed", g.Snapshot())
			}
		})
	}
}
