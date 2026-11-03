package group

import (
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"net/netip"
	"testing"
	"time"
)

func TestRound2NestedFallbackStates(t *testing.T) {
	clk := newFakeClock()
	hk := newAuto(t, Options{Name: "HK", Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("hk1"), newFake("hk2")), clk, nil, nil)
	sg := newAuto(t, Options{Name: "SG", Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("sg1")), clk, nil, nil)
	final := newAuto(t, Options{Name: "Final", Type: TypeFallback, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, []outbound.Outbound{hk, sg}, clk, nil, nil)
	check := func(stage, want string) {
		t.Helper()
		got := final.Current()
		t.Logf("%s: Final=%s HK_al ive=%v HK_current=%s", stage, got, hk.ClientAlive(), hk.Current())
		if got != want {
			t.Fatalf("want %s got %s", want, got)
		}
	}
	check("both child groups untested", "HK")
	at := clk.Now()
	hk.RecordProbe("hk1", 0, at, errors.New("probe failure"))
	check("HK current leaf failed once, hk2 untested", "HK")
	hk.RecordProbe("hk2", 0, at, errors.New("probe failure"))
	check("all HK leaves latest probe failed, SG untested", "SG")
	final.RecordProbe("HK", 20*time.Millisecond, at.Add(time.Second), nil)
	check("parent once successful cannot bypass recovery", "SG")
	clk.Advance(6 * time.Second)
	final.RecordProbe("HK", 20*time.Millisecond, clk.Now(), nil)
	check("two parent successes still need hold", "SG")
	clk.Advance(5 * time.Second)
	check("parent fresher stable health overrides old child failure", "HK")
	hk.RecordProbe("hk2", 30*time.Millisecond, at.Add(2*time.Second), nil)
	check("one HK child recovers", "HK")
	single := newAuto(t, Options{Name: "singleHK", Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("only")), clk, nil, nil)
	parent := newAuto(t, Options{Name: "P", Type: TypeFallback, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, []outbound.Outbound{single, sg}, clk, nil, nil)
	single.RecordProbe("only", 0, at, errors.New("one failed test"))
	if parent.Current() != "SG" {
		t.Fatal("single-leaf HK failure must select SG")
	}
	t.Log("one-leaf HK: one failed health sample => SG")
}

func TestRound2SoftFixedLifecycle(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeSmart, TypeFallback, TypeLoadBalance} {
		t.Run(kind, func(t *testing.T) {
			clk := newFakeClock()
			g := newAuto(t, Options{Type: kind, Fixed: "b", Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a"), newFake("b")), clk, nil, nil)
			at := clk.Now()
			g.RecordProbe("a", 10*time.Millisecond, at, nil)
			g.RecordProbe("b", 40*time.Millisecond, at, nil)
			check := func(want string) {
				t.Helper()
				if g.Current() != want || g.Snapshot().Current != want {
					t.Fatalf("current=%s snapshot=%s want=%s", g.Current(), g.Snapshot().Current, want)
				}
				g.mu.Lock()
				var cs []int
				if kind == TypeLoadBalance {
					cs = g.lbOrderLocked(netip.Addr{}, "test", false, at, nil)
				} else {
					cs = g.candidatesLocked("test", false, at)
				}
				g.mu.Unlock()
				if len(cs) == 0 || g.cfg.members[cs[0]] != want {
					t.Fatalf("candidates=%v want %s", cs, want)
				}
			}
			check("b")
			g.RecordProbe("b", 0, at.Add(time.Second), errors.New("failed"))
			if kind == TypeFallback {
				check("b")
				acceptedFallbackFailure(t, g, clk, "b")
				at = clk.Now()
			}
			check("a")
			if g.cfg.fixed != "b" {
				t.Fatal("lost fixed on failure")
			}
			g.RecordProbe("b", 40*time.Millisecond, at.Add(2*time.Second), nil)
			check("a")
			clk.Advance(7 * time.Second)
			g.RecordProbe("b", 40*time.Millisecond, clk.Now(), nil)
			check("a")
			clk.Advance(5 * time.Second)
			check("b")
			// Unpin is a document replacement, as desktop document.apply does.
			unpinned := newAuto(t, Options{Type: kind, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a"), newFake("b")), clk, nil, nil)
			if unpinned.Snapshot().Fixed != "" {
				t.Fatal("unpin persisted")
			}
			if kind == TypeSmart {
				if unpinned.Current() != "" {
					t.Fatal("cold Smart selected before complete round")
				}
				v2Round(unpinned, clk, 10*time.Millisecond, 40*time.Millisecond)
			}
			if unpinned.Current() != "a" {
				t.Fatal("unpin did not restore automatic")
			}
		})
	}
}
