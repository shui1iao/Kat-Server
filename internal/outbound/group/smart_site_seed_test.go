package group

import (
	"errors"
	"testing"
	"time"
)

// A site's cache entry can disappear while an older flow/attempt is alive.
// A single report must neither reintroduce member zero nor promote its owner.
func TestSmartOldReportRetainsCurrentSiteSeed(t *testing.T) {
	for _, report := range []string{"observer_success", "observer_failure", "dial_failure", "legacy_success", "legacy_failure"} {
		for _, state := range []string{"lru_evicted", "ttl_expired", "existing"} {
			t.Run(report+"/"+state, func(t *testing.T) {
				clk := newFakeClock()
				g := newAuto(t, Options{Type: TypeSmart}, members(newFake("a"), newFake("b"), newFake("c")), clk, nil, nil)
				key := siteKey("old-flow.example", 443, "tcp")
				// Model an older explicit/alternative flow on a; beforeWrite has
				// not happened, so an idle connection may outlive the site's TTL.
				original := g.sites.ensure(key, clk.Now(), g.cur)
				obs := g.smartObserver(0, key, 0)
				t.Cleanup(obs.close)
				clk.Advance(time.Second)
				g.RecordProbeRound([]ProbeSample{
					{Name: "a", Latency: 300 * time.Millisecond, At: clk.Now()},
					{Name: "b", Latency: 20 * time.Millisecond, At: clk.Now()},
					{Name: "c", Latency: 100 * time.Millisecond, At: clk.Now()},
				})
				if g.Current() != "b" || original.current != 1 {
					t.Fatal("fixture did not bootstrap non-first group/site choice", g.Current(), original.current)
				}
				want := g.cur
				switch state {
				case "lru_evicted":
					g.sites.cap = 1
					g.sites.ensure(siteKey("other.example", 443, "tcp"), clk.Now(), g.cur)
					if g.sites.get(key, clk.Now()) != nil {
						t.Fatal("fixture did not evict entry")
					}
				case "ttl_expired":
					clk.Advance(smartSiteTTL)
					if g.sites.get(key, clk.Now()) != nil {
						t.Fatal("fixture did not expire entry")
					}
				case "existing":
					// An existing site's preference may differ from the group.
					original.current, want = 2, 2
				}
				switch report {
				case "observer_success":
					obs.beforeWrite(1)
					clk.Advance(time.Millisecond)
					obs.afterRead(1, nil)
				case "observer_failure":
					obs.beforeWrite(1)
					obs.afterRead(0, errors.New("old connection failed"))
				case "dial_failure":
					g.smartAttemptFailure(0, key, false)
				case "legacy_success":
					g.realSuccess(0, key, time.Millisecond, true)
				case "legacy_failure":
					g.realFailure(0, key, false)
				}
				e := g.sites.get(key, clk.Now())
				if e == nil || e.current != want || g.Current() != "b" {
					t.Fatalf("report changed choice: entry=%+v want_site=%d group=%q", e, want, g.Current())
				}
				if (state == "existing") != (e == original) {
					t.Fatal("unexpected cache entry identity")
				}
				r := e.recs[0]
				if r == nil {
					t.Fatal("report hidden instead of recorded")
				}
				if report == "observer_success" || report == "legacy_success" {
					if r.okAt.IsZero() || !r.failAt.IsZero() {
						t.Fatal("successful evidence lost", r)
					}
				} else if r.failAt.IsZero() || r.failures != 1 {
					t.Fatal("failure evidence lost", r)
				}
			})
		}
	}
}
