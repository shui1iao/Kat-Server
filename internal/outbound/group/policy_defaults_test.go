package group

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func TestPolicyDefaultsByTypeAndDesktop(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeSmart, TypeFallback, TypeLoadBalance} {
		for _, desktop := range []bool{false, true} {
			for _, interval := range []string{"", `,"interval":"0s"`, `,"interval":"7m"`} {
				var o Options
				text := `{"name":"g","type":"` + kind + `","members":["a"],"probe":{"url":"http://probe.test/"` + interval + `}}`
				if e := json.Unmarshal([]byte(text), &o); e != nil {
					t.Fatal(e)
				}
				o.Probe.ClientHead = desktop
				c, e := normalize(o)
				if e != nil {
					t.Fatal(e)
				}
				wantInterval := 10 * time.Minute
				if desktop || kind == TypeSmart {
					wantInterval = 5 * time.Minute
				}
				if kind == TypeURLTest {
					wantInterval = time.Minute
				}
				if interval == `,"interval":"7m"` {
					wantInterval = 7 * time.Minute
				}
				wantTolerance, wantRelative, wantDwell := 50*time.Millisecond, .2, time.Minute
				if kind == TypeURLTest || kind == TypeSmart {
					wantTolerance, wantRelative, wantDwell = 20*time.Millisecond, .1, 30*time.Second
					if len(c.priority) != 1 || c.priority[0] != 1 {
						t.Fatal("new member weight is not one", c.priority)
					}
				}
				if c.interval != wantInterval || c.tolerance != wantTolerance || c.relative != wantRelative || c.confirms != 2 || c.dwell != wantDwell {
					t.Fatalf("%s desktop=%v source=%s: interval=%v tolerance=%v relative=%v confirms=%v dwell=%v", kind, desktop, interval, c.interval, c.tolerance, c.relative, c.confirms, c.dwell)
				}
				if c.timeout != 5*time.Second || c.expected != nil || c.lazy != (kind != TypeSmart) || c.exploration != 0 || !c.adaptiveDial || c.scope != "site" {
					t.Fatal("unrelated timeout/status/lazy/Smart defaults changed", c)
				}
			}
		}
	}
}

func TestPolicyExplicitDampingAndZeroPreserved(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeSmart} {
		for _, tc := range []struct {
			fields           string
			tolerance, dwell time.Duration
			relative         float64
			confirms         int
		}{
			{`,"tolerance":"75ms","damping":{"relative_improvement":0.35,"confirm_rounds":4,"min_dwell":"2m"}`, 75 * time.Millisecond, 2 * time.Minute, .35, 4},
			{`,"tolerance":0,"damping":{"relative_improvement":0,"min_dwell":"0s"}`, 0, 0, 0, 2},
		} {
			var o Options
			if e := json.Unmarshal([]byte(`{"name":"g","type":"`+kind+`","members":["a"],"probe":{"url":"http://probe.test/","interval":"7m","timeout":"9s"}`+tc.fields+`}`), &o); e != nil {
				t.Fatal(e)
			}
			for round := range 2 {
				c, e := normalize(o)
				if e != nil || c.tolerance != tc.tolerance || c.dwell != tc.dwell || c.relative != tc.relative || c.confirms != tc.confirms || c.interval != 7*time.Minute || c.timeout != 9*time.Second {
					t.Fatal("explicit value/zero changed", kind, round, c, e)
				}
				b, e := json.Marshal(o)
				if e != nil {
					t.Fatal(e)
				}
				if e = json.Unmarshal(b, &o); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
}

func TestPolicyDefaultGateRetainsConfirmationAndDwell(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeSmart} {
		g, c := v2Group(t, kind)
		q := switchGate{}
		q.reset()
		since := c.Now()
		pair := func(at time.Time) bool {
			g.evidence++
			return g.gateLocked(&q, 0, 1, 300, 260, true, since, at, at, at)
		}
		if pair(since) || q.wins != 1 {
			t.Fatal(kind, "one fluctuation promoted", q)
		}
		if pair(since.Add(29*time.Second)) || q.wins != 2 {
			t.Fatal(kind, "confirmation bypassed 30s dwell", q)
		}
		for range 10 {
			if g.gateLocked(&q, 0, 1, 300, 260, true, since, since.Add(29*time.Second), q.currentAt, q.bestAt) || q.wins != 2 {
				t.Fatal(kind, "duplicate evidence counted", q)
			}
		}
		if !pair(since.Add(30 * time.Second)) {
			t.Fatal(kind, "approved default improvement did not pass after dwell", q)
		}
	}
}

func TestPolicyDynamicPriorityAbsentAndNewMembers(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeSmart} {
		for _, fields := range []string{`"use":["p"]`, `"include_all":true`, `"include_all_proxies":true`, `"include_all_providers":true`, `"include_group":"source"`} {
			var o Options
			if e := json.Unmarshal([]byte(`{"name":"g","type":"`+kind+`","members":["a","new"],"priority":{"a":1.5,"gone":0.5},"probe":{"url":"http://probe.test/"},`+fields+`}`), &o); e != nil {
				t.Fatal(e)
			}
			o.Expanded = true
			c, e := normalize(o)
			if e != nil || len(c.priority) != 2 || c.priority[0] != 1.5 || c.priority[1] != 1 || o.Priority["gone"] != .5 {
				t.Fatal("absent preference lost or new member inherited weight", fields, c.priority, e)
			}
			o.Members = []string{"gone", "new", "a"}
			c, e = normalize(o)
			if e != nil || c.priority[0] != .5 || c.priority[1] != 1 || c.priority[2] != 1.5 {
				t.Fatal("weight followed position rather than name", fields, c.priority, e)
			}
		}
	}
}

// A control-plane health failure does not mean this established carrier has
// failed. Automatic decisions must leave it open; no migration is promised.
func TestPolicyAutomaticSwitchKeepsEstablishedTCPUDP(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeSmart} {
		for _, reason := range []string{"performance", "failure"} {
			t.Run(kind+"/"+reason, func(t *testing.T) {
				c := newFakeClock()
				a, b := newFake("a"), newFake("b")
				g := newAuto(t, Options{Type: kind}, members(a, b), c, nil, nil)
				v2Round(g, c, 100*ms_, 200*ms_)
				dst := outbound.Addr{Host: "business.test", Port: 443}
				old, e := g.DialTCP(context.Background(), dst)
				if e != nil {
					t.Fatal(e)
				}
				defer old.Close()
				peer := <-a.peers
				defer peer.Close()
				udp, e := g.ListenPacket(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				defer udp.Close()
				oldPacket := a.lastPC
				if ownerOf(old) != "a" || oldPacket == nil {
					t.Fatal("old flow was not on a")
				}
				c.Advance(30 * time.Second)
				if reason == "failure" {
					c.Advance(time.Second)
					g.RecordProbe("a", 0, c.Now(), errors.New("health verification failed"))
				} else if kind == TypeURLTest {
					for range 5 {
						v2Round(g, c, 300*ms_, 20*ms_)
					}
				} else {
					// Actual write/read observations through the production observer,
					// not probe samples or a forced switch/index assignment.
					for range 6 {
						for range 4 {
							smartBusinessExchange(t, g, c, 0, dst.Host, time.Second)
						}
						for range 4 {
							smartBusinessExchange(t, g, c, 1, dst.Host, 20*ms_)
						}
						c.Advance(5 * time.Second)
					}
				}
				if g.Current() != "b" {
					t.Fatal("automatic switch did not occur", g.Current())
				}
				newTCP, e := g.DialTCP(context.Background(), dst)
				if e != nil {
					t.Fatal(e)
				}
				if ownerOf(newTCP) != "b" {
					newTCP.Close()
					t.Fatal("new TCP did not use b")
				}
				newTCP.Close()
				(<-b.peers).Close()
				newUDP, e := g.ListenPacket(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				defer newUDP.Close()
				if b.lastPC == nil || a.lps != 1 || b.lps != 1 {
					t.Fatal("new UDP did not use b")
				}
				// Both directions still work on the identical old TCP carrier.
				if e := old.SetDeadline(time.Now().Add(2 * time.Second)); e != nil {
					t.Fatal(e)
				}
				done := make(chan error, 1)
				go func() {
					buf := make([]byte, 4)
					_, e := io.ReadFull(peer, buf)
					if e == nil {
						_, e = peer.Write([]byte("pong"))
					}
					done <- e
				}()
				if _, e := old.Write([]byte("ping")); e != nil {
					t.Fatal("old TCP closed on switch", e)
				}
				buf := make([]byte, 4)
				if _, e := io.ReadFull(old, buf); e != nil || string(buf) != "pong" {
					t.Fatal("old TCP no longer usable", string(buf), e)
				}
				if e := <-done; e != nil {
					t.Fatal(e)
				}
				if ownerOf(old) != "a" {
					t.Fatal("old TCP migrated")
				}
				select {
				case <-oldPacket.closed:
					t.Fatal("old UDP closed on switch")
				default:
				}
				if _, e := udp.WriteTo([]byte("ping"), dst); e != nil {
					t.Fatal(e)
				}
				oldPacket.in <- []byte("pong")
				if n, _, e := udp.ReadFrom(buf); e != nil || string(buf[:n]) != "pong" {
					t.Fatal("old UDP no longer usable", e)
				}
				oldPacket.mu.Lock()
				sent := oldPacket.sent
				oldPacket.mu.Unlock()
				if sent != 1 || b.lastPC.sent != 0 {
					t.Fatal("old UDP datagram rerouted to new carrier")
				}
			})
		}
	}
}
