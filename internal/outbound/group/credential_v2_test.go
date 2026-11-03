package group

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// The real credential E2E used twelve *different* sites inside 1.2s. An EOF
// after a successful dial is not proof of a proxy-wide credential error: v2
// must avoid that site immediately, then correlate two hosts with its 5s
// directed verification. Exercise the actual write/read observer, not only
// smartAttemptFailure, and prove that no written payload is replayed.
func TestV2CredentialEOFSiteFailoverAndDirectedAttribution(t *testing.T) {
	for _, scope := range []string{"site", "group"} {
		for _, hosts := range []int{1, 2} {
			t.Run(scope+string(rune('0'+hosts)), func(t *testing.T) {
				clk := newFakeClock()
				a, b := newFake("a"), newFake("b")
				p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond, "b": 150 * time.Millisecond})
				lazy := true
				ev := &eventLog{}
				g := newAuto(t, Options{Type: TypeSmart, Lazy: &lazy, Smart: &SmartOptions{Scope: scope}}, members(a, b), clk, p, ev)
				g.Start(context.Background())
				probeNow(t, g)
				p.set("a", 0, true) // credential rotated after the complete successful round
				for i := 0; i < hosts; i++ {
					host := string(rune('a'+i)) + ".example"
					key := siteKey(host, 443, "tcp")
					c, e := g.DialTCP(context.Background(), outbound.Addr{Host: host, Port: 443})
					if e != nil {
						t.Fatal(e)
					}
					if ownerOf(c) != "a" {
						t.Fatal("new site's prior was already convicted")
					}
					peer := <-a.peers
					read := make(chan error, 1)
					go func() { defer peer.Close(); _, e := io.ReadFull(peer, make([]byte, 4)); read <- e }()
					if _, e := c.Write([]byte("data")); e != nil {
						t.Fatal(e)
					}
					if _, e := c.Read(make([]byte, 1)); e != io.EOF {
						t.Fatal("expected credential-like EOF", e)
					}
					c.Close()
					if e := <-read; e != nil {
						t.Fatal(e)
					}
					if b.dialCount() != i {
						t.Fatal("written data was retried on backup")
					}
					if got := dial(t, g, host); got != "b" {
						t.Fatal("next same-site connection must avoid failed member", got)
					}
					(<-b.peers).Close()
					g.mu.Lock()
					local := g.sites.get(key, clk.Now()).failedRecently(0, clk.Now())
					penalty := g.st[0].real.failure
					down := g.st[0].recovery.down
					g.mu.Unlock()
					if !local || down || penalty != 0 || g.Current() != "a" {
						t.Fatal("ambiguous EOF incorrectly punished entire proxy")
					}
				}
				clk.Advance(5*time.Second - time.Nanosecond)
				if p.count("a") != 1 || len(switches(ev)) != 1 || switches(ev)[0] != ">a" {
					t.Fatalf("verification ran before 5s: a=%d b=%d switches=%v", p.count("a"), p.count("b"), switches(ev))
				}
				clk.Advance(time.Nanosecond)
				deadline := time.Now().Add(time.Second)
				for {
					g.mu.Lock()
					down, step := g.st[0].recovery.down, g.st[0].recoveryStep
					g.mu.Unlock()
					if down || step > 0 {
						if down != (hosts == 2) {
							t.Fatal("directed verification did not require two distinct hosts", hosts, down)
						}
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("directed verification did not commit")
					}
					time.Sleep(time.Millisecond)
				}
				if p.count("a") != 2 || p.count("b") != 1 {
					t.Fatal("verification was not one targeted probe", p.count("a"), p.count("b"))
				}
				if hosts == 2 {
					if g.Current() != "b" {
						t.Fatal("confirmed credential fault not avoided immediately")
					}
					if got := dial(t, g, "unseen.example"); got != "b" {
						t.Fatal("fresh site still uses revoked credential", got)
					}
					(<-b.peers).Close()
				} else if g.Current() != "a" {
					t.Fatal("one destination globally demoted proxy")
				}
			})
		}
	}
}
