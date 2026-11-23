package kernel

import (
	"errors"
	"github.com/shui1iao/Kat/internal/stats"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Once the credential is recognized, parser errors belong to Kat, not to
// the web backend. Include both boundaries of the authenticated header.
func TestMatchedTrojanErrorsStayPrivate(t *testing.T) {
	in := inFor("trojan", nil)
	base := peerHeader("trojan", 1, Address{"example.test", 443})
	for _, pos := range []int{56, 57, 58, len(base) - 1} {
		h := append([]byte{}, base...)
		h[pos] = 0xff
		c, w := net.Pipe()
		done := make(chan struct{})
		go func() { defer close(done); defer w.Close(); _, _ = w.Write(h) }()
		req, e := parseTrojan(c, in)
		c.Close()
		<-done
		var fb *trojanReject
		if e == nil || req.UserIndex < 0 || errors.As(e, &fb) {
			t.Fatalf("offset %d: matched request was accepted or marked for fallback", pos)
		}
	}
}
func TestUDPSelectsPermittedCandidate(t *testing.T) {
	a := udpAssociation{server: &Server{}, outbound4: &net.UDPConn{}}
	denied := netip.MustParseAddrPort("127.0.0.1:443")
	allowed := netip.MustParseAddrPort("192.0.2.1:443")
	noFamily := netip.MustParseAddrPort("[2001:db8::1]:443")
	if v, s, b := a.selectDestination([]netip.AddrPort{denied, allowed}); v != allowed || s != a.outbound4 || b {
		t.Fatal(v, s, b)
	}
	if _, s, b := a.selectDestination([]netip.AddrPort{denied}); s != nil || !b {
		t.Fatal("all denied not reported")
	}
	if _, s, b := a.selectDestination([]netip.AddrPort{denied, noFamily}); s != nil || b {
		t.Fatal("unavailable family classified as all denied")
	}
}
func TestStatsQuarantineFailurePausesAcrossReload(t *testing.T) {
	p := filepath.Join(t.TempDir(), "usage.json")
	if e := os.WriteFile(p, []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	k := &core{lockedFile: p, reg: stats.New(nil, nil, nil, time.Now())}
	c := Config{Stats: &StatsOptions{File: p}}
	called := false
	k.loadStatsWith(&c, func(string, time.Time) (string, error) { called = true; return "", os.ErrPermission })
	if !called || k.statsPath != "" || k.quarantineBlocked != p {
		t.Fatal("failed quarantine not protected")
	}
	plan, e := k.prepareState(&c)
	if e != nil {
		t.Fatal(e)
	}
	if plan.persist != "" || len(plan.files) > 0 {
		plan.abort()
		t.Fatal("reload would overwrite original")
	}
	plan.commit()
	if e = k.saveStats(); e != nil {
		t.Fatal(e)
	}
	if b, e := os.ReadFile(p); e != nil || string(b) != "corrupt" {
		t.Fatal("lost original", e)
	}
}
func TestSourceGuardSweepBoundedAndFair(t *testing.T) {
	g := newSourceGuard(&core{})
	defer g.close()
	now := time.Now()
	n := 2*guardSweepBatch + 1
	for i := 0; i < n; i++ {
		key := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
		w := &failWindow{start: now.Add(-2 * defaultBanWindow), expiry: guardExpiry{index: -1}}
		g.fails[key] = w
		g.failExpiry.set(&w.expiry, key, w.start)
		b := &banEntry{until: now.Add(-time.Second), expiry: guardExpiry{index: -1}}
		g.bans[key] = b
		g.banExpiry.set(&b.expiry, key, b.until)
	}
	g.nbans.Store(int64(n))
	for _, left := range []int{n - guardSweepBatch, 1, 0} {
		g.sweepLocked(now)
		if len(g.fails) != left || len(g.bans) != left || g.nbans.Load() != int64(left) {
			t.Fatalf("batch did not stop at %d", left)
		}
	}
	if g.moreExpiredLocked(now) {
		t.Fatal("sweep did not drain")
	}
}
