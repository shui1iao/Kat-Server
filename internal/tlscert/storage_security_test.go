package tlscert

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileValidityGatesAndFutureActivation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	write := func(c, k []byte) {
		t.Helper()
		if e := os.WriteFile(cp, c, 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(kp, k, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(pemPair(t, 1, now.Add(time.Hour), "example.test"))
	c, s, e := LoadPair(cp, kp)
	if e != nil {
		t.Fatal(e)
	}
	f := NewFilePair(cp, kp, c, s)
	write(pemPair(t, 2, now.Add(-time.Minute), "example.test"))
	if _, _, e = LoadPair(cp, kp); e == nil {
		t.Fatal("expired files admitted")
	}
	write(pemPair(t, 3, now.Add(3*time.Hour), "example.test"))
	if _, _, e = LoadPair(cp, kp); !errors.Is(e, errFuture) {
		t.Fatal(e)
	}
	if r, _ := f.Check(now); r != Refused || f.Certificate() != c {
		t.Fatal("future cert replaced active")
	}
	if r, e := f.Check(now.Add(time.Hour)); r != Replaced || e != nil {
		t.Fatal("future cert did not become usable", r, e)
	}
}
func TestAtomicBundleRefusalRetainsGeneration(t *testing.T) {
	m, e := NewManager(Options{Domains: []string{"a.example"}, Storage: t.TempDir()}, Hooks{})
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	c1, k1 := pemPair(t, 1, now.Add(time.Hour), "a.example")
	c2, k2 := pemPair(t, 2, now.Add(time.Hour), "a.example")
	if _, e = m.storePair(c1, k1); e != nil {
		t.Fatal(e)
	}
	if _, e = m.storePair(c2, k1); e == nil {
		t.Fatal("invalid generation installed")
	}
	if c := m.loadStored(); c == nil || c.Leaf.SerialNumber.Int64() != 1 {
		t.Fatal("lost matching previous pair")
	}
	if _, e = m.storePair(c2, k2); e != nil {
		t.Fatal(e)
	}
	if c := m.loadStored(); c == nil || c.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("new generation unreadable")
	}
	st, e := os.Stat(filepath.Join(m.certDir(), "pair.pem"))
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("private bundle", e)
	}
}
func TestChallengeOwnsOnlyCreatedFile(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	clean, e := writeChallenge(root, "token_123", "public")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = writeChallenge(root, "token_123", "different"); e == nil {
		t.Fatal("claimed existing file")
	}
	p := filepath.Join(root, ".well-known", "acme-challenge", "token_123")
	if e = os.Rename(p, p+".old"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, []byte("replacement"), 0644); e != nil {
		t.Fatal(e)
	}
	if e = clean(); e == nil {
		t.Fatal("silent replacement")
	}
	if b, e := os.ReadFile(p); e != nil || string(b) != "replacement" {
		t.Fatal("lost foreign file", e)
	}
	ok, e := writeChallenge(root, "new-token", "ok")
	if e != nil {
		t.Fatal(e)
	}
	if e = ok(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Lstat(filepath.Join(filepath.Dir(p), "new-token")); !os.IsNotExist(e) {
		t.Fatal("owned challenge remained")
	}
	other := t.TempDir()
	if e = os.Symlink(root, filepath.Join(other, ".well-known")); e != nil {
		t.Skip("symlink unavailable")
	}
	if _, e = writeChallenge(other, "other", "ok"); e == nil {
		t.Fatal("followed challenge symlink")
	}
}
func TestProviderConfinesCredentials(t *testing.T) {
	for _, u := range []string{"http://dns.example/api", "http://localhost/api", "https://user@dns.example/api"} {
		if ValidCloudflareAPI(u) {
			t.Fatal("accepted unsafe endpoint")
		}
	}
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("redirect followed") }))
	defer target.Close()
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer first.Close()
	c := Cloudflare{APIURL: first.URL, HTTP: first.Client(), Token: "unit-test", ZoneID: "z"}
	if _, e := c.Present(context.Background(), "x.example", "test"); e == nil {
		t.Fatal("accepted redirect")
	}
}
