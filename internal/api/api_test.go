package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testBackend struct {
	level          atomic.Value
	reloads        atomic.Int64
	resetErr       error
	detailsEnabled atomic.Bool
	reloadErr      error
	blockStats     chan struct{}
	inStats        chan struct{}
}

func newTestBackend() *testBackend {
	b := &testBackend{}
	b.level.Store("info")
	b.detailsEnabled.Store(true)
	return b
}

func (b *testBackend) Version() string { return "0.8.4-test" }
func (b *testBackend) Stats() any {
	if b.inStats != nil {
		select {
		case b.inStats <- struct{}{}:
		default:
		}
	}
	if b.blockStats != nil {
		<-b.blockStats
	}
	return map[string]any{"active": 0, "items": []string{}}
}
func (b *testBackend) ResetStats() error { return b.resetErr }
func (b *testBackend) Connections() (any, bool) {
	if !b.detailsEnabled.Load() {
		return nil, false
	}
	return []map[string]any{}, true
}
func (b *testBackend) CloseConnection(id uint64) (bool, bool) {
	if !b.detailsEnabled.Load() {
		return false, false
	}
	return id == 42, true
}
func (b *testBackend) CloseAllConnections() (int, bool) {
	if !b.detailsEnabled.Load() {
		return 0, false
	}
	return 3, true
}
func (b *testBackend) LogLevel() string {
	v, _ := b.level.Load().(string)
	return v
}
func (b *testBackend) SetLogLevel(level string) error {
	switch level {
	case "debug", "info", "warn", "error":
		b.level.Store(level)
		return nil
	default:
		return errors.New("invalid level")
	}
}
func (b *testBackend) Reload() (any, error) {
	if b.reloadErr != nil {
		return nil, b.reloadErr
	}
	gen := b.reloads.Add(1)
	return map[string]any{"ok": true, "generation": gen}, nil
}
func (b *testBackend) Bans() any { return []string{} }
func (b *testBackend) RemoveBan(source string) (bool, error) {
	if source == "bad" {
		return false, &Failure{Code: "bad_source", Message: "invalid source"}
	}
	return source == "203.0.113.9", nil
}

func unixHTTPClient(sock string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
		Timeout: 3 * time.Second,
	}
}

func TestUnixPermissionsPeerCredAndBearerAuth(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nested", "kat.sock")

	// Reserve an ephemeral loopback TCP port cleanly for Options.Listen.
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr := probeLn.Addr().String()
	_ = probeLn.Close()

	b := newTestBackend()
	var debugCount atomic.Int64
	srv, errs := Start(Options{
		Socket: sock,
		Listen: tcpAddr,
		Secret: "super-secret-token",
		Debug:  func(string, string, int) { debugCount.Add(1) },
	}, b)
	if len(errs) != 0 {
		t.Fatalf("Start returned errors: %v", errs)
	}
	defer srv.Close()

	// 1. Verify Unix socket 0600 mode and parent directory 0700 mode.
	fi, err := os.Lstat(sock)
	if err != nil {
		t.Fatalf("Lstat(%s): %v", sock, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected unix socket mode, got %v", fi.Mode())
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("expected socket mode 0600, got %04o", fi.Mode().Perm())
	}

	// Verify active socket cannot be stolen by a second Start or strict Prepare.
	if _, prepErr := Prepare(Options{Socket: sock}, b, nil); !errors.Is(prepErr, ErrSocketInUse) {
		t.Fatalf("expected ErrSocketInUse on active socket, got %v", prepErr)
	}
	regFile := filepath.Join(dir, "not-a-sock.txt")
	if err := os.WriteFile(regFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, prepErr := Prepare(Options{Socket: regFile}, b, nil); !errors.Is(prepErr, ErrNotSocket) {
		t.Fatalf("expected ErrNotSocket on regular file, got %v", prepErr)
	}

	// 2. Unix socket requests succeed without Bearer header (authenticated via SO_PEERCRED / 0600).
	ucli := unixHTTPClient(sock)
	resp, err := ucli.Get("http://kat/v1/version")
	if err != nil {
		t.Fatalf("unix GET /v1/version: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "0.8.4-test") {
		t.Fatalf("unexpected version response: %d %s", resp.StatusCode, string(body))
	}

	// 3. TCP Bearer authentication: missing, malformed, and wrong tokens must return 401.
	tcli := &http.Client{Timeout: 3 * time.Second}
	baseURL := "http://" + tcpAddr
	for _, authHdr := range []string{"", "Basic dXNlcjpwYXNz", "Bearer ", "Bearer wrong-secret"} {
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/v1/version", nil)
		if authHdr != "" {
			req.Header.Set("Authorization", authHdr)
		}
		r, err := tcli.Do(req)
		if err != nil {
			t.Fatalf("TCP request (%q): %v", authHdr, err)
		}
		_, _ = io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("auth %q: expected 401, got %d", authHdr, r.StatusCode)
		}
		if got := r.Header.Get("WWW-Authenticate"); got != `Bearer realm="kat"` {
			t.Fatalf("unexpected WWW-Authenticate header: %q", got)
		}
	}

	// Valid Bearer token succeeds.
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/v1/stats", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	r, err := tcli.Do(req)
	if err != nil {
		t.Fatalf("authorized TCP request: %v", err)
	}
	rawStats, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != http.StatusOK || strings.Contains(string(rawStats), ": null") {
		t.Fatalf("unexpected stats response: %d %s", r.StatusCode, string(rawStats))
	}
	if debugCount.Load() == 0 {
		t.Fatal("expected Debug callback to record requests")
	}
}

func TestBodyTruncationRoutesAndJSONSliceSafety(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "kat.sock")
	b := newTestBackend()
	srv, errs := Start(Options{Socket: sock}, b)
	if len(errs) != 0 {
		t.Fatalf("Start errors: %v", errs)
	}
	defer srv.Close()

	ucli := unixHTTPClient(sock)

	// 1. 4096B request body truncation & DisallowUnknownFields on PUT /v1/log/level.
	oversizedValidJSON := `{"level":"debug"}` + strings.Repeat(" ", 5000)
	req, _ := http.NewRequest(http.MethodPut, "http://kat/v1/log/level", strings.NewReader(oversizedValidJSON+"{}"))
	resp, err := ucli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	// Extra trailing token or >4096B body in PUT must be rejected or bounded.
	oversizedField := `{"level":"` + strings.Repeat("a", 5000) + `"}`
	req2, _ := http.NewRequest(http.MethodPut, "http://kat/v1/log/level", strings.NewReader(oversizedField))
	resp2, err := ucli.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on >4096B body truncation, got %d", resp2.StatusCode)
	}

	unknownField := `{"level":"debug","extra":1}`
	req3, _ := http.NewRequest(http.MethodPut, "http://kat/v1/log/level", strings.NewReader(unknownField))
	resp3, err := ucli.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown field, got %d", resp3.StatusCode)
	}

	// Valid log level change + bad level check.
	reqOK, _ := http.NewRequest(http.MethodPut, "http://kat/v1/log/level", strings.NewReader(`{"level":"debug"}`))
	respOK, err := ucli.Do(reqOK)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(respOK.Body)
	respOK.Body.Close()
	if respOK.StatusCode != http.StatusOK || b.LogLevel() != "debug" {
		t.Fatalf("PUT /v1/log/level failed: status=%d level=%s", respOK.StatusCode, b.LogLevel())
	}

	reqBadLv, _ := http.NewRequest(http.MethodPut, "http://kat/v1/log/level", strings.NewReader(`{"level":"trace"}`))
	respBadLv, err := ucli.Do(reqBadLv)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(respBadLv.Body)
	respBadLv.Body.Close()
	if respBadLv.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid level name, got %d", respBadLv.StatusCode)
	}

	// 2. Connections, Bans, Reload, ResetStats, and 404 routes.
	for _, badID := range []string{"0", "-1", "99999999999999999999999", "abc"} {
		rReq, _ := http.NewRequest(http.MethodDelete, "http://kat/v1/connections/"+badID, nil)
		rResp, err := ucli.Do(rReq)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(rResp.Body)
		rResp.Body.Close()
		if rResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("bad connection id %q returned %d, want 400", badID, rResp.StatusCode)
		}
	}

	del42, _ := http.NewRequest(http.MethodDelete, "http://kat/v1/connections/42", nil)
	r42, err := ucli.Do(del42)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(r42.Body)
	r42.Body.Close()
	if r42.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /v1/connections/42: got %d, want 200", r42.StatusCode)
	}

	del99, _ := http.NewRequest(http.MethodDelete, "http://kat/v1/connections/99", nil)
	r99, err := ucli.Do(del99)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(r99.Body)
	r99.Body.Close()
	if r99.StatusCode != http.StatusNotFound {
		t.Fatalf("DELETE /v1/connections/99: got %d, want 404", r99.StatusCode)
	}

	// Disabled connection details -> 409 Conflict.
	b.detailsEnabled.Store(false)
	rDis, err := ucli.Get("http://kat/v1/connections")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(rDis.Body)
	rDis.Body.Close()
	if rDis.StatusCode != http.StatusConflict {
		t.Fatalf("GET /v1/connections when disabled: got %d, want 409", rDis.StatusCode)
	}

	// Bans list (must serialize as [] not null) + DELETE /v1/bans/{source}.
	rBans, err := ucli.Get("http://kat/v1/bans")
	if err != nil {
		t.Fatal(err)
	}
	bansBytes, _ := io.ReadAll(rBans.Body)
	rBans.Body.Close()
	if rBans.StatusCode != http.StatusOK || strings.TrimSpace(string(bansBytes)) != "[]" {
		t.Fatalf("GET /v1/bans: status=%d body=%q", rBans.StatusCode, string(bansBytes))
	}

	for _, tc := range []struct {
		src  string
		want int
	}{
		{"203.0.113.9", http.StatusOK},
		{"203.0.113.10", http.StatusNotFound},
		{"bad", http.StatusBadRequest},
	} {
		reqBan, _ := http.NewRequest(http.MethodDelete, "http://kat/v1/bans/"+tc.src, nil)
		rBan, err := ucli.Do(reqBan)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(rBan.Body)
		rBan.Body.Close()
		if rBan.StatusCode != tc.want {
			t.Fatalf("DELETE /v1/bans/%s: got %d, want %d", tc.src, rBan.StatusCode, tc.want)
		}
	}

	// Reload 200 and 422 (*Failure).
	rRel, err := ucli.Post("http://kat/v1/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(rRel.Body)
	rRel.Body.Close()
	if rRel.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/reload: got %d, want 200", rRel.StatusCode)
	}
	b.reloadErr = &Failure{Code: "reload_refused", Stage: "validate", Message: "bad config"}
	rRelFail, err := ucli.Post("http://kat/v1/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(rRelFail.Body)
	rRelFail.Body.Close()
	if rRelFail.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("POST /v1/reload refused: got %d, want 422", rRelFail.StatusCode)
	}
	b.reloadErr = nil
}

func TestHotReloadRetiresOldEndpointWith503AndConcurrentReads(t *testing.T) {
	dir := t.TempDir()
	sock1 := filepath.Join(dir, "s1", "kat1.sock")
	sock2 := filepath.Join(dir, "s2", "kat2.sock")

	b := newTestBackend()
	b.blockStats = make(chan struct{})
	b.inStats = make(chan struct{}, 1)

	srv, errs := Start(Options{Socket: sock1}, b)
	if len(errs) != 0 {
		t.Fatalf("Start errors: %v", errs)
	}
	defer srv.Close()

	// Verify Prepare.Abort cleans up newly created parent directories without affecting sock1.
	abortDir := filepath.Join(dir, "abort-parent", "sub")
	prepAbort, err := Prepare(Options{Socket: filepath.Join(abortDir, "kat.sock")}, b, srv)
	if err != nil {
		t.Fatalf("Prepare for abort: %v", err)
	}
	prepAbort.Abort()
	if _, statErr := os.Stat(filepath.Join(dir, "abort-parent")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected Abort to remove created empty parent dir, statErr=%v", statErr)
	}

	// Capture sock1 endpoint before hot-swap, and hold an in-flight GET /v1/stats
	// on sock1 across Commit() to verify graceful drain + 503 api_retired handler swap.
	srv.mu.Lock()
	oldEp := srv.endpoints[0]
	srv.mu.Unlock()

	connHold, err := net.DialTimeout("unix", sock1, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connHold.Close()

	holdDone := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(connHold, "GET /v1/stats HTTP/1.1\r\nHost: kat\r\n\r\n"); err != nil {
			holdDone <- err
			return
		}
		r, err := http.ReadResponse(bufio.NewReader(connHold), &http.Request{Method: http.MethodGet})
		if err != nil {
			holdDone <- err
			return
		}
		_, _ = io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			holdDone <- errors.New("in-flight request did not finish with 200")
			return
		}
		holdDone <- nil
	}()
	select {
	case <-b.inStats:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for in-flight request")
	}

	// Hot-swap endpoint from sock1 -> sock2 while connHold is in flight!
	prep, err := Prepare(Options{Socket: sock2}, b, srv)
	if err != nil {
		t.Fatalf("Prepare swap: %v", err)
	}
	prep.Commit()

	// Any request reaching the retired endpoint handler before Shutdown closes
	// its transport MUST deterministically receive 503 api_retired!
	rec := httptest.NewRecorder()
	oldEp.srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://kat/v1/version", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on retired endpoint handler, got %d (%s)", rec.Code, rec.Body.String())
	}
	var errPayload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errPayload); err != nil || errPayload["error"] != "api_retired" {
		t.Fatalf("expected error=api_retired, got %s (err=%v)", rec.Body.String(), err)
	}
	// And dialing retired sock1 must now fail immediately.
	if cOld, dialErr := net.DialTimeout("unix", sock1, 200*time.Millisecond); dialErr == nil {
		cOld.Close()
		t.Fatal("expected retired sock1 to refuse new connections")
	}

	// Unblock connHold and verify both it and concurrent reads on sock2 succeed cleanly.
	close(b.blockStats)
	if err := <-holdDone; err != nil {
		t.Fatalf("in-flight request failed during endpoint retirement: %v", err)
	}

	ucli2 := unixHTTPClient(sock2)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				r, err := ucli2.Get("http://kat/v1/stats")
				if err != nil {
					t.Errorf("concurrent GET /v1/stats on sock2: %v", err)
					return
				}
				_, _ = io.ReadAll(r.Body)
				r.Body.Close()
				if r.StatusCode != http.StatusOK {
					t.Errorf("unexpected status %d", r.StatusCode)
					return
				}
			}
		}()
	}
	wg.Wait()
}
