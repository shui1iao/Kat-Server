package kernel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTrojanFallbackSelfLoopRejectedStaticWildcardAndDynamicPort(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertFiles(t, dir, 100)

	// 1. Static exact self-loop (127.0.0.1:18443 -> 127.0.0.1:18443) must be rejected by Validate().
	exactCfg := Config{
		Inbounds: []Inbound{{
			Protocol: "trojan",
			Listen:   "127.0.0.1:18443",
			Users:    []User{{Password: "pw1"}},
			Fallback: "127.0.0.1:18443",
			TLS:      &TLSConfig{Cert: certPath, Key: keyPath},
		}},
	}
	if err := exactCfg.Validate(); err == nil {
		t.Fatal("expected exact self-loop Fallback to fail Validate()")
	}

	// 2. Wildcard Listen (0.0.0.0:18443 / [::]:18443) with loopback Fallback on same port must fail Validate().
	for _, wildListen := range []string{"0.0.0.0:18443", "[::]:18443"} {
		for _, fb := range []string{"127.0.0.1:18443", "[::1]:18443"} {
			wCfg := Config{
				Inbounds: []Inbound{{
					Protocol: "trojan",
					Listen:   wildListen,
					Users:    []User{{Password: "pw1"}},
					Fallback: fb,
					TLS:      &TLSConfig{Cert: certPath, Key: keyPath},
				}},
			}
			if err := wCfg.Validate(); err == nil {
				t.Fatalf("expected wildcard Listen %s + Fallback %s to fail Validate()", wildListen, fb)
			}
		}
	}

	// 3. Cross-inbound port collision (Trojan Fallback pointing to sibling SOCKS5 inbound port) must fail Validate().
	crossCfg := Config{
		Inbounds: []Inbound{
			{
				Protocol: "trojan",
				Listen:   "127.0.0.1:18443",
				Users:    []User{{Password: "pw1"}},
				Fallback: "127.0.0.1:11080",
				TLS:      &TLSConfig{Cert: certPath, Key: keyPath},
			},
			{
				Protocol: "socks5",
				Listen:   "0.0.0.0:11080",
				Users:    []User{{Username: "u", Password: "p"}},
			},
		},
	}
	if err := crossCfg.Validate(); err == nil {
		t.Fatal("expected cross-inbound Fallback self-loop to fail Validate()")
	}

	// 4. Dynamic :0 port scenario: start server on 127.0.0.1:0, obtain bound port,
	// then Reload with Listen still "127.0.0.1:0" (reusing bound socket) and Fallback
	// pointing to that bound port -> prepare() MUST reject it and keep old generation intact!
	cfgPath := filepath.Join(dir, "config.json")
	writeDynamicCfg := func(fb string) {
		inb := map[string]any{
			"protocol": "trojan",
			"listen":   "127.0.0.1:0",
			"users":    []map[string]string{{"password": "pw-dynamic"}},
			"tls":      map[string]any{"cert": certPath, "key": keyPath},
		}
		if fb != "" {
			inb["fallback"] = fb
		}
		raw, _ := json.Marshal(map[string]any{"inbounds": []any{inb}})
		if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeDynamicCfg("")
	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Start(initialCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close(context.Background())
	srv.SetConfigLoader(func() (Config, error) { return Load(cfgPath) })

	boundAddr := srv.Addresses()[0].String()
	writeDynamicCfg(boundAddr) // Fallback targets the dynamically bound :0 listener!
	if res, err := srv.Reload("test"); err == nil || res.OK {
		t.Fatalf("expected Reload with Fallback=%s hitting dynamic :0 listener to be rejected!", boundAddr)
	}
	if got := srv.CurrentConfig().Inbounds[0].Fallback; got != "" {
		t.Fatalf("running config was corrupted after rejected reload: fallback=%q", got)
	}
}

func TestTrojanFallbackZeroWindowTimeoutQuotaAndPrecomputedDigests(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertFiles(t, dir, 200)

	// 1. Stalled / zero-window backend that accepts TCP with tiny SO_RCVBUF and never reads:
	// sending a fallback head larger than backend+proxy socket buffers blocks writeAll(out, head),
	// which MUST abort within HandshakeTimeout and release connSlots!
	stalledLn, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer stalledLn.Close()
	var stalledConns []net.Conn
	var stalledMu sync.Mutex
	defer func() {
		stalledMu.Lock()
		for _, c := range stalledConns {
			_ = c.Close()
		}
		stalledMu.Unlock()
	}()
	go func() {
		for {
			sc, err := stalledLn.AcceptTCP()
			if err != nil {
				return
			}
			_ = sc.SetReadBuffer(1024)
			stalledMu.Lock()
			stalledConns = append(stalledConns, sc)
			stalledMu.Unlock()
			// Never read from sc!
		}
	}()

	// Directly verify writeAll(out, largeHead) inside trojanFallback times out on stalled backend!
	srv, err := Start(Config{
		Inbounds: []Inbound{{
			Protocol: "trojan",
			Listen:   "127.0.0.1:0",
			Users:    []User{{Password: "alpha-secret"}, {Password: "beta-secret"}, {Password: "gamma-secret"}},
			Fallback: stalledLn.Addr().String(),
			TLS:      &TLSConfig{Cert: certPath, Key: keyPath},
		}},
		Security: &SecurityOptions{AllowLoopback: true},
		Limits: Limits{
			Connections:      256, // fallbackSlots = max(64, 256/4) = 64
			HandshakeTimeout: Duration(180 * time.Millisecond),
			DialTimeout:      Duration(500 * time.Millisecond),
			TCPIdle:          Duration(10 * time.Second), // deliberately long so only HandshakeTimeout can free stalled head write!
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close(context.Background())

	// Verify precomputed digests match trojanPasswordDigest for every user.
	curIn := srv.CurrentConfig().Inbounds[0]
	if len(curIn.trojanDigests) != 3 {
		t.Fatalf("expected 3 precomputed Trojan digests, got %d", len(curIn.trojanDigests))
	}
	for i, u := range curIn.Users {
		if curIn.trojanDigests[i] != trojanPasswordDigest(u.Password) {
			t.Fatalf("user %d precomputed digest mismatch", i)
		}
	}

	// Test trojanFallback head write deadline directly with a 4 MiB head that exceeds kernel socket buffers:
	// without SetWriteDeadline(HandshakeTimeout) before writeAll(out, head), this blocks forever!
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	hugeHead := bytes.Repeat([]byte("G"), 4<<20)
	doneHead := make(chan struct{})
	startWrite := time.Now()
	go func() {
		defer close(doneHead)
		srv.trojanFallback(c2, hugeHead, &curIn)
	}()
	select {
	case <-doneHead:
		if elapsed := time.Since(startWrite); elapsed > 2*time.Second {
			t.Fatalf("trojanFallback zero-window head write took too long: %v", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("trojanFallback hung on zero-window backend head write (missing SetWriteDeadline!)")
	}

	// 2. Verify concurrent fallbackSlots quota (64 for Connections=256) prevents fallback flood
	// from starving authenticated Trojan proxy connections!
	holdBackend, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer holdBackend.Close()
	releaseHold := make(chan struct{})
	go func() {
		for {
			sc, err := holdBackend.AcceptTCP()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				<-releaseHold
			}(sc)
		}
	}()

	echoTarget := echoTCP(t)
	srvQuota, err := Start(Config{
		Inbounds: []Inbound{{
			Protocol: "trojan",
			Listen:   "127.0.0.1:0",
			Users:    []User{{Password: "u0"}, {Password: "u1"}, {Password: "valid-trojan-pw"}},
			Fallback: holdBackend.Addr().String(),
			TLS:      &TLSConfig{Cert: certPath, Key: keyPath},
		}},
		Security: &SecurityOptions{AllowLoopback: true},
		Limits: Limits{
			Connections:      256, // fallbackSlots = 64
			Handshakes:       128,
			HandshakeTimeout: Duration(time.Second),
			DialTimeout:      Duration(time.Second),
			TCPIdle:          Duration(5 * time.Second),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srvQuota.Close(context.Background())
	qAddr := srvQuota.Addresses()[0].String()

	// Open 80 1-byte non-hex fallback connections (> 64 fallbackSlots, < 256 Connections).
	fallbackClients := make([]*tls.Conn, 0, 80)
	for i := 0; i < 80; i++ {
		tc, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", qAddr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("dial fallback #%d: %v", i, err)
		}
		_, _ = tc.Write([]byte("G"))
		fallbackClients = append(fallbackClients, tc)
	}
	defer func() {
		close(releaseHold)
		for _, tc := range fallbackClients {
			_ = tc.Close()
		}
	}()

	// Wait until excess (>64) fallback connections are rejected and Active settles <= 64.
	waitFor(t, func() bool {
		act := srvQuota.Stats().Active
		return act > 0 && act <= 64
	})

	// Meanwhile, an authenticated Trojan connection using the 3rd user ("valid-trojan-pw") MUST succeed!
	authConn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", qAddr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial authenticated Trojan during fallback flood: %v", err)
	}
	defer authConn.Close()
	_ = authConn.SetDeadline(time.Now().Add(2 * time.Second))
	digest := trojanPasswordDigest("valid-trojan-pw")
	var req bytes.Buffer
	req.Write(digest[:])
	req.WriteString("\r\n")
	req.WriteByte(1)
	req.Write(appendAddress(nil, echoTarget, false))
	req.WriteString("\r\n")
	req.WriteString("ping-trojan")
	if _, err := authConn.Write(req.Bytes()); err != nil {
		t.Fatalf("authenticated Trojan write failed: %v", err)
	}
	var pong [11]byte
	if _, err := io.ReadFull(authConn, pong[:]); err != nil || string(pong[:]) != "ping-trojan" {
		t.Fatalf("authenticated Trojan echo failed: got %q err=%v", string(pong[:]), err)
	}
	_ = authConn.Close()
	if strings.TrimSpace(string(pong[:])) != "ping-trojan" {
		t.Fatal("unexpected echo")
	}
}
