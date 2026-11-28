package kernel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	A "github.com/shui1iao/Kat/internal/anytls"
)

func writeTestCertFiles(t testing.TB, dir string, serial int64) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cp := filepath.Join(dir, "cert.pem")
	kp := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cp, kp
}

func TestAnyTLSSlowlorisAndCertHotReloadRace(t *testing.T) {
	dir := t.TempDir()
	cp, kp := writeTestCertFiles(t, dir, 1)
	cfgPath := filepath.Join(dir, "config.json")

	writeCfg := func(listen string) {
		cfg := map[string]any{
			"inbounds": []map[string]any{{
				"protocol": "anytls",
				"listen":   listen,
				"anytls":   map[string]any{"password": "anytls-pw-race", "max_sessions": 32},
				"tls":      map[string]any{"cert": cp, "key": kp, "watch": true, "watch_interval": "5s"},
			}},
			"limits": map[string]any{
				"handshakes":        16,
				"handshake_timeout": "200ms",
			},
		}
		raw, _ := json.Marshal(cfg)
		if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeCfg("127.0.0.1:0")

	loaded, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Start(loaded)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close(context.Background())
	listenAddr := srv.Addresses()[0].String()
	srv.SetConfigLoader(func() (Config, error) {
		return Load(cfgPath)
	})

	var stop atomic.Bool
	var wg sync.WaitGroup
	for w := 0; w < 10; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; !stop.Load() && i < 12; i++ {
				tc, err := tls.DialWithDialer(&net.Dialer{Timeout: 300 * time.Millisecond}, "tcp", listenAddr, &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "localhost",
				})
				if err != nil {
					continue
				}
				if id%2 == 0 {
					_, _ = tc.Write([]byte{0x00})
					var b [4]byte
					_ = tc.SetReadDeadline(time.Now().Add(350 * time.Millisecond))
					_, _ = tc.Read(b[:])
				}
				_ = tc.Close()
			}
		}(w)
	}

	for r := 2; r <= 6; r++ {
		_, _ = writeTestCertFiles(t, dir, int64(r))
		if _, err := srv.Reload("test"); err != nil {
			t.Fatalf("Reload #%d failed under concurrent TLS load: %v", r, err)
		}
	}
	stop.Store(true)
	wg.Wait()

	waitFor(t, func() bool {
		s := srv.Stats()
		return s.Active == 0 && s.Handshakes == 0
	})
}

func TestSS2022SlowlorisAndInvalidAEADStorm(t *testing.T) {
	var rawKey [16]byte
	_, _ = rand.Read(rawKey[:])
	psk := base64.StdEncoding.EncodeToString(rawKey[:])

	srv, err := Start(Config{
		Inbounds: []Inbound{{
			Protocol: "shadowsocks",
			Listen:   "127.0.0.1:0",
			SS:       &SSOptions{Method: "2022-blake3-aes-128-gcm", Key: psk},
		}},
		Limits: Limits{
			Connections:      64,
			Handshakes:       12,
			HandshakeTimeout: Duration(180 * time.Millisecond),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close(context.Background())
	addr := srv.Addresses()[0].String()

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(mode int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
			if err != nil {
				return
			}
			defer c.Close()
			switch mode % 3 {
			case 0:
				_, _ = c.Write([]byte{1, 2, 3, 4, 5})
				var b [8]byte
				_ = c.SetReadDeadline(time.Now().Add(350 * time.Millisecond))
				_, _ = c.Read(b[:])
			case 1:
				junk := make([]byte, 128)
				_, _ = rand.Read(junk)
				_, _ = c.Write(junk)
				var b [8]byte
				_ = c.SetReadDeadline(time.Now().Add(350 * time.Millisecond))
				_, _ = c.Read(b[:])
			case 2:
			}
		}(i)
	}
	wg.Wait()

	waitFor(t, func() bool {
		s := srv.Stats()
		return s.Active == 0 && s.Handshakes == 0
	})
}

// TestAnyTLSRelayLogsActualInboundIndex verifies S-6: relayAnyTLS forwards the
// inbound's logIndex instead of hardcoding -1 on non-quiet TCP I/O errors.
func TestAnyTLSRelayLogsActualInboundIndex(t *testing.T) {
	var captured atomic.Value
	fl := &failureLog{
		allow: func() bool { return true },
		write: func(b []byte) error {
			captured.Store(string(b))
			return nil
		},
	}
	srv := &Server{
		core: &core{failures: fl},
		pool: newBufferPool(16384, 2),
	}
	srv.cfg.Limits.TCPIdle = Duration(time.Second)

	codec, err := A.NewServer(A.Config{Password: "pw-s6", WriteTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// errConn returns a non-quiet error on Read so relayAnyTLS emits failTCPIO.
	badTarget := &loudErrConn{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run relayAnyTLS directly with logIndex = 2 over an in-memory stream mock.
	_ = codec
	srv.relayAnyTLS(ctx, 2, c1, badTarget)
	fl.shutdown()

	got, _ := captured.Load().(string)
	if !strings.Contains(got, "inbound=2") {
		t.Fatalf("expected failure log to record inbound=2, got: %q", got)
	}
}

type loudErrConn struct{}

func (*loudErrConn) Read([]byte) (int, error)         { return 0, os.ErrInvalid }
func (*loudErrConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*loudErrConn) Close() error                     { return nil }
func (*loudErrConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (*loudErrConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2} }
func (*loudErrConn) SetDeadline(time.Time) error      { return nil }
func (*loudErrConn) SetReadDeadline(time.Time) error  { return nil }
func (*loudErrConn) SetWriteDeadline(time.Time) error { return nil }

// ---- Hot-path Benchmarks ----

type benchMemConn struct {
	r bytes.Reader
}

func (c *benchMemConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *benchMemConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *benchMemConn) Close() error                { return nil }
func (c *benchMemConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}
func (c *benchMemConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}
}
func (c *benchMemConn) SetDeadline(time.Time) error      { return nil }
func (c *benchMemConn) SetReadDeadline(time.Time) error  { return nil }
func (c *benchMemConn) SetWriteDeadline(time.Time) error { return nil }

func BenchmarkPerfCompareParseTrojanHit16Users(b *testing.B) {
	dir := b.TempDir()
	cp, kp := writeTestCertFiles(b, dir, 1)
	users := make([]User, 16)
	for i := range users {
		users[i] = User{Password: "trojan-bench-secret-password-" + string(rune('a'+i))}
	}
	cfg := Config{
		Inbounds: []Inbound{{
			Protocol: "trojan",
			Listen:   "127.0.0.1:0",
			Users:    users,
			TLS:      &TLSConfig{Cert: cp, Key: kp},
		}},
	}
	if err := cfg.Validate(); err != nil {
		b.Fatal(err)
	}
	in := cfg.Inbounds[0]
	hexHash := trojanPasswordDigest(users[15].Password)
	var wire bytes.Buffer
	wire.Write(hexHash[:])
	wire.WriteString("\r\n")
	wire.WriteByte(1)
	wire.Write([]byte{3, 15})
	wire.WriteString("api.example.com")
	_ = binary.Write(&wire, binary.BigEndian, uint16(443))
	wire.WriteString("\r\n")
	raw := wire.Bytes()

	conn := &benchMemConn{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.r.Reset(raw)
		req, err := parseTrojan(conn, in)
		if err != nil || req.UserIndex != 15 || req.Target.Port != 443 {
			b.Fatalf("unexpected: err=%v idx=%d port=%d", err, req.UserIndex, req.Target.Port)
		}
	}
}

func BenchmarkPerfCompareTrojanDatagramReadIPv4(b *testing.B) {
	var wire bytes.Buffer
	wire.Write([]byte{1, 127, 0, 0, 1})
	_ = binary.Write(&wire, binary.BigEndian, uint16(53))
	_ = binary.Write(&wire, binary.BigEndian, uint16(64))
	wire.WriteString("\r\n")
	wire.Write(make([]byte, 64))
	raw := wire.Bytes()
	conn := &benchMemConn{}
	td := &trojanDatagrams{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.r.Reset(raw)
		pkt, err := td.ReadPacket(conn, Address{})
		if err != nil {
			b.Fatal(err)
		}
		releasePacket(pkt)
	}
}

func BenchmarkPerfCompareTrojanDatagramReadDomain(b *testing.B) {
	var wire bytes.Buffer
	wire.Write([]byte{3, 10})
	wire.WriteString("dns.google")
	_ = binary.Write(&wire, binary.BigEndian, uint16(443))
	_ = binary.Write(&wire, binary.BigEndian, uint16(64))
	wire.WriteString("\r\n")
	wire.Write(make([]byte, 64))
	raw := wire.Bytes()
	conn := &benchMemConn{}
	td := &trojanDatagrams{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.r.Reset(raw)
		pkt, err := td.ReadPacket(conn, Address{})
		if err != nil {
			b.Fatal(err)
		}
		releasePacket(pkt)
	}
}

func BenchmarkPerfCompareKernelReadAddressDomain(b *testing.B) {
	raw := []byte{3, 15, 'a', 'p', 'i', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb}
	var br bytes.Reader
	bfr := bufio.NewReaderSize(&br, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		br.Reset(raw)
		bfr.Reset(&br)
		if _, err := readAddress(bfr, false); err != nil {
			b.Fatal(err)
		}
	}
}
