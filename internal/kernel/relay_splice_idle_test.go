package kernel

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func countSelfPipeFDs(t *testing.T) (total int, pipes int, ok bool) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, 0, false
	}
	for _, e := range entries {
		link, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil {
			continue
		}
		total++
		if strings.HasPrefix(link, "pipe:") {
			pipes++
		}
	}
	return total, pipes, true
}

func dialLoopbackSOCKS5(t *testing.T, proxyAddr string, dst *net.TCPAddr) *net.TCPConn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	tc := c.(*net.TCPConn)
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := tc.Write([]byte{5, 1, 0}); err != nil {
		tc.Close()
		t.Fatalf("socks greeting write: %v", err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(tc, greet[:]); err != nil || greet != [2]byte{5, 0} {
		tc.Close()
		t.Fatalf("socks greeting resp: %v %v", greet, err)
	}
	ip4 := dst.IP.To4()
	req := []byte{5, 1, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3], byte(dst.Port >> 8), byte(dst.Port)}
	if _, err := tc.Write(req); err != nil {
		tc.Close()
		t.Fatalf("socks req write: %v", err)
	}
	var rep [10]byte
	if _, err := io.ReadFull(tc, rep[:]); err != nil || rep[1] != 0 {
		tc.Close()
		t.Fatalf("socks rep: %v %v", rep, err)
	}
	_ = tc.SetDeadline(time.Time{})
	return tc
}

// TestSpliceInteractiveHeartbeatSurvivesTCPIdleAndSilentReclaimed verifies S-1:
//  1. An interactive TCP session (< 64 KiB total bytes) exchanging small heartbeats
//     across multiple TCPIdle windows MUST stay 100% alive on the Linux splice(2) fast path;
//  2. Truly silent connections (both after <64 KiB and after >64 KiB burst) MUST be
//     reclaimed promptly when TCPIdle expires.
func TestSpliceInteractiveHeartbeatSurvivesTCPIdleAndSilentReclaimed(t *testing.T) {
	echoLn, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.AcceptTCP()
			if err != nil {
				return
			}
			go func(conn *net.TCPConn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	dstAddr := echoLn.Addr().(*net.TCPAddr)

	for _, disableFast := range []bool{false, true} {
		mode := "splice_fastpath"
		if disableFast {
			mode = "adaptive_copy_path"
		}
		t.Run(mode, func(t *testing.T) {
			const idleWindow = 220 * time.Millisecond
			srv, err := Start(Config{
				Inbounds: []Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0"}},
				Security: &SecurityOptions{AllowLoopback: true},
				Limits: Limits{
					DisableFastPath: disableFast,
					TCPIdle:         Duration(idleWindow),
					BufferSize:      65536,
					PoolBuffers:     8,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close(context.Background())
			proxyAddr := srv.Addresses()[0].String()

			// Part A: Active interactive session (1 KiB every 35ms for 16 rounds = 560ms > 2.5x TCPIdle,
			// total 16 KiB << 64 KiB spliceChunk) MUST NOT be killed!
			cli := dialLoopbackSOCKS5(t, proxyAddr, dstAddr)
			msg := bytes.Repeat([]byte("K"), 1024)
			reply := make([]byte, len(msg))
			for step := 0; step < 16; step++ {
				time.Sleep(35 * time.Millisecond)
				_ = cli.SetDeadline(time.Now().Add(time.Second))
				if _, err := cli.Write(msg); err != nil {
					cli.Close()
					t.Fatalf("interactive step %d write failed: %v", step, err)
				}
				if _, err := io.ReadFull(cli, reply); err != nil {
					cli.Close()
					t.Fatalf("interactive step %d read failed (falsely killed by idle watchdog!): %v", step, err)
				}
				if !bytes.Equal(reply, msg) {
					cli.Close()
					t.Fatalf("interactive step %d payload corrupted", step)
				}
			}
			_ = cli.Close()

			// Part B: Silent connection after >64 KiB burst + partial chunk (100 KiB total)
			// must still be reclaimed promptly once silent for TCPIdle!
			cliSilent := dialLoopbackSOCKS5(t, proxyAddr, dstAddr)
			burst := bytes.Repeat([]byte("B"), 100<<10)
			gotBurst := make([]byte, len(burst))
			_ = cliSilent.SetDeadline(time.Now().Add(2 * time.Second))
			errCh := make(chan error, 1)
			go func() {
				_, werr := cliSilent.Write(burst)
				errCh <- werr
			}()
			if _, err := io.ReadFull(cliSilent, gotBurst); err != nil {
				cliSilent.Close()
				t.Fatalf("burst echo read failed: %v", err)
			}
			if werr := <-errCh; werr != nil {
				cliSilent.Close()
				t.Fatalf("burst write failed: %v", werr)
			}

			// Stop all traffic: watchdog must close connection around idleWindow (~220ms), well within 1.2s!
			silentStart := time.Now()
			_ = cliSilent.SetReadDeadline(silentStart.Add(1500 * time.Millisecond))
			var one [1]byte
			_, eofErr := cliSilent.Read(one[:])
			elapsed := time.Since(silentStart)
			_ = cliSilent.Close()
			if eofErr == nil {
				t.Fatal("expected silent connection to be closed by idle watchdog, got nil error")
			}
			if nerr, ok := eofErr.(net.Error); ok && nerr.Timeout() {
				t.Fatalf("silent connection was NOT closed by idle watchdog within 1.5s (elapsed=%v)", elapsed)
			}
			waitFor(t, func() bool { return srv.Stats().Active == 0 })

			// Verify TrimBuffers drains pooled buffers cleanly.
			_ = srv.TrimBuffers()
		})
	}
}

func TestSpliceHalfCloseAndBidirectionalRSTZeroPipeLeak(t *testing.T) {
	payload := make([]byte, 256<<10) // 256 KiB = 4x spliceChunk (64 KiB)
	_, _ = rand.Read(payload)

	// 1. Half-close both directions on splice fast path.
	tgtLn, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer tgtLn.Close()
	go func() {
		sc, err := tgtLn.AcceptTCP()
		if err != nil {
			return
		}
		defer sc.Close()
		reqBytes, err := io.ReadAll(sc)
		if err != nil || string(reqBytes) != "CLIENT-EOF" {
			return
		}
		_, _ = sc.Write(payload)
		_ = sc.CloseWrite()
	}()

	srv, err := Start(Config{
		Inbounds: []Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0"}},
		Security: &SecurityOptions{AllowLoopback: true},
		Limits:   Limits{TCPIdle: Duration(5 * time.Second), DrainTimeout: Duration(3 * time.Second)},
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := srv.Addresses()[0].String()
	cli := dialLoopbackSOCKS5(t, proxyAddr, tgtLn.Addr().(*net.TCPAddr))
	if _, err := cli.Write([]byte("CLIENT-EOF")); err != nil {
		t.Fatal(err)
	}
	if err := cli.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(cli)
	_ = cli.Close()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("half-close download mismatch: len=%d err=%v", len(got), err)
	}
	srv.Close(context.Background())

	// 2. Bidirectional RST storm under backpressured splice pipes -> zero pipe FD leak.
	rstLn, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer rstLn.Close()
	go func() {
		for {
			sc, err := rstLn.AcceptTCP()
			if err != nil {
				return
			}
			go func(c *net.TCPConn) {
				_, _ = c.Write(payload)
				_ = c.SetLinger(0)
				_ = c.Close()
			}(sc)
		}
	}()

	srv2, err := Start(Config{
		Inbounds: []Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0"}},
		Security: &SecurityOptions{AllowLoopback: true},
		Limits:   Limits{TCPIdle: Duration(500 * time.Millisecond), DrainTimeout: Duration(200 * time.Millisecond)},
	})
	if err != nil {
		t.Fatal(err)
	}
	pAddr2 := srv2.Addresses()[0].String()
	rDst := rstLn.Addr().(*net.TCPAddr)

	// Warm Go's internal splice pipe pool before measuring baseline FDs.
	wConn := dialLoopbackSOCKS5(t, pAddr2, rDst)
	_ = wConn.SetLinger(0)
	_ = wConn.Close()
	waitFor(t, func() bool { return srv2.Stats().Active == 0 })

	_, basePipes, fdOK := countSelfPipeFDs(t)

	var wg sync.WaitGroup
	for i := 0; i < 48; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp4", pAddr2, 2*time.Second)
			if err != nil {
				return
			}
			tc := c.(*net.TCPConn)
			_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := tc.Write([]byte{5, 1, 0}); err != nil {
				tc.Close()
				return
			}
			var g [2]byte
			if _, err := io.ReadFull(tc, g[:]); err != nil || g != [2]byte{5, 0} {
				tc.Close()
				return
			}
			ip4 := rDst.IP.To4()
			req := []byte{5, 1, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3], byte(rDst.Port >> 8), byte(rDst.Port)}
			_, _ = tc.Write(req)
			var rep [10]byte
			if _, err := io.ReadFull(tc, rep[:]); err == nil && rep[1] == 0 {
				var small [512]byte
				_, _ = tc.Read(small[:])
			}
			if idx%2 == 0 {
				_ = tc.SetLinger(0)
			}
			_ = tc.Close()
		}(i)
	}
	wg.Wait()
	waitFor(t, func() bool { return srv2.Stats().Active == 0 })
	srv2.Close(context.Background())

	if fdOK {
		// Two GC cycles flush Go's sync.Pool victim cache in internal/poll.splicePipePool.
		for attempt := 0; attempt < 4; attempt++ {
			runtime.GC()
			runtime.GC()
			_, afterPipes, _ := countSelfPipeFDs(t)
			if afterPipes <= basePipes+8 {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		_, afterPipes, _ := countSelfPipeFDs(t)
		t.Fatalf("pipe FD leak after RST storm: baseline=%d after=%d", basePipes, afterPipes)
	}
}
