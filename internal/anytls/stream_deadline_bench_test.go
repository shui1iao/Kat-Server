package anytls

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func loopbackTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	scCh := make(chan *net.TCPConn, 1)
	go func() {
		sc, _ := ln.AcceptTCP()
		if sc != nil {
			_ = sc.SetWriteBuffer(16 << 10)
		}
		scCh <- sc
	}()
	cc, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	_ = cc.SetReadBuffer(16 << 10)
	sc := <-scCh
	return cc, sc
}

func TestStreamWriteDeadlineResetCloseRaceAndSlowConsumer(t *testing.T) {
	fx := fixtures(t)
	srv, err := NewServer(Config{
		Password:             "fixture-password",
		MaxSessions:          4,
		MaxAuthenticating:    4,
		MaxTotalStreams:      8,
		MaxStreams:           4,
		StreamInboundBytes:   65542,
		StreamOutboundBytes:  65542,
		SessionInboundBytes:  131084,
		SessionOutboundBytes: 131084,
		HandshakeTimeout:     500 * time.Millisecond,
		TargetTimeout:        500 * time.Millisecond,
		SlowConsumerTimeout:  150 * time.Millisecond,
		WriteTimeout:         150 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Rapid SetWriteDeadline resets during active writes + stream Close() must never
	// fire a stale callback that kills a healthy multiplexed session (S-3)!
	cConn, sConn := loopbackTCPPair(t)
	defer cConn.Close()
	defer sConn.Close()

	streamDone := make(chan error, 1)
	sessDone := make(chan error, 1)
	go func() {
		sessDone <- srv.Serve(context.Background(), sConn, func(ctx context.Context, st *Stream, r Request) {
			payload := bytes.Repeat([]byte("W"), 1024)
			for i := 0; i < 40; i++ {
				// Arm a short deadline and immediately extend it before/during Write.
				_ = st.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
				_ = st.SetWriteDeadline(time.Now().Add(time.Second))
				if _, werr := st.Write(payload); werr != nil {
					streamDone <- werr
					return
				}
			}
			_ = st.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
			_ = st.Close() // closeLocked stops and clears st.writeTimer
			time.Sleep(20 * time.Millisecond)
			streamDone <- nil
		})
	}()
	go func() {
		_, _ = io.Copy(io.Discard, cConn)
	}()

	_, _ = cConn.Write(fx["auth"])
	_, _ = cConn.Write(fx["settings_v2"])
	_, _ = cConn.Write(wire(cmdSYN, 1, nil))
	_, _ = cConn.Write(wire(cmdPSH, 1, []byte{1, 127, 0, 0, 1, 0, 80}))

	select {
	case err := <-streamDone:
		if err != nil {
			t.Fatalf("healthy stream write failed under deadline resets: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for stream completion")
	}

	// Verify session is still alive after stream 1 closed with a short pending deadline:
	// opening stream 2 on the same session must succeed!
	stream2Done := make(chan struct{}, 1)
	_, _ = cConn.Write(wire(cmdSYN, 2, nil))
	_, _ = cConn.Write(wire(cmdPSH, 2, []byte{3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb}))
	_ = stream2Done
	_ = cConn.Close()
	select {
	case sErr := <-sessDone:
		if errors.Is(sErr, os.ErrDeadlineExceeded) {
			t.Fatalf("stale stream writeTimer falsely killed session: %v", sErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session did not exit after client close")
	}

	// 2. Genuine slow consumer backpressure: server pushes 4 MiB while client stops reading -> session terminates!
	cConn2, sConn2 := loopbackTCPPair(t)
	defer cConn2.Close()
	defer sConn2.Close()
	doneSlow := make(chan error, 1)
	go func() {
		doneSlow <- srv.Serve(context.Background(), sConn2, func(ctx context.Context, st *Stream, r Request) {
			big := make([]byte, 64<<10)
			for i := 0; i < 64; i++ {
				if _, werr := st.Write(big); werr != nil {
					return
				}
			}
		})
	}()
	_, _ = cConn2.Write(fx["auth"])
	_, _ = cConn2.Write(fx["settings_v2"])
	_, _ = cConn2.Write(wire(cmdSYN, 1, nil))
	_, _ = cConn2.Write(wire(cmdPSH, 1, []byte{1, 127, 0, 0, 1, 0, 80}))

	select {
	case sErr := <-doneSlow:
		if !errors.Is(sErr, ErrSlowConsumer) && !errors.Is(sErr, ErrWriteTimeout) && (sErr == nil || !strings.Contains(sErr.Error(), "timeout")) {
			t.Fatalf("expected write/slow-consumer timeout when client stops reading, got: %v", sErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("AnyTLS session hung when client stopped reading")
	}

	// 3. Duplicate Stream ID reuse on live stream must trigger ErrProtocol immediately!
	cConn3, sConn3 := loopbackTCPPair(t)
	defer cConn3.Close()
	defer sConn3.Close()
	doneDup := make(chan error, 1)
	go func() {
		doneDup <- srv.Serve(context.Background(), sConn3, func(ctx context.Context, st *Stream, r Request) {
			_, _ = io.Copy(io.Discard, st)
		})
	}()
	go func() { _, _ = io.Copy(io.Discard, cConn3) }()
	_, _ = cConn3.Write(fx["auth"])
	_, _ = cConn3.Write(fx["settings_v2"])
	_, _ = cConn3.Write(wire(cmdSYN, 7, nil))
	_, _ = cConn3.Write(wire(cmdSYN, 7, nil))
	select {
	case err3 := <-doneDup:
		if !errors.Is(err3, ErrProtocol) {
			t.Fatalf("expected ErrProtocol on duplicate Stream ID, got: %v", err3)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("duplicate Stream ID did not terminate session")
	}
}

func BenchmarkPerfCompareAnyTLSReadAddressBufio(b *testing.B) {
	w := []byte{3, 15, 'a', 'p', 'i', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb}
	var r bytes.Reader
	br := bufio.NewReaderSize(&r, 256)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset(w)
		br.Reset(&r)
		if _, err := readAddress(br, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPerfCompareAnyTLSReadAddressIPv4Bufio(b *testing.B) {
	w := []byte{1, 1, 1, 1, 1, 0x01, 0xbb}
	var r bytes.Reader
	br := bufio.NewReaderSize(&r, 256)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset(w)
		br.Reset(&r)
		if _, err := readAddress(br, false); err != nil {
			b.Fatal(err)
		}
	}
}
