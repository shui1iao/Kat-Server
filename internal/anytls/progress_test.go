package anytls

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestAuthenticatedIdleAndFrameCompletion(t *testing.T) {
	for _, part := range []string{"header", "body"} {
		t.Run(part, func(t *testing.T) {
			c := cfg()
			c.HandshakeTimeout = 150 * time.Millisecond
			cl := start(t, c, noHandler)
			login(t, cl, 2)
			// Waiting for the first byte of a frame is not a partial read.
			time.Sleep(c.HandshakeTimeout + 20*time.Millisecond)
			cl.send(t, wire(cmdHeartRequest, 1, nil))
			cl.next(t, cmdHeartResponse, 1)
			frame := wire(cmdWaste, 0, []byte("abc"))
			if part == "header" {
				cl.send(t, frame[:2])
			} else {
				cl.send(t, frame[:8])
			}
			select {
			case err := <-cl.result:
				cl.result <- err
				var ne net.Error
				if !errors.As(err, &ne) || !ne.Timeout() {
					t.Fatalf("want physical read timeout, got %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("partial frame did not release carrier")
			}
		})
	}
}
func TestPendingAndAuthenticatedQuotaAcrossGeneration(t *testing.T) {
	c := cfg()
	old := start(t, c, noHandler)
	login(t, old, 2)
	c.MaxSessions = 1
	c.MaxTotalStreams = 1
	next, e := old.server.PrepareSuccessor(c)
	if e != nil {
		t.Fatal(e)
	}
	if old.server.quota.maxSessions == 1 {
		t.Fatal("prepare changed live identity")
	}
	next.ActivateLimits()
	if old.server.quota.maxStreams != 1 {
		t.Fatal("old codec escaped new identity stream limit")
	}
	a, b := net.Pipe()
	defer b.Close()
	if e = next.Serve(context.Background(), a, noHandler); !errors.Is(e, ErrSessionLimit) {
		t.Fatal("successor ignored established carrier", e)
	}
	if old.server.Stats().Sessions != 1 || next.Stats().Sessions != 0 {
		t.Fatal("per-codec accounting inconsistent")
	}
}
func TestQueuedWriteDeadlineOnlyWithdrawsItsFrame(t *testing.T) {
	tr := &ownedBlockedTransport{entered: make(chan struct{}), unblock: make(chan struct{})}
	s, first := ownedSession(t, tr, 3*time.Second)
	second := &Stream{session: s, id: 22}
	go s.writeLoop()
	defer func() { s.fail(context.Canceled); <-s.writerDone }()
	var open = true
	defer func() {
		if open {
			close(tr.unblock)
		}
	}()
	firstDone := make(chan error, 1)
	go func() { _, e := first.Write([]byte("first")); firstDone <- e }()
	<-tr.entered
	secondDone := make(chan error, 1)
	go func() { _, e := second.Write([]byte("second")); secondDone <- e }()
	until := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		n := len(s.out)
		s.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("second not queued")
		}
		time.Sleep(time.Millisecond)
	}
	second.SetWriteDeadline(time.Now().Add(120 * time.Millisecond))
	second.SetWriteDeadline(time.Time{})
	select {
	case e := <-secondDone:
		t.Fatalf("cleared deadline fired: %v", e)
	case <-time.After(150 * time.Millisecond):
	}
	second.SetWriteDeadline(time.Now().Add(-time.Second))
	select {
	case e := <-secondDone:
		if !errors.Is(e, os.ErrDeadlineExceeded) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("updated deadline not honored")
	}
	if s.ctx.Err() != nil {
		t.Fatal("queued deadline cancelled unrelated writer")
	}
	s.mu.Lock()
	if len(s.out) != 0 || s.outFrames != 1 {
		s.mu.Unlock()
		t.Fatal("withdrawn frame still charged")
	}
	s.mu.Unlock()
	close(tr.unblock)
	open = false
	if e := <-firstDone; e != nil {
		t.Fatal(e)
	}
}
