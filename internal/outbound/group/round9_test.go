package group

import (
	"context"
	"github.com/shui1iao/Kat/internal/outbound"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type r9SlowDial struct{ calls atomic.Int32 }

func (s *r9SlowDial) Name() string { return "member" }
func (s *r9SlowDial) Type() string { return "direct" }
func (s *r9SlowDial) Close() error { return nil }
func (s *r9SlowDial) UDP() bool    { return false }
func (s *r9SlowDial) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, outbound.ErrUDPUnsupported
}
func (s *r9SlowDial) DialTCP(ctx context.Context, a outbound.Addr) (net.Conn, error) {
	s.calls.Add(1)
	select {
	case <-time.After(80 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", a.String())
}
func TestR9UnifiedReusesOneSocketAndExcludesHandshake(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Error("not HEAD")
		}
		calls.Add(1)
		time.Sleep(15 * time.Millisecond)
		w.WriteHeader(204)
	}))
	defer target.Close()
	out := &r9SlowDial{}
	lat, e := ProbeOutboundDelay(context.Background(), out, target.URL, true)
	if e != nil || lat < 10*time.Millisecond || lat > 70*time.Millisecond || out.calls.Load() != 1 || calls.Load() != 2 {
		t.Fatal("not warm RTT", lat, e, out.calls.Load(), calls.Load())
	}
	out = &r9SlowDial{}
	lat, e = ProbeOutboundDelay(context.Background(), out, target.URL, false)
	if e != nil || lat < 90*time.Millisecond || out.calls.Load() != 1 || calls.Load() != 3 {
		t.Fatal("full mode changed", lat, e)
	}
}
func TestR9UnifiedSecondFailureRetainsFirstSampleWithoutRedial(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 2 {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(204)
	}))
	defer target.Close()
	out := &r9SlowDial{}
	lat, e := ProbeOutboundDelay(context.Background(), out, target.URL, true)
	if e != nil || lat < 85*time.Millisecond || out.calls.Load() != 1 || calls.Load() != 2 {
		t.Fatal("fallback must keep first full sample", lat, e, out.calls.Load(), calls.Load())
	}
}
func TestR9UnifiedClosingServerDoesNotStartAnotherConnection(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Connection", "close")
		w.WriteHeader(204)
	}))
	defer target.Close()
	out := &r9SlowDial{}
	lat, e := ProbeOutboundDelay(context.Background(), out, target.URL, true)
	if e != nil || lat < 75*time.Millisecond || out.calls.Load() != 1 || calls.Load() != 1 {
		t.Fatal(lat, e, out.calls.Load(), calls.Load())
	}
}
func TestR9UnifiedSameDeadlineAndExpectedStatus(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 2 {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second):
			}
		}
		w.WriteHeader(204)
	}))
	defer target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 140*time.Millisecond)
	defer cancel()
	out := &r9SlowDial{}
	before := time.Now()
	lat, e := ProbeOutboundDelay(ctx, out, target.URL, true)
	if e != nil || lat < 75*time.Millisecond || time.Since(before) > 300*time.Millisecond || out.calls.Load() != 1 {
		t.Fatal("deadline extended or first lost", lat, e)
	}
}
