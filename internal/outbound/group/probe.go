package group

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

type probeContextKey struct{}

// A background HTTP measurement must not start waiting for a newly cold
// dependency while holding capacity. Readiness can race a hot selection edit.
type preparedProbeKey struct{}

var errProbeDependencyUnready = errors.New("probe: dependency not ready")

type ProbeMeasurement struct{ Cold time.Duration }

func WithProbeMeasurement(ctx context.Context, m *ProbeMeasurement) context.Context {
	return context.WithValue(ctx, probeContextKey{}, m)
}
func isProbe(ctx context.Context) bool { return ctx.Value(probeContextKey{}) != nil }

// probeFunc measures one member. It returns the latency on success.
type probeFunc func(ctx context.Context, m outbound.Outbound) (time.Duration, error)

var errProbeStatus = errors.New("probe: server error status")

// httpProber issues one HTTP(S) GET to the configured URL through a member.
// Latency is measured from the start of the member dial to the arrival of the
// response headers. Any status < 500 is success (the path works). Redirects
// are not followed and the connection is never reused, so only the configured
// URL is ever contacted, once per member per round.
type httpProber struct {
	url    string
	target outbound.Addr
	tls    *tls.Config // nil: standard verification against system roots
	clk    clock
	// expected: statuses that count as success (probe.expected_status);
	// nil = any status below 500.
	unified  bool
	head     bool
	expected func(int) bool
}

func (p *httpProber) probe(ctx context.Context, m outbound.Outbound) (time.Duration, error) {
	if !isProbe(ctx) {
		ctx = WithProbeMeasurement(ctx, &ProbeMeasurement{})
	}
	var started time.Time
	var warm atomic.Bool
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if warm.Load() {
				return nil, errors.New("probe: warm connection unavailable")
			}
			// Always the configured URL's host:port, through the member.
			if p.head && started.IsZero() {
				started = p.clk.Now()
			}
			return m.DialTCP(ctx, p.target)
		},
		DisableKeepAlives:      !p.unified,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	if p.tls != nil {
		tr.TLSClientConfig = p.tls.Clone()
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	method := http.MethodGet
	if p.head {
		method = http.MethodHead
	}
	req, err := http.NewRequestWithContext(ctx, method, p.url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Kat-probe")
	start := p.clk.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	if p.head && (resp.StatusCode == 405 || resp.StatusCode == 501) {
		resp.Body.Close()
		req.Method = http.MethodGet
		resp, err = client.Do(req)
		if err != nil {
			return 0, err
		}
	}
	if p.head && !started.IsZero() {
		start = started
	}
	lat := p.clk.Now().Sub(start)
	if m, ok := ctx.Value(probeContextKey{}).(*ProbeMeasurement); ok {
		m.Cold = lat
	}
	// HEAD has no body. GET fallback is bounded/drained so only a reusable
	// connection can supply the unified sample. Never redial for sample two.
	_, drainErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if p.unified && drainErr == nil {
		second := p.clk.Now()
		reused := false
		secondCtx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }})
		// Reusing is mandatory: a closing server must retain the first full sample,
		// not silently turn a new handshake into an RTT. No extra destination dial.
		warm.Store(true)
		secondReq := req.Clone(secondCtx)
		if secondResp, e := client.Do(secondReq); e == nil {
			secondResp.Body.Close()
			if reused {
				resp = secondResp
				lat = p.clk.Now().Sub(second)
			}
		}
	}

	if p.expected != nil {
		if !p.expected(resp.StatusCode) {
			return 0, fmt.Errorf("%w %d (not an expected status)", errProbeStatus, resp.StatusCode)
		}
	} else if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("%w %d", errProbeStatus, resp.StatusCode)
	}
	return lat, nil
}

// ProbeOutbound reuses the production HTTP(S) prober without a group selection.
func ProbeOutbound(ctx context.Context, m outbound.Outbound, rawURL string) (time.Duration, error) {
	c, err := normalize(Options{Name: "manual-probe", Type: TypeURLTest, Members: []string{"target"}, Probe: &ProbeOptions{URL: rawURL}})
	if err != nil {
		return 0, errors.New("invalid HTTP(S) probe URL")
	}
	p := &httpProber{url: c.url, target: c.target, clk: realClock{}}
	return p.probe(ctx, m)
}

// ProbeOutboundHead is the desktop manual URLTest (unified-delay=false): HEAD,
// from dial to response headers, normal TLS verification; no redirect/body read.
// A target rejecting HEAD (405/501) gets GET within the SAME target deadline.
func ProbeOutboundHead(ctx context.Context, m outbound.Outbound, rawURL string) (time.Duration, error) {
	return ProbeOutboundDelay(ctx, m, rawURL, false)
}
func ProbeOutboundDelay(ctx context.Context, m outbound.Outbound, rawURL string, unified bool) (time.Duration, error) {
	return ProbeOutboundDelayWithStatus(ctx, m, rawURL, unified, "")
}

// ProbeOutboundDelayWithStatus retains the client's manual timeout/unified policy
// and honors the target group's HTTP success criteria using the same parser.
func ProbeOutboundDelayWithStatus(ctx context.Context, m outbound.Outbound, rawURL string, unified bool, expectedStatus string) (time.Duration, error) {
	c, e := normalize(Options{Name: "manual-probe", Type: TypeURLTest, Members: []string{"target"}, Probe: &ProbeOptions{URL: rawURL, ExpectedStatus: expectedStatus}})
	if e != nil {
		return 0, errors.New("invalid probe URL")
	}
	return (&httpProber{url: c.url, target: c.target, clk: realClock{}, head: true, unified: unified, expected: c.expected}).probe(ctx, m)
}
