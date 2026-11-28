package kernel

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type bufferPool struct {
	size int
	free chan []byte
}

func newBufferPool(size, count int) *bufferPool { return &bufferPool{size, make(chan []byte, count)} }
func (p *bufferPool) get() []byte {
	select {
	case b := <-p.free:
		return b
	default:
		return make([]byte, p.size)
	}
}
func (p *bufferPool) put(b []byte) {
	if cap(b) != p.size {
		return
	}
	clear(b[:cap(b)])
	select {
	case p.free <- b[:p.size]:
	default:
	}
}
func (p *bufferPool) bytes() uint64 {
	if p == nil {
		return 0
	}
	return uint64(len(p.free)) * uint64(p.size)
}
func (p *bufferPool) drain() int {
	if p == nil {
		return 0
	}
	dropped := 0
	for {
		select {
		case <-p.free:
			dropped++
		default:
			return dropped
		}
	}
}

// TrimBuffers drops idle relay buffers cached in the generation pool so long
// idle periods return their spans to the OS.
func (s *Server) TrimBuffers() int {
	if s == nil {
		return 0
	}
	cur := s.current()
	if cur == nil || cur.pool == nil {
		return 0
	}
	return cur.pool.drain()
}

const (
	smallRelayBufSize      = 8 << 10
	smallRelayDemoteThresh = 4 << 10
)

var smallRelayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, smallRelayBufSize)
		return &b
	},
}

type readOnly struct{ io.Reader }
type writeOnly struct{ io.Writer }

func (s *Server) copy(dst, src net.Conn) error { return s.copyM(dst, src, meter{}) }

// spliceChunk bounds one kernel splice while statistics are kept, so that
// counters and rates advance smoothly during long transfers.
const spliceChunk = 64 << 10

// copyM is copy with payload metering: m counts the bytes written to dst.
func (s *Server) copyM(dst, src net.Conn, m meter) error {
	if t, ok := ss2022DownSource(src); ok {
		return s.copySS2022DownM(dst, src, t, m)
	}
	if !s.cfg.Limits.DisableFastPath {
		rawDst, dstAct := unwrapActivity(dst)
		rawSrc, srcAct := unwrapActivity(src)
		if d, ok := rawDst.(*net.TCPConn); ok {
			if r, ok := rawSrc.(*net.TCPConn); ok {
				act := dstAct
				if act == nil {
					act = srcAct
				}
				if m.f == nil && act == nil {
					_, e := d.ReadFrom(r)
					return e
				}
				for {
					// LimitedReader over a TCPConn preserves Linux kernel splice(2)
					// while advancing flow statistics and idle activity timestamps.
					n, e := d.ReadFrom(&io.LimitedReader{R: r, N: spliceChunk})
					if n > 0 {
						m.add(int(n))
						if act != nil {
							act.Store(time.Now().UnixNano())
						}
					}
					if e != nil || n < spliceChunk {
						return e
					}
				}
			}
		}
	}
	rawSrcConn, _ := unwrapActivity(src)
	_, ss2017Down := rawSrcConn.(*ssDownReadConn)
	if s.pool.size <= smallRelayBufSize || ss2017Down {
		b := s.pool.get()
		defer s.pool.put(b)
		_, e := io.CopyBuffer(writeOnly{m.writer(dst)}, readOnly{src}, b)
		return e
	}
	return copyAdaptive(dst, src, m, s.pool)
}
func closeWrite(c net.Conn) error {
	if v, ok := c.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return c.Close()
}

func unwrapActivity(c net.Conn) (net.Conn, *atomic.Int64) {
	if a, ok := c.(*activityStream); ok {
		return a.Conn, a.last
	}
	return c, nil
}

type activityStream struct {
	net.Conn
	last *atomic.Int64
}

func (c *activityStream) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, e
}
func (c *activityStream) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, e
}
func (c *activityStream) CloseWrite() error { return closeWrite(c.Conn) }
func (s *Server) relay(ctx context.Context, a, b net.Conn) error {
	return s.relayIdle(ctx, a, b, s.cfg.Limits.TCPIdle.value())
}
func (s *Server) relayIdle(ctx context.Context, a, b net.Conn, idle time.Duration) error {
	if idle > 0 {
		var last atomic.Int64
		last.Store(time.Now().UnixNano())
		stop := make(chan struct{})
		exited := make(chan struct{})
		defer func() { close(stop); <-exited }()
		originalA, originalB := a, b
		var tcA, tcB *net.TCPConn
		var progA, progB tcpProgressSample
		if !s.cfg.Limits.DisableFastPath {
			a1, b1 := extractTCPConn(originalA), extractTCPConn(originalB)
			if a1 != nil && b1 != nil {
				tcA, tcB = a1, b1
				progA = sampleTCPProgress(tcA)
				progB = sampleTCPProgress(tcB)
			}
		}
		go func() {
			defer close(exited)
			timer := time.NewTimer(idle)
			defer timer.Stop()
			for {
				select {
				case <-stop:
					return
				case <-timer.C:
					now := time.Now()
					remaining := idle - now.Sub(time.Unix(0, last.Load()))
					if remaining <= 0 {
						if tcA != nil && tcB != nil {
							curA := sampleTCPProgress(tcA)
							curB := sampleTCPProgress(tcB)
							if curA.advanced(progA) || curB.advanced(progB) {
								progA, progB = curA, curB
								last.Store(now.UnixNano())
								timer.Reset(idle)
								continue
							}
						}
						originalA.Close()
						originalB.Close()
						return
					}
					if tcA != nil && tcB != nil {
						progA = sampleTCPProgress(tcA)
						progB = sampleTCPProgress(tcB)
					}
					timer.Reset(remaining)
				}
			}
		}()
		a = &activityStream{a, &last}
		b = &activityStream{b, &last}
	}

	done := make(chan error, 2)
	up, down := meters(ctx)
	transfer := func(dst, src net.Conn, m meter) {
		e := s.copyM(dst, src, m)
		if e == nil {
			e = closeWrite(dst)
		}
		done <- e
	}
	// a is the client side, b the target: b->a is download, a->b upload.
	go transfer(a, b, down)
	go transfer(b, a, up)
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		a.Close()
		b.Close()
		<-done
		<-done
		return ctx.Err()
	}
	if err != nil {
		a.Close()
		b.Close()
	} else {
		deadline := time.Now().Add(s.cfg.Limits.DrainTimeout.value())
		a.SetDeadline(deadline)
		b.SetDeadline(deadline)
	}
	select {
	case e := <-done:
		if err == nil && !quietFailure(e) {
			err = e
		}
	case <-ctx.Done():
		a.Close()
		b.Close()
		<-done
		err = ctx.Err()
	}
	return err
}

// copyAdaptive starts with the full pool buffer (preserving single-write bulk
// framing) and demotes idle/small-frame streams (<= 4 KiB read) to an 8 KiB
// pooled buffer while blocked in Read, promoting immediately back to the full
// buffer as soon as a read fills 8 KiB.
func copyAdaptive(dst, src net.Conn, m meter, pool *bufferPool) error {
	w := m.writer(dst)
	large := pool.get()
	var smallPtr *[]byte
	cur := large
	defer func() {
		if large != nil {
			pool.put(large)
		}
		if smallPtr != nil {
			clear(*smallPtr)
			smallRelayBufPool.Put(smallPtr)
		}
	}()
	for {
		nr, er := src.Read(cur)
		if nr > 0 {
			nw, ew := w.Write(cur[:nr])
			if ew != nil {
				return ew
			}
			if nr != nw {
				return io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return nil
			}
			return er
		}
		if large != nil && nr <= smallRelayDemoteThresh {
			pool.put(large)
			large = nil
			smallPtr = smallRelayBufPool.Get().(*[]byte)
			cur = *smallPtr
		} else if large == nil && nr == len(cur) {
			clear(*smallPtr)
			smallRelayBufPool.Put(smallPtr)
			smallPtr = nil
			large = pool.get()
			cur = large
		}
	}
}
