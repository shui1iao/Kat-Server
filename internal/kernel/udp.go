package kernel

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const maxDatagram = 65507

const udpSmallBufCap = 2048

var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, udpSmallBufCap)
		return &b
	},
}

func getUDPPlainBuf() []byte {
	return (*udpBufPool.Get().(*[]byte))[:0]
}

func putUDPPlainBuf(b []byte) {
	if cap(b) == udpSmallBufCap {
		s := b[:udpSmallBufCap]
		clear(s)
		udpBufPool.Put(&s)
	}
}

func deadlineRefreshInterval(d time.Duration) int64 {
	if d < 200*time.Millisecond {
		return 0
	}
	iv := d / 4
	if iv > time.Second {
		iv = time.Second
	}
	return int64(iv)
}

type packet struct {
	target  Address
	payload []byte
	pooled  []byte // optional backing buffer to return to udpBufPool after send/drop
}

func releasePacket(p packet) {
	if p.pooled != nil {
		putUDPPlainBuf(p.pooled)
	}
}
type udpAssociation struct {
	server                       *Server
	writeBack                    func(Address, []byte) error
	writeBackBatch               func([]Address, [][]byte) error
	ssNative                     bool // only native SS uses bidirectional target idle refresh
	ctx                          context.Context
	cancel                       context.CancelFunc
	stream                       net.Conn
	outbound4, outbound6, native *net.UDPConn
	raw4, raw6, rawNative        syscall.RawConn
	v6Native                     bool
	activity                     atomic.Int64
	queuedBytes                  atomic.Int64
	outputMu                     sync.Mutex
	req                          request
	queue                        chan packet
	mu                           sync.Mutex
	client                       netip.AddrPort
	allowed                      map[netip.AddrPort]time.Time
	wg                           sync.WaitGroup
	source                       netip.Addr
	// Statistics: the association's flow and the route of each direct
	// target (same lifetime as allowed, guarded by mu) for reply metering.
	flow   *flow
	routes map[netip.AddrPort]*udpRoute

	// Hot-path throttling state (single-writer per loop or guarded by outputMu/mu).
	lastAllowedSweep     int64
	lastOutWriteDL4      int64
	lastOutWriteDL6      int64
	lastOutputWriteDL    int64
}

func (s *Server) resolve(ctx context.Context, a Address) (netip.AddrPort, error) {
	if a.Port == 0 {
		return netip.AddrPort{}, errors.New("zero destination port")
	}
	if ip, e := netip.ParseAddr(a.Host); e == nil {
		return netip.AddrPortFrom(ip.Unmap(), a.Port), nil
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.DialTimeout.value())
	defer cancel()
	if e := s.dialSlots.acquire(ctx); e != nil {
		return netip.AddrPort{}, e
	}
	s.counters.Dials.Add(1)
	defer func() { s.dialSlots.release(); s.counters.Dials.Add(-1) }()
	ips, e := s.lookup(ctx, a.Host)
	if e != nil {
		return netip.AddrPort{}, e
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, errors.New("no address")
	}
	return netip.AddrPortFrom(ips[0].Unmap(), a.Port), nil
}
func (s *Server) serveUDP(c net.Conn, r request) error {
	if !s.udpSlots.try() {
		s.failure(failUDPBudget, "udp", -1)
		_ = r.respond(c, nil, false)
		return errors.New("UDP association limit")
	}
	s.counters.UDP.Add(1)
	defer func() { s.udpSlots.release(); s.counters.UDP.Add(-1) }()
	parent := s.ctx
	if r.Context != nil {
		parent = r.Context
	}
	f, fparent := s.newFlow(parent, "udp", Address{})
	ctx, cancel := context.WithCancel(fparent)
	a := &udpAssociation{server: s, ctx: ctx, cancel: cancel, stream: c, req: r, queue: make(chan packet, s.cfg.Limits.UDPQueue), allowed: make(map[netip.AddrPort]time.Time), flow: f}
	a.source = sourceOf(parent)
	if !a.source.IsValid() {
		a.source = addrIP(c.RemoteAddr())
	}
	f.setSource(a.source)
	defer f.end("ok")
	defer cancel()
	var e error
	a.outbound4, e = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(s.cfg.UDPBindIPv4)})
	if e != nil {
		return e
	}
	a.raw4, _ = a.outbound4.SyscallConn()
	defer a.outbound4.Close()
	a.outbound6, e = net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP(s.cfg.UDPBindIPv6)})
	if e != nil && s.cfg.UDPBindIPv6 != "" {
		return e
	}
	if a.outbound6 != nil {
		a.raw6, _ = a.outbound6.SyscallConn()
		defer a.outbound6.Close()
	}
	if r.Mode == "socks5" {
		peer := c.RemoteAddr().(*net.TCPAddr).AddrPort()
		peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
		ip, err := netip.ParseAddr(r.Target.Host)
		if err != nil {
			v, err := s.resolve(ctx, Address{r.Target.Host, 1})
			if err != nil {
				return err
			}
			ip = v.Addr()
		}
		if !ip.IsUnspecified() && ip.Unmap() != peer.Addr() {
			_ = r.respond(c, nil, false)
			return errors.New("UDP client address must match TCP peer")
		}
		a.client = netip.AddrPortFrom(peer.Addr(), r.Target.Port)
		local := c.LocalAddr().(*net.TCPAddr)
		a.native, e = net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Zone: local.Zone})
		if e != nil {
			return e
		}
		a.rawNative, _ = a.native.SyscallConn()
		a.v6Native = isIPv6UDPSocket(a.native)
		defer a.native.Close()
	}
	var bound net.Addr
	if a.native != nil {
		bound = a.native.LocalAddr()
	}
	if e = r.respond(c, bound, true); e != nil {
		return e
	}
	a.activity.Store(time.Now().UnixNano())
	// One cancellation watcher, sender and return reader per association; never per packet.
	a.wg.Add(2)
	go func() {
		defer a.wg.Done()
		<-ctx.Done()
		c.Close()
		a.outbound4.Close()
		if a.outbound6 != nil {
			a.outbound6.Close()
		}
		if a.native != nil {
			a.native.Close()
		}
	}()
	go func() { defer a.wg.Done(); defer cancel(); a.sendLoop() }()
	for _, socket := range []*net.UDPConn{a.outbound4, a.outbound6} {
		if socket == nil {
			continue
		}
		a.wg.Add(1)
		go func() { defer a.wg.Done(); defer cancel(); a.returnLoop(socket) }()
	}
	if a.native != nil {
		a.wg.Add(1)
		go func() { defer a.wg.Done(); defer cancel(); var b [1]byte; _, _ = c.Read(b[:]) }()
		e = a.nativeLoop()
	} else {
		e = a.streamLoop()
	}
	cancel()
	a.wg.Wait()
	// Release all queued payloads; they are private bounded allocations, not shared pool references.
	for {
		select {
		case p := <-a.queue:
			a.queuedBytes.Add(-int64(len(p.payload)))
			releasePacket(p)
		default:
			return e
		}
	}
}
func (a *udpAssociation) enqueue(p packet) {
	n := int64(len(p.payload))
	limit := int64(a.server.cfg.Limits.UDPQueueBytes)
	// A zero limit only exists in isolated unit fixtures; validated servers always set it.
	if limit == 0 {
		limit = int64(a.server.cfg.Limits.UDPQueue * maxDatagram)
	}
	if a.ctx.Err() != nil {
		releasePacket(p)
		return
	}
	for {
		old := a.queuedBytes.Load()
		if n > limit-old {
			releasePacket(p)
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPQueue, "udp", -1)
			return
		}
		if a.queuedBytes.CompareAndSwap(old, old+n) {
			break
		}
	}
	select {
	case <-a.ctx.Done():
		a.queuedBytes.Add(-n)
		releasePacket(p)
	case a.queue <- p:
	default:
		a.queuedBytes.Add(-n)
		releasePacket(p)
		a.server.counters.Dropped.Add(1)
		a.server.failure(failUDPQueue, "udp", -1)
	}
}
func (a *udpAssociation) nativeLoop() error {
	b := make([]byte, 65535)
	var frags *reassembly // created by the first fragment (FRAG != 0)
	defer func() {
		if frags != nil {
			frags.close()
		}
	}()
	for {
		n, src, e := a.native.ReadFromUDPAddrPort(b)
		if e != nil {
			return e
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		a.mu.Lock()
		client := a.client
		a.mu.Unlock()
		if src.Addr() != client.Addr() || (client.Port() != 0 && src.Port() != client.Port()) {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			continue
		}
		if n < 4 || b[0] != 0 || b[1] != 0 {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			continue
		}
		reader := bytes.NewReader(b[3:n])
		target, e := readAddress(reader, false)
		if e != nil || reader.Len() > maxDatagram || target.Port == 0 {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			continue
		}
		a.mu.Lock()
		if a.client.Port() == 0 {
			a.client = src
		}
		a.mu.Unlock()
		payload := append([]byte(nil), b[n-reader.Len():n]...)
		if b[2] != 0 {
			if frags == nil {
				frags = a.newReassembly()
			}
			if frags == nil {
				a.server.frags.dropped.Add(1)
				continue
			}
			var ok bool
			if target, payload, ok = frags.add(b[2], target, payload); !ok {
				continue
			}
		}
		a.enqueue(packet{target: target, payload: payload})
	}
}
func (a *udpAssociation) streamLoop() error {
	if a.req.UDPRead != nil {
		for {
			p, e := a.req.UDPRead()
			if e != nil {
				return e
			}
			a.enqueue(p)
		}
	}
	if a.req.Datagrams == nil {
		return errors.New("missing datagram codec")
	}
	for {
		p, e := a.req.Datagrams.ReadPacket(a.stream, a.req.Target)
		if e != nil {
			return e
		}
		a.enqueue(p)
	}
}
func (a *udpAssociation) sendLoop() {
	idle := a.server.cfg.Limits.UDPIdle.value()
	var batch [udpMmsgBatchSize]packet
	var sb udpSendBatch
	for {
		select {
		case <-a.ctx.Done():
			return
		case p := <-a.queue:
			batch[0] = p
			n := 1
			drainedBytes := int64(len(p.payload))
			for n < udpMmsgBatchSize {
				select {
				case p2 := <-a.queue:
					batch[n] = p2
					drainedBytes += int64(len(p2.payload))
					n++
				default:
					goto drained
				}
			}
		drained:
			a.queuedBytes.Add(-drainedBytes)
			if n == 1 {
				a.send(a.ctx, batch[0], idle)
				batch[0] = packet{}
			} else {
				a.sendBatch(a.ctx, batch[:n], idle, &sb)
				clear(batch[:n])
			}
		}
	}
}

func (a *udpAssociation) sendBatch(ctx context.Context, batch []packet, idle time.Duration, sb *udpSendBatch) {
	defer func() {
		for _, p := range batch {
			releasePacket(p)
		}
	}()
	var (
		pkts4, pkts6   [udpMmsgBatchSize][]byte
		addrs4, addrs6 [udpMmsgBatchSize]netip.AddrPort
		rts4, rts6     [udpMmsgBatchSize]*udpRoute
		n4, n6         int

		lastTarget Address
		lastIP     netip.AddrPort
		lastSock   *net.UDPConn
		lastRT     *udpRoute
		hasLast    bool
	)
	now := time.Now()
	nowNano := now.UnixNano()

	a.mu.Lock()
	if nowNano-a.lastAllowedSweep >= int64(idle/2) {
		for k, t := range a.allowed {
			if now.Sub(t) > idle {
				delete(a.allowed, k)
				delete(a.routes, k)
			}
		}
		a.lastAllowedSweep = nowNano
	}
	a.mu.Unlock()

	for i := range batch {
		p := batch[i]
		var (
			target netip.AddrPort
			socket *net.UDPConn
			rt     *udpRoute
		)
		if hasLast && p.target == lastTarget {
			target, socket, rt = lastIP, lastSock, lastRT
		} else {
			candidates, e := a.server.routeUDP(ctx, p.target)
			if e != nil {
				a.server.counters.Dropped.Add(1)
				a.server.resolutionFailure(e)
				continue
			}
			var allBlocked bool
			target, socket, allBlocked = a.selectDestination(candidates)
			if socket == nil {
				a.server.counters.Dropped.Add(1)
				if allBlocked {
					a.server.failure(failBlocked, "udp", -1)
				} else {
					a.server.failure(failUDPInvalid, "udp", -1)
				}
				continue
			}
			rt = a.flow.udpDecided(p.target, 0, []string{"direct"})
			a.mu.Lock()
			_, exists := a.allowed[target]
			if !exists && len(a.allowed) >= a.server.cfg.Limits.UDPTargets {
				for k, t := range a.allowed {
					if now.Sub(t) > idle {
						delete(a.allowed, k)
						delete(a.routes, k)
					}
				}
				a.lastAllowedSweep = nowNano
			}
			if !exists && len(a.allowed) >= a.server.cfg.Limits.UDPTargets {
				a.mu.Unlock()
				a.server.counters.Dropped.Add(1)
				a.server.failure(failUDPTargets, "udp", -1)
				continue
			}
			a.allowed[target] = now
			if rt != nil {
				if a.routes == nil {
					a.routes = map[netip.AddrPort]*udpRoute{}
				}
				a.routes[target] = rt
			}
			a.mu.Unlock()
			lastTarget, lastIP, lastSock, lastRT, hasLast = p.target, target, socket, rt, true
		}
		if socket == a.outbound4 {
			pkts4[n4] = p.payload
			addrs4[n4] = target
			rts4[n4] = rt
			n4++
		} else {
			pkts6[n6] = p.payload
			addrs6[n6] = target
			rts6[n6] = rt
			n6++
		}
	}

	dialTimeout := a.server.cfg.Limits.DialTimeout.value()
	iv := deadlineRefreshInterval(dialTimeout)
	sentAny := false
	if n4 > 0 {
		a.outputMu.Lock()
		if iv == 0 || nowNano-a.lastOutWriteDL4 >= iv {
			a.outbound4.SetWriteDeadline(now.Add(dialTimeout))
			a.lastOutWriteDL4 = nowNano
		}
		sent, e := writeUDPBatch(a.outbound4, a.raw4, false, sb, pkts4[:n4], addrs4[:n4])
		a.outputMu.Unlock()
		for i := 0; i < sent; i++ {
			a.flow.udpUp(rts4[i], len(pkts4[i]))
		}
		if sent > 0 {
			sentAny = true
		}
		if e != nil {
			a.server.counters.Dropped.Add(int64(n4 - sent))
			a.server.failure(failUDPIO, "udp", -1)
		}
	}
	if n6 > 0 {
		a.outputMu.Lock()
		if iv == 0 || nowNano-a.lastOutWriteDL6 >= iv {
			a.outbound6.SetWriteDeadline(now.Add(dialTimeout))
			a.lastOutWriteDL6 = nowNano
		}
		sent, e := writeUDPBatch(a.outbound6, a.raw6, true, sb, pkts6[:n6], addrs6[:n6])
		a.outputMu.Unlock()
		for i := 0; i < sent; i++ {
			a.flow.udpUp(rts6[i], len(pkts6[i]))
		}
		if sent > 0 {
			sentAny = true
		}
		if e != nil {
			a.server.counters.Dropped.Add(int64(n6 - sent))
			a.server.failure(failUDPIO, "udp", -1)
		}
	}
	if sentAny && !a.ssNative {
		a.activity.Store(nowNano)
	}
}

// selectDestination keeps DNS order but never treats one denied address as
// a denial of later, permitted answers. A missing address family is not an ACL denial.
func (a *udpAssociation) selectDestination(candidates []netip.AddrPort) (netip.AddrPort, *net.UDPConn, bool) {
	blocked := 0
	for _, ip := range candidates {
		if a.server.cfg.blockedDestination(ip.Addr()) {
			blocked++
			continue
		}
		socket := a.outbound4
		if ip.Addr().Is6() {
			socket = a.outbound6
		}
		if socket != nil {
			return ip, socket, false
		}
	}
	return netip.AddrPort{}, nil, len(candidates) > 0 && blocked == len(candidates)
}

// send resolves and forwards one datagram directly.
func (a *udpAssociation) send(ctx context.Context, p packet, idle time.Duration) {
	defer releasePacket(p)
	candidates, e := a.server.routeUDP(ctx, p.target)
	if e != nil {
		a.server.counters.Dropped.Add(1)
		a.server.resolutionFailure(e)
		return
	}
	target, socket, allBlocked := a.selectDestination(candidates)
	if socket == nil {
		a.server.counters.Dropped.Add(1)
		if allBlocked {
			a.server.failure(failBlocked, "udp", -1)
		} else {
			a.server.failure(failUDPInvalid, "udp", -1)
		}
		return
	}
	rt := a.flow.udpDecided(p.target, 0, []string{"direct"})
	now := time.Now()
	nowNano := now.UnixNano()
	a.mu.Lock()
	_, exists := a.allowed[target]
	if (!exists && len(a.allowed) >= a.server.cfg.Limits.UDPTargets) || nowNano-a.lastAllowedSweep >= int64(idle/2) {
		for k, t := range a.allowed {
			if now.Sub(t) > idle {
				delete(a.allowed, k)
				delete(a.routes, k)
			}
		}
		a.lastAllowedSweep = nowNano
	}
	if !exists && len(a.allowed) >= a.server.cfg.Limits.UDPTargets {
		a.mu.Unlock()
		a.server.counters.Dropped.Add(1)
		a.server.failure(failUDPTargets, "udp", -1)
		return
	}
	a.allowed[target] = now
	if rt != nil {
		if a.routes == nil {
			a.routes = map[netip.AddrPort]*udpRoute{}
		}
		a.routes[target] = rt
	}
	a.mu.Unlock()
	dialTimeout := a.server.cfg.Limits.DialTimeout.value()
	a.outputMu.Lock()
	dlPtr := &a.lastOutWriteDL4
	if socket == a.outbound6 {
		dlPtr = &a.lastOutWriteDL6
	}
	if iv := deadlineRefreshInterval(dialTimeout); iv == 0 || nowNano-*dlPtr >= iv {
		socket.SetWriteDeadline(now.Add(dialTimeout))
		*dlPtr = nowNano
	}
	_, e = socket.WriteToUDPAddrPort(p.payload, target)
	a.outputMu.Unlock()
	if e != nil {
		a.server.counters.Dropped.Add(1)
		a.server.failure(failUDPIO, "udp", -1)
		return
	}
	a.flow.udpUp(rt, len(p.payload))
	if !a.ssNative {
		a.activity.Store(nowNano)
	}
}
func (a *udpAssociation) returnLoop(socket *net.UDPConn) {
	b := make([]byte, 65535)
	idle := a.server.cfg.Limits.UDPIdle.value()
	readDLInterval := deadlineRefreshInterval(idle)
	var lastReadDL int64
	var lastSrcAddr netip.Addr
	var lastSrcHost string
	var pktSeen int
	var rb *udpRecvBatch
	var raw syscall.RawConn
	defer func() {
		if rb != nil {
			releaseUDPRecvBatch(rb)
		}
	}()
	var (
		outSrcs     [udpMmsgBatchSize]Address
		outPayloads [udpMmsgBatchSize][]byte
		outRTs      [udpMmsgBatchSize]*udpRoute
		outLens     [udpMmsgBatchSize]int
	)
	for {
		act := a.activity.Load()
		if readDLInterval == 0 || lastReadDL == 0 || act-lastReadDL >= readDLInterval {
			socket.SetReadDeadline(time.Unix(0, act).Add(idle))
			lastReadDL = act
		}
		if rb == nil {
			n, src, e := socket.ReadFromUDPAddrPort(b)
			if e != nil {
				if timeout, ok := e.(net.Error); ok && timeout.Timeout() && time.Since(time.Unix(0, a.activity.Load())) < idle {
					lastReadDL = 0
					continue
				}
				return
			}
			addr := src.Addr().Unmap()
			src = netip.AddrPortFrom(addr, src.Port())
			now := time.Now()
			client, rt, ok := a.acceptReturnWithMeta(src, n, now, idle)
			if !ok {
				a.server.counters.Dropped.Add(1)
				a.server.failure(failUDPSource, "udp", -1)
				continue
			}
			if addr != lastSrcAddr {
				lastSrcAddr = addr
				lastSrcHost = addr.String()
			}
			payload := b[:n]
			source := Address{lastSrcHost, src.Port()}
			if e = a.output(client, source, payload, idle); e != nil {
				return
			}
			if a.flow != nil {
				a.flow.udpDown(rt, n)
			}
			pktSeen++
			if pktSeen == udpMmsgUpgradeCnt {
				if socket == a.outbound4 {
					raw = a.raw4
				} else if socket == a.outbound6 {
					raw = a.raw6
				} else {
					raw, _ = socket.SyscallConn()
				}
				if raw != nil {
					rb = acquireUDPRecvBatch()
					b = nil // release single-packet buffer once upgraded
				}
			}
			continue
		}

		cnt, e := readUDPBatch(socket, raw, rb)
		if e != nil {
			if timeout, ok := e.(net.Error); ok && timeout.Timeout() && time.Since(time.Unix(0, a.activity.Load())) < idle {
				lastReadDL = 0
				continue
			}
			return
		}
		now := time.Now()
		nowNano := now.UnixNano()
		valid := 0
		var client netip.AddrPort
		a.mu.Lock()
		client = a.client
		for i := 0; i < cnt; i++ {
			src := rb.addrs[i]
			n := rb.lens[i]
			if !src.IsValid() || n > maxDatagram {
				a.server.counters.Dropped.Add(1)
				a.server.failure(failUDPSource, "udp", -1)
				continue
			}
			last, ok := a.allowed[src]
			expired := now.Sub(last) > idle
			if a.ssNative {
				expired = now.Sub(last) >= idle
			}
			if !ok || expired {
				a.server.counters.Dropped.Add(1)
				a.server.failure(failUDPSource, "udp", -1)
				continue
			}
			if a.ssNative && now.After(last) {
				a.allowed[src] = now
			}
			addr := src.Addr()
			if addr != lastSrcAddr {
				lastSrcAddr = addr
				lastSrcHost = addr.String()
			}
			outSrcs[valid] = Address{lastSrcHost, src.Port()}
			outPayloads[valid] = rb.bufs[i][:n]
			outRTs[valid] = a.routes[src]
			outLens[valid] = n
			valid++
		}
		if valid > 0 {
			if a.ssNative {
				a.touchSSActivity(now)
			} else {
				a.activity.Store(nowNano)
			}
		}
		a.mu.Unlock()
		if valid == 0 {
			continue
		}
		if e = a.outputBatch(client, outSrcs[:valid], outPayloads[:valid], idle); e != nil {
			return
		}
		if a.flow != nil {
			for i := 0; i < valid; i++ {
				a.flow.udpDown(outRTs[i], outLens[i])
			}
		}
	}
}

func (a *udpAssociation) outputBatch(client netip.AddrPort, sources []Address, payloads [][]byte, idle time.Duration) error {
	if len(payloads) == 0 {
		return nil
	}
	if len(payloads) == 1 {
		return a.output(client, sources[0], payloads[0], idle)
	}
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	if a.writeBackBatch != nil {
		return a.writeBackBatch(sources, payloads)
	}
	if a.writeBack != nil {
		for i := range payloads {
			if e := a.writeBack(sources[i], payloads[i]); e != nil {
				return e
			}
		}
		return nil
	}
	if a.req.UDPWriteBatch != nil {
		now := time.Now()
		nowNano := now.UnixNano()
		if iv := deadlineRefreshInterval(idle); iv == 0 || nowNano-a.lastOutputWriteDL >= iv {
			a.stream.SetWriteDeadline(now.Add(idle))
			a.lastOutputWriteDL = nowNano
		}
		return a.req.UDPWriteBatch(sources, payloads)
	}
	if a.native != nil {
		if client.Port() == 0 {
			return nil
		}
		var (
			pkts  [udpMmsgBatchSize][]byte
			addrs [udpMmsgBatchSize]netip.AddrPort
			sb    udpSendBatch
			n     int
		)
		for i := range payloads {
			out := appendAddress([]byte{0, 0, 0}, sources[i], false)
			out = append(out, payloads[i]...)
			if len(out) > maxDatagram {
				a.server.counters.Dropped.Add(1)
				a.server.failure(failUDPInvalid, "udp", -1)
				continue
			}
			pkts[n] = out
			addrs[n] = client
			n++
		}
		if n == 0 {
			return nil
		}
		dialTimeout := a.server.cfg.Limits.DialTimeout.value()
		now := time.Now()
		nowNano := now.UnixNano()
		if iv := deadlineRefreshInterval(dialTimeout); iv == 0 || nowNano-a.lastOutputWriteDL >= iv {
			a.native.SetWriteDeadline(now.Add(dialTimeout))
			a.lastOutputWriteDL = nowNano
		}
		_, e := writeUDPBatch(a.native, a.rawNative, a.v6Native, &sb, pkts[:n], addrs[:n])
		return e
	}
	for i := range payloads {
		out := a.req.Datagrams.AppendPacket(nil, sources[i], payloads[i])
		now := time.Now()
		nowNano := now.UnixNano()
		if iv := deadlineRefreshInterval(idle); iv == 0 || nowNano-a.lastOutputWriteDL >= iv {
			a.stream.SetWriteDeadline(now.Add(idle))
			a.lastOutputWriteDL = nowNano
		}
		if e := writeAll(a.stream, out); e != nil {
			return e
		}
	}
	return nil
}

// output writes one reply datagram back to the client through whichever
// inbound path owns this association (SS native writeBack, UDPWrite stream,
// SOCKS5 native socket or a datagram codec). Shared by direct and proxy replies.
func (a *udpAssociation) output(client netip.AddrPort, source Address, payload []byte, idle time.Duration) error {
	var e error
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	if a.writeBack != nil {
		e = a.writeBack(source, payload)
	} else if a.req.UDPWrite != nil {
		now := time.Now()
		nowNano := now.UnixNano()
		if iv := deadlineRefreshInterval(idle); iv == 0 || nowNano-a.lastOutputWriteDL >= iv {
			a.stream.SetWriteDeadline(now.Add(idle))
			a.lastOutputWriteDL = nowNano
		}
		e = a.req.UDPWrite(source, payload)
	} else if a.native != nil {
		if client.Port() == 0 {
			return nil
		}
		out := appendAddress([]byte{0, 0, 0}, source, false)
		out = append(out, payload...)
		if len(out) > maxDatagram {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			return nil
		}
		dialTimeout := a.server.cfg.Limits.DialTimeout.value()
		now := time.Now()
		nowNano := now.UnixNano()
		if iv := deadlineRefreshInterval(dialTimeout); iv == 0 || nowNano-a.lastOutputWriteDL >= iv {
			a.native.SetWriteDeadline(now.Add(dialTimeout))
			a.lastOutputWriteDL = nowNano
		}
		_, e = a.native.WriteToUDPAddrPort(out, client)
	} else {
		out := a.req.Datagrams.AppendPacket(nil, source, payload)
		now := time.Now()
		nowNano := now.UnixNano()
		if iv := deadlineRefreshInterval(idle); iv == 0 || nowNano-a.lastOutputWriteDL >= iv {
			a.stream.SetWriteDeadline(now.Add(idle))
			a.lastOutputWriteDL = nowNano
		}
		e = writeAll(a.stream, out)
	}
	return e
}

// Datagram-over-stream parsing always uses ReadFull, never TCP Read boundaries.

// ssIdleExpired uses the same last-valid-activity timestamp as target readers.
// It is SS-only: other protocols retain their existing idle/default behavior.
func (a *udpAssociation) ssIdleExpired(now time.Time) bool {
	return now.Sub(time.Unix(0, a.activity.Load())) >= a.server.cfg.Limits.UDPIdle.value()
}

// An exact target must already be authorized and not idle-expired BEFORE a reply
// can renew it. Unknown/expired sources and oversized datagrams never keep it alive.
// Refreshing only native SS preserves other protocol target-expiry semantics.
func (a *udpAssociation) acceptReturn(src netip.AddrPort, n int, now time.Time, idle time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	last, ok := a.allowed[src]
	expired := now.Sub(last) > idle
	if a.ssNative {
		expired = now.Sub(last) >= idle
	}
	if !ok || expired || n > maxDatagram {
		return false
	}
	if a.ssNative {
		if now.After(last) {
			a.allowed[src] = now
		}
		a.touchSSActivity(now)
	} else {
		a.activity.Store(now.UnixNano())
	}
	return true
}

func (a *udpAssociation) acceptReturnWithMeta(src netip.AddrPort, n int, now time.Time, idle time.Duration) (netip.AddrPort, *udpRoute, bool) {
	a.mu.Lock()
	client := a.client
	last, ok := a.allowed[src]
	expired := now.Sub(last) > idle
	if a.ssNative {
		expired = now.Sub(last) >= idle
	}
	if !ok || expired || n > maxDatagram {
		a.mu.Unlock()
		return netip.AddrPort{}, nil, false
	}
	if a.ssNative {
		if now.After(last) {
			a.allowed[src] = now
		}
		a.touchSSActivity(now)
	} else {
		a.activity.Store(now.UnixNano())
	}
	var rt *udpRoute
	if a.flow != nil {
		rt = a.routes[src]
	}
	a.mu.Unlock()
	return client, rt, true
}

// Concurrent SS readers/replies must not move the idle deadline backwards.
func (a *udpAssociation) touchSSActivity(now time.Time) {
	n := now.UnixNano()
	for old := a.activity.Load(); n > old; old = a.activity.Load() {
		if a.activity.CompareAndSwap(old, n) {
			return
		}
	}
}
