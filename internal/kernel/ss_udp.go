package kernel

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/ss"
	"github.com/shui1iao/Kat/internal/udpmmsg"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type ssAssociationID struct {
	source  netip.AddrPort
	session uint64
}
type ssRuntime struct {
	codec     *ss.Server
	identity  string
	limits    ss.ProtectionLimits // immutable policy staged by this generation
	v2022     bool
	*ssRoutes // shared across generations for the same identity
}
type ssRoutes struct {
	mu           sync.RWMutex
	associations map[ssAssociationID]*ssNativeAssociation
}

// ssUDPListener is one SS UDP socket, kept across reloads while its address
// is configured for a Shadowsocks inbound. bind names the generation, inbound
// and codec that create new associations; a removed socket is "draining":
// it only serves associations created on it and closes after the last one.
type ssUDPListener struct {
	key      string
	socket   *net.UDPConn
	raw      syscall.RawConn
	v6Socket bool
	bind     atomic.Pointer[udpBinding]
	draining atomic.Bool
	assocs   atomic.Int64 // live associations created on this socket
	// Explicit udp_rcvbuf_2017 only: read-back sizes and the bytes still charged
	// to the process extra socket budget (released exactly once, after close).
	rcvbufBefore, rcvbufActual int
	rcvbufInitial              int64
	rcvbufCharge               atomic.Int64
	lastWriteDL                atomic.Int64
	gsoDisabled                atomic.Bool
}

// releaseRcvBuf returns this listener's charge once; concurrent/duplicate calls are no-ops.
func (l *ssUDPListener) releaseRcvBuf() { returnSSRcvBuf(l.rcvbufCharge.Swap(0)) }

type ssReplyState struct {
	capability *ss.Packet
	listener   *ssUDPListener
}

type ssNativeAssociation struct {
	a          *udpAssociation
	runtime    *ssRuntime
	id         ssAssociationID
	capability *ss.Packet
	listener   *ssUDPListener
	replyState atomic.Pointer[ssReplyState]
	origin     *ssUDPListener // socket the association was created on
}

func (s *Server) listenSSUDP(in Inbound, bound net.Addr) (*ssUDPListener, error) {
	a := bound.(*net.TCPAddr)
	// TCP wildcard selection may be dual-stack [::] for an IPv4 config.
	// Preserve the configured UDP family, but use TCP's actual port (also :0).
	host, _, e := net.SplitHostPort(in.Listen)
	if e != nil {
		return nil, e
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("invalid SS UDP listen IP")
	}
	network := "udp6"
	if ip.To4() != nil {
		network = "udp4"
	}
	u, e := net.ListenUDP(network, &net.UDPAddr{IP: ip, Port: a.Port, Zone: a.Zone})
	if e != nil {
		return nil, e
	}
	raw, _ := u.SyscallConn()
	udpmmsg.EnableGRO(raw)
	l := &ssUDPListener{socket: u, raw: raw, v6Socket: udpmmsg.IsIPv6Socket(u)}
	l.bind.Store(&udpBinding{g: s, idx: in.logIndex, runtime: in.ssRuntime})
	if in.SS != nil && in.SS.UDPRcvBuf2017 != 0 {
		if in.ssRuntime.v2022 {
			u.Close()
			return nil, &ssRcvBufError{"only SS2017 UDP listeners are supported"}
		}
		before, actual, charge, e := setSS2017RcvBuf(u, in.SS.UDPRcvBuf2017)
		if e != nil {
			u.Close()
			return nil, e
		}
		l.rcvbufBefore, l.rcvbufActual, l.rcvbufInitial = before, actual, charge
		l.rcvbufCharge.Store(charge)
	}
	return l, nil
}

// The0.5.12 TCP path now needs32775B, not65528B, per owned wire.
// Fund at most7 extra65535B UDP receive buffers from that released process
// wire budget:16*32775+7*65535=983145 <= old16*65528=1048448.
// Exactly one extra fixed reader per SS listener (SS2017, and since 0.5.20 SS2022)
// enables authenticated crypto to run on a second CPU while the other reader polls.
// Both share this single process pool: no new buffers, packet goroutines, larger
// socket buffer, larger association queue, or per-connection cache.
const ss2017ExtraReadBuffers = 7

var ss2017ReadSlots = make(chan struct{}, ss2017ExtraReadBuffers)

func (k *core) loopSSUDP(l *ssUDPListener) {
	defer k.accepts.Done()
	if runtime.GOMAXPROCS(0) > 1 {
		select {
		case ss2017ReadSlots <- struct{}{}:
			k.accepts.Add(1)
			go func() { defer k.accepts.Done(); defer func() { <-ss2017ReadSlots }(); k.readSSUDP(l) }()
		default:
		}
	}
	k.readSSUDP(l)
}
func (k *core) readSSUDP(l *ssUDPListener) {
	rb := udpmmsg.AcquireRecvBatch()
	defer udpmmsg.ReleaseRecvBatch(rb)
	var (
		fastAssoc  *ssNativeAssociation
		fastTgts   [udpmmsg.BatchSize]Address
		fastPays   [udpmmsg.BatchSize][]byte
		fastPooled [udpmmsg.BatchSize][]byte
		fastNow    time.Time
		fastN      int
	)
	flushFast := func() {
		if fastN == 0 {
			return
		}
		if fastAssoc.a.tryDirectForwardBatch(fastTgts[:fastN], fastPays[:fastN], fastNow) {
			for i := 0; i < fastN; i++ {
				putUDPPlainBuf(fastPooled[i])
				fastPooled[i] = nil
				fastPays[i] = nil
			}
		} else {
			for i := 0; i < fastN; i++ {
				fastAssoc.a.enqueue(packet{target: fastTgts[i], payload: fastPays[i], pooled: fastPooled[i]})
				fastPooled[i] = nil
				fastPays[i] = nil
			}
		}
		fastAssoc = nil
		fastN = 0
	}
	for {
		cnt, e := udpmmsg.ReadBatch(l.socket, l.raw, rb)
		b := l.bind.Load()
		s := b.g
		logIndex := b.idx
		if e != nil {
			if !quietFailure(e) && !l.draining.Load() {
				s.failure(failUDPIO, "shadowsocks", logIndex)
			}
			return
		}
		for idx := 0; idx < cnt; idx++ {
			wire := rb.Bufs[idx]
			n := rb.Lens[idx]
			source := rb.Addrs[idx]
			if !source.IsValid() {
				continue
			}
			if n > maxDatagram || !s.handSlots.try() {
				s.counters.Dropped.Add(1)
				if n > maxDatagram {
					s.failure(failUDPInvalid, "shadowsocks", logIndex)
				} else {
					s.failure(failUDPBudget, "shadowsocks", logIndex)
				}
				continue
			}
			rt := b.runtime
			var decBuf []byte
			if n <= udpSmallBufCap {
				decBuf = getUDPPlainBuf()
			}
			var p *ss.Packet
			if rt.v2022 {
				var refused bool
				p, e, refused = k.decodeSS2022OnBinding(l, b, decBuf, wire[:n], source)
				if refused {
					putUDPPlainBuf(decBuf)
					s.handSlots.release()
					s.counters.Dropped.Add(1)
					continue
				}
			} else {
				p, e = rt.codec.DecodeUDPTo(decBuf, wire[:n], source)
			}
			s.handSlots.release()
			if e != nil {
				putUDPPlainBuf(decBuf)
				s.counters.Dropped.Add(1)
				s.failure(failUDPInvalid, "shadowsocks", logIndex)
				continue
			}
			payload := p.Payload
			// Detach payload slice from capability so capability never aliases pooled memory.
			p.Payload = nil
			var pooled []byte
			if decBuf != nil && cap(payload) <= cap(decBuf) {
				pooled = decBuf
			} else if decBuf != nil {
				putUDPPlainBuf(decBuf)
			}
			id := ssAssociationID{source: source}
			if rt.v2022 {
				id = ssAssociationID{session: p.ClientSessionID}
			}
			now := p.AuthenticatedAt()
			// Steady-state fast path under RLock: avoids exclusive lock contention
			// between parallel SS UDP readers and outbound replies.
			rt.mu.RLock()
			if s.nativeContext.Err() == nil {
				if assoc := rt.associations[id]; assoc != nil && assoc.a.ctx.Err() == nil && !assoc.a.ssIdleExpired(now) {
					if st := assoc.replyState.Load(); st == nil || st.listener != l {
						assoc.replyState.Store(&ssReplyState{capability: p, listener: l})
					}
					assoc.a.touchSSActivity(now)
					rt.mu.RUnlock()
					if fastAssoc != nil && fastAssoc != assoc {
						flushFast()
					}
					fastAssoc = assoc
					fastNow = now
					fastTgts[fastN] = Address{p.Target.Host, p.Target.Port}
					fastPays[fastN] = payload
					fastPooled[fastN] = pooled
					fastN++
					continue
				}
			}
			rt.mu.RUnlock()
			flushFast()

			rt.mu.Lock()
			if s.nativeContext.Err() != nil {
				rt.mu.Unlock()
				putUDPPlainBuf(pooled)
				s.counters.Dropped.Add(1)
				continue
			}
			assoc := rt.associations[id]
			if assoc != nil && (assoc.a.ctx.Err() != nil || assoc.a.ssIdleExpired(now)) {
				assoc.a.cancel()
				delete(rt.associations, id)
				assoc = nil
			}
			if assoc == nil {
				// A new association belongs to the generation bound right now; a
				// removed (draining) socket accepts no new association.
				if !rt.v2022 && s.udpSourceRefused(source.Addr(), logIndex) {
					rt.mu.Unlock()
					putUDPPlainBuf(pooled)
					s.counters.Dropped.Add(1)
					continue
				}
				k.bindMu.RLock()
				ok := !l.draining.Load() && l.bind.Load() == b
				if ok {
					s.refs.Add(1)
				}
				k.bindMu.RUnlock()
				if !ok {
					rt.mu.Unlock()
					putUDPPlainBuf(pooled)
					s.counters.Dropped.Add(1)
					continue
				}
				if !s.udpSlots.try() {
					rt.mu.Unlock()
					putUDPPlainBuf(pooled)
					s.counters.Dropped.Add(1)
					s.failure(failUDPBudget, "shadowsocks", logIndex)
					s.unref()
					continue
				}
				base := withInbound(withSourceIP(s.nativeContext, source.Addr()), logIndex)
				base = withInboundMeta(base, &s.cfg.Inbounds[logIndex], l.socket.LocalAddr(), net.UDPAddrFromAddrPort(source))
				f, fctx := s.newFlow(base, "udp", Address{})
				ctx, cancel := context.WithCancel(fctx)
				a := &udpAssociation{server: s, ctx: ctx, cancel: cancel, ssNative: true, queue: make(chan packet, s.cfg.Limits.UDPQueue), allowed: map[netip.AddrPort]time.Time{}, source: source.Addr(), flow: f}
				if e = a.openOutbound(); e != nil {
					cancel()
					f.end("udp_socket_failed")
					s.udpSlots.release()
					rt.mu.Unlock()
					putUDPPlainBuf(pooled)
					s.counters.Dropped.Add(1)
					s.failure(failUDPIO, "shadowsocks", logIndex)
					s.unref()
					continue
				}
				a.activity.Store(now.UnixNano())
				assoc = &ssNativeAssociation{a: a, runtime: rt, id: id, origin: l}
				l.assocs.Add(1)
				a.writeBack = assoc.reply
				a.writeBackBatch = assoc.replyBatch
				rt.associations[id] = assoc
				s.counters.UDP.Add(1)
				s.wg.Add(1)
				go s.runSSAssociation(assoc)
			}
			assoc.capability = p
			assoc.listener = l
			assoc.replyState.Store(&ssReplyState{capability: p, listener: l})
			// Only a fully authenticated, fresh, formatted request reaches here.
			assoc.a.touchSSActivity(now)
			assoc.a.enqueue(packet{target: Address{p.Target.Host, p.Target.Port}, payload: payload, pooled: pooled})
			rt.mu.Unlock()
		}
		flushFast()
	}
}

// A live binding authorizes peer migration under its current ACL. Holding
// bindMu through authentication/commit linearizes that decision with reload.
// The steady state does not take the association lock during authentication.
func (k *core) decodeSS2022OnBinding(l *ssUDPListener, b *udpBinding, dst, wire []byte, source netip.AddrPort) (*ss.Packet, error, bool) {
	draining := l.draining.Load()
	rt := b.runtime
	if draining {
		// Removed listeners have no current ACL grant for a migration. Only
		// their existing association/peer may drain. Lock order is the same
		// as new-association admission: routes -> binding -> codec.
		rt.mu.Lock()
		defer rt.mu.Unlock()
	}
	k.bindMu.RLock()
	defer k.bindMu.RUnlock()
	if l.bind.Load() != b || draining != l.draining.Load() || b.g.udpSourceRefused(source.Addr(), b.idx) {
		return nil, nil, true
	}
	if draining {
		p, err := rt.codec.DecodeEstablishedUDPTo(dst, wire, source, func(id uint64) *ss.Packet {
			n := rt.associations[ssAssociationID{session: id}]
			if n == nil || n.a.ctx.Err() != nil || n.a.ssIdleExpired(time.Now()) {
				return nil
			}
			st := n.replyState.Load()
			if st == nil || st.listener != l {
				return nil
			}
			return st.capability
		})
		return p, err, false
	}
	p, err := rt.codec.DecodeUDPTo(dst, wire, source)
	return p, err, false
}

func (a *udpAssociation) openOutbound() error {
	var e error
	s := a.server
	a.outbound4, e = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(s.cfg.UDPBindIPv4)})
	if e != nil {
		return e
	}
	a.outbound6, e = net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP(s.cfg.UDPBindIPv6)})
	if e != nil && s.cfg.UDPBindIPv6 != "" {
		a.outbound4.Close()
		return e
	}
	a.raw4, _ = a.outbound4.SyscallConn()
	udpmmsg.EnableGRO(a.raw4)
	if a.outbound6 != nil {
		a.raw6, _ = a.outbound6.SyscallConn()
		udpmmsg.EnableGRO(a.raw6)
	}
	a.activity.Store(time.Now().UnixNano())
	return nil
}
func (a *udpAssociation) closeOutbound() {
	a.outbound4.Close()
	if a.outbound6 != nil {
		a.outbound6.Close()
	}
}
func (s *Server) runSSAssociation(n *ssNativeAssociation) {
	a := n.a
	defer func() {
		a.cancel()
		a.closeOutbound()
		a.flow.end("ok")
		n.runtime.mu.Lock()
		if n.runtime.associations[n.id] == n {
			delete(n.runtime.associations, n.id)
		}
		n.runtime.mu.Unlock()
		for {
			select {
			case p := <-a.queue:
				a.queuedBytes.Add(-int64(len(p.payload)))
				releasePacket(p)
			default:
				s.counters.UDP.Add(-1)
				s.udpSlots.release()
				// The association no longer uses its socket (a removed
				// inbound's socket closes with its last association) nor
				// its generation.
				if n.origin != nil {
					n.origin.assocs.Add(-1)
					if s.core != nil {
						s.closeIfDrained(n.origin)
					}
				}
				s.unref()
				s.wg.Done()
				return
			}
		}
	}()
	a.wg.Add(2)
	go func() { defer a.wg.Done(); <-a.ctx.Done(); a.closeOutbound() }()
	go func() { defer a.wg.Done(); defer a.cancel(); a.sendLoop() }()
	for _, socket := range []*net.UDPConn{a.outbound4, a.outbound6} {
		if socket != nil {
			a.wg.Add(1)
			go func() { defer a.wg.Done(); defer a.cancel(); a.returnLoop(socket) }()
		}
	}
	// The association and codec use configured bidirectional inactivity, not
	// the timestamp/replay retention interval. Return readers also enforce idle.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			a.wg.Wait()
			return
		case <-ticker.C:
			expired := a.ssIdleExpired(time.Now())
			if expired {
				a.cancel()
			}
		}
	}
}
func (n *ssNativeAssociation) reply(from Address, payload []byte) error {
	if n.a.ctx.Err() != nil {
		return context.Canceled
	}
	var capability *ss.Packet
	var l *ssUDPListener
	if st := n.replyState.Load(); st != nil {
		capability, l = st.capability, st.listener
	} else {
		n.runtime.mu.RLock()
		capability, l = n.capability, n.listener
		n.runtime.mu.RUnlock()
	}
	if l == nil {
		return errors.New("missing authenticated SS listener")
	}
	var encBuf []byte
	if len(payload)+320 <= udpSmallBufCap {
		encBuf = getUDPPlainBuf()
		defer putUDPPlainBuf(encBuf)
	}
	wire, peer, e := n.runtime.codec.EncodeUDPTo(encBuf, capability, ss.Address{Host: from.Host, Port: from.Port}, payload)
	if e != nil {
		return e
	}
	if len(wire) > maxDatagram {
		n.a.server.counters.Dropped.Add(1)
		return nil
	}
	dialTimeout := n.a.server.cfg.Limits.DialTimeout.value()
	now := time.Now()
	nowNano := now.UnixNano()
	if iv := deadlineRefreshInterval(dialTimeout); iv == 0 {
		l.socket.SetWriteDeadline(now.Add(dialTimeout))
	} else {
		last := l.lastWriteDL.Load()
		if nowNano-last >= iv && l.lastWriteDL.CompareAndSwap(last, nowNano) {
			l.socket.SetWriteDeadline(now.Add(dialTimeout))
		}
	}
	_, e = l.socket.WriteToUDPAddrPort(wire, peer)
	return e
}

func (n *ssNativeAssociation) replyBatch(froms []Address, payloads [][]byte) error {
	if len(payloads) == 0 {
		return nil
	}
	if len(payloads) == 1 {
		return n.reply(froms[0], payloads[0])
	}
	if n.a.ctx.Err() != nil {
		return context.Canceled
	}
	var capability *ss.Packet
	var l *ssUDPListener
	if st := n.replyState.Load(); st != nil {
		capability, l = st.capability, st.listener
	} else {
		n.runtime.mu.RLock()
		capability, l = n.capability, n.listener
		n.runtime.mu.RUnlock()
	}
	if l == nil {
		return errors.New("missing authenticated SS listener")
	}
	var (
		encBufs  [udpmmsg.BatchSize][]byte
		wires    [udpmmsg.BatchSize][]byte
		peers    [udpmmsg.BatchSize]netip.AddrPort
		sb       udpmmsg.SendBatch
		numWires int
	)
	if l.gsoDisabled.Load() {
		sb.DisableGSO()
	}
	defer func() {
		for i := 0; i < len(payloads) && i < udpmmsg.BatchSize; i++ {
			if encBufs[i] != nil {
				putUDPPlainBuf(encBufs[i])
			}
		}
	}()
	for i := 0; i < len(payloads); i++ {
		payload := payloads[i]
		var encBuf []byte
		if len(payload)+320 <= udpSmallBufCap && i < udpmmsg.BatchSize {
			encBuf = getUDPPlainBuf()
			encBufs[i] = encBuf
		}
		wire, peer, e := n.runtime.codec.EncodeUDPTo(encBuf, capability, ss.Address{Host: froms[i].Host, Port: froms[i].Port}, payload)
		if e != nil {
			return e
		}
		if len(wire) > maxDatagram {
			n.a.server.counters.Dropped.Add(1)
			continue
		}
		wires[numWires] = wire
		peers[numWires] = peer
		numWires++
	}
	if numWires == 0 {
		return nil
	}
	dialTimeout := n.a.server.cfg.Limits.DialTimeout.value()
	now := time.Now()
	nowNano := now.UnixNano()
	if iv := deadlineRefreshInterval(dialTimeout); iv == 0 {
		l.socket.SetWriteDeadline(now.Add(dialTimeout))
	} else {
		last := l.lastWriteDL.Load()
		if nowNano-last >= iv && l.lastWriteDL.CompareAndSwap(last, nowNano) {
			l.socket.SetWriteDeadline(now.Add(dialTimeout))
		}
	}
	_, e := udpmmsg.WriteBatch(l.socket, l.raw, l.v6Socket, &sb, wires[:numWires], peers[:numWires])
	if sb.GSODisabled() {
		l.gsoDisabled.Store(true)
	}
	return e
}

// tryDirectForwardBatch sends a batch of already-decoded steady-state SS UDP
// payloads directly via sendmmsg when the target IP is already authorized and
// the association queue is empty, eliminating the a.queue channel hop.
func (a *udpAssociation) tryDirectForwardBatch(targets []Address, payloads [][]byte, now time.Time) bool {
	if len(payloads) == 0 || len(a.queue) > 0 || a.ctx.Err() != nil {
		return false
	}
	var (
		ips [udpmmsg.BatchSize]netip.AddrPort
		rts [udpmmsg.BatchSize]*udpRoute
		is6 bool
	)
	idle := a.server.cfg.Limits.UDPIdle.value()
	for i, tgt := range targets {
		if tgt.Port == 0 {
			return false
		}
		ip, err := netip.ParseAddr(tgt.Host)
		if err != nil {
			return false
		}
		ip = ip.Unmap()
		if i == 0 {
			is6 = ip.Is6()
		} else if ip.Is6() != is6 {
			return false
		}
		ips[i] = netip.AddrPortFrom(ip, tgt.Port)
	}
	sock := a.outbound4
	raw := a.raw4
	if is6 {
		sock = a.outbound6
		raw = a.raw6
	}
	if sock == nil {
		return false
	}
	a.mu.Lock()
	for i := 0; i < len(payloads); i++ {
		last, ok := a.allowed[ips[i]]
		if !ok || now.Sub(last) > idle {
			a.mu.Unlock()
			return false
		}
		a.allowed[ips[i]] = now
		rts[i] = a.routes[ips[i]]
	}
	a.mu.Unlock()

	dialTimeout := a.server.cfg.Limits.DialTimeout.value()
	nowNano := now.UnixNano()
	iv := deadlineRefreshInterval(dialTimeout)
	a.outputMu.Lock()
	dlPtr := &a.lastOutWriteDL4
	sbPtr := &a.sb4
	if is6 {
		dlPtr = &a.lastOutWriteDL6
		sbPtr = &a.sb6
	}
	if iv == 0 || nowNano-*dlPtr >= iv {
		sock.SetWriteDeadline(now.Add(dialTimeout))
		*dlPtr = nowNano
	}
	sent, e := udpmmsg.WriteBatch(sock, raw, is6, sbPtr, payloads, ips[:len(payloads)])
	a.outputMu.Unlock()
	for i := 0; i < sent; i++ {
		if a.flow != nil {
			a.flow.udpUp(rts[i], len(payloads[i]))
		}
	}
	if e != nil {
		a.server.counters.Dropped.Add(int64(len(payloads) - sent))
		a.server.failure(failUDPIO, "udp", -1)
	}
	return true
}
