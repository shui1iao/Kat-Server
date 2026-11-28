package kernel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// ---- Trojan request parsing and fallback (0.7.0) ----
//
// The request is read incrementally: the first byte that cannot belong to a
// Trojan request (56 hex digits, CRLF, command, address, CRLF) ends the
// parse at once instead of waiting for 56 bytes. With "fallback" set on the
// inbound, every byte read so far and the rest of the connection are then
// relayed unchanged to the fallback address (typically a local web site);
// without it the connection is closed as before. Kat itself dials the
// fallback address, so a loopback address is allowed there.

// trojanReject is a request that is not a valid Trojan request. head holds
// every byte read from the client; auth is true when the request had the
// form of a Trojan password hash that matched no user.
type trojanReject struct {
	auth bool
	head []byte
	err  error
}

func (e *trojanReject) Error() string { return "trojan: " + e.err.Error() }
func (e *trojanReject) Unwrap() error { return e.err }

var errTrojanFormat = errors.New("not a Trojan request")

func trojanPasswordDigest(password string) [56]byte {
	sum := sha256.Sum224([]byte(password))
	var encoded [56]byte
	hex.Encode(encoded[:], sum[:])
	return encoded
}

func precomputeTrojanDigests(users []User) [][56]byte {
	if len(users) == 0 {
		return nil
	}
	out := make([][56]byte, len(users))
	for i, u := range users {
		out[i] = trojanPasswordDigest(u.Password)
	}
	return out
}

func isLocalInterfaceIP(target netip.Addr) bool {
	if !target.IsValid() {
		return false
	}
	target = target.WithZone("").Unmap()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if parsed, ok := netip.AddrFromSlice(ip); ok && parsed.WithZone("").Unmap() == target {
			return true
		}
	}
	return false
}

// fallbackConflictsWithListen reports whether dialing fb could connect back to
// a TCP listener bound to (listenIP, listenPort) on this host.
func fallbackConflictsWithListen(fb netip.AddrPort, listenIP netip.Addr, listenPort uint16) bool {
	if fb.Port() == 0 || listenPort == 0 || fb.Port() != listenPort {
		return false
	}
	fbIP := fb.Addr().WithZone("").Unmap()
	lIP := listenIP.WithZone("").Unmap()
	if !fbIP.IsValid() || !lIP.IsValid() {
		return false
	}
	if fbIP == lIP {
		return true
	}
	if lIP.IsUnspecified() && (fbIP.IsLoopback() || fbIP.IsUnspecified() || isLocalInterfaceIP(fbIP)) {
		return true
	}
	if fbIP.IsUnspecified() && (lIP.IsLoopback() || lIP.IsUnspecified() || isLocalInterfaceIP(lIP)) {
		return true
	}
	return false
}

func parseStaticListenAddr(listen string) (netip.Addr, uint16, bool) {
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return netip.Addr{}, 0, false
	}
	return ip.WithZone("").Unmap(), uint16(port), true
}

func (in *Inbound) validateFallback(c *Config, i int) error {
	if in.Fallback == "" {
		return nil
	}
	if in.Protocol != "trojan" {
		return fmt.Errorf("inbound %d: fallback is only valid for Trojan inbounds", i)
	}
	ap, e := netip.ParseAddrPort(in.Fallback)
	if e != nil || ap.Port() == 0 || ap.Addr().Zone() != "" || ap.Addr().Unmap().IsUnspecified() {
		return fmt.Errorf("inbound %d: fallback must be a literal non-wildcard IP and non-zero port, e.g. 127.0.0.1:8080", i)
	}
	if c != nil {
		for j := range c.Inbounds {
			lIP, lPort, ok := parseStaticListenAddr(c.Inbounds[j].Listen)
			if ok && fallbackConflictsWithListen(ap, lIP, lPort) {
				return fmt.Errorf("inbound %d: fallback %s conflicts with inbound %d listener %s (self-loop)", i, in.Fallback, j, c.Inbounds[j].Listen)
			}
		}
		if c.API != nil && c.API.Listen != "" {
			if lIP, lPort, ok := parseStaticListenAddr(c.API.Listen); ok && fallbackConflictsWithListen(ap, lIP, lPort) {
				return fmt.Errorf("inbound %d: fallback %s conflicts with management API listener %s", i, in.Fallback, c.API.Listen)
			}
		}
	}
	return nil
}

func validateBoundFallbacks(inbounds []Inbound, boundAddrs []net.Addr, apiListen string) error {
	for i := range inbounds {
		fbStr := inbounds[i].Fallback
		if fbStr == "" {
			continue
		}
		fb, err := netip.ParseAddrPort(fbStr)
		if err != nil {
			continue
		}
		for j, ba := range boundAddrs {
			if ba == nil {
				continue
			}
			ta, ok := ba.(*net.TCPAddr)
			if !ok || ta.Port <= 0 {
				continue
			}
			port := uint16(ta.Port)
			if bIP, ok := netip.AddrFromSlice(ta.IP); ok {
				if fallbackConflictsWithListen(fb, bIP, port) {
					return fmt.Errorf("inbound %d: fallback %s conflicts with bound inbound %d listener %s (self-loop)", i, fbStr, j, ba.String())
				}
			}
			if j < len(inbounds) {
				if host, _, err := net.SplitHostPort(inbounds[j].Listen); err == nil {
					if cfgIP, err := netip.ParseAddr(host); err == nil && fallbackConflictsWithListen(fb, cfgIP, port) {
						return fmt.Errorf("inbound %d: fallback %s conflicts with bound inbound %d listener %s (self-loop)", i, fbStr, j, ba.String())
					}
				}
			}
		}
		if apiListen != "" {
			if lIP, lPort, ok := parseStaticListenAddr(apiListen); ok && fallbackConflictsWithListen(fb, lIP, lPort) {
				return fmt.Errorf("inbound %d: fallback %s conflicts with management API listener %s", i, fbStr, apiListen)
			}
		}
	}
	return nil
}

func isHexDigit(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

func parseTrojan(c net.Conn, in Inbound) (request, error) {
	r := request{Mode: "trojan", UserIndex: -1}
	poolBuf := getUDPPlainBuf()
	defer putUDPPlainBuf(poolBuf)
	scratch := poolBuf[:260]
	head := scratch[:56]
	n := 0
	for n < len(head) {
		m, e := c.Read(head[n:])
		for i := n; i < n+m; i++ {
			if !isHexDigit(head[i]) {
				return r, &trojanReject{head: append([]byte(nil), head[:n+m]...), err: errTrojanFormat}
			}
		}
		n += m
		if n < len(head) && e != nil {
			return r, e
		}
	}
	match := 0
	if len(in.trojanDigests) == len(in.Users) {
		for i := range in.trojanDigests {
			m := subtle.ConstantTimeCompare(head[:56], in.trojanDigests[i][:])
			match |= m
			if m == 1 {
				r.UserIndex = i
			}
		}
	} else {
		for i, u := range in.Users {
			encoded := trojanPasswordDigest(u.Password)
			m := subtle.ConstantTimeCompare(head[:56], encoded[:])
			match |= m
			if m == 1 {
				r.UserIndex = i
			}
		}
	}
	// Once the digest matches, no bytes from this request may reach the fallback,
	// including when the separator itself is invalid. Only unmatched traffic
	// carries a replayable prefix to the configured web backend.
	if match == 0 {
		prefix := make([]byte, 56, 58)
		copy(prefix, head[:56])
		one := scratch[56:57]
		for _, want := range [2]byte{'\r', '\n'} {
			if e := readExact(c, one); e != nil {
				return r, e
			}
			prefix = append(prefix, one[0])
			if one[0] != want {
				return r, &trojanReject{head: prefix, err: errTrojanFormat}
			}
		}
		return r, &trojanReject{auth: true, head: prefix, err: errors.New("authentication failed")}
	}
	if e := expectCRLFBuf(c, scratch[:2]); e != nil {
		return r, e
	}
	if e := readExact(c, scratch[:1]); e != nil {
		return r, e
	}
	r.Command = scratch[0]
	if r.Command != 1 && r.Command != 3 {
		return r, errors.New("unsupported Trojan command")
	}
	var e error
	r.Target, e = readAddressBuf(c, scratch[:])
	if e != nil {
		return r, e
	}
	if e = expectCRLFBuf(c, scratch[:2]); e != nil {
		return r, e
	}
	if r.Command == 3 {
		r.Datagrams = &trojanDatagrams{}
	}
	return r, nil
}

func fallbackSlotLimit(connections int) int {
	return max(64, connections/4)
}

// trojanFallback relays a rejected connection to the inbound's fallback
// address, starting with the bytes already read. An unreachable fallback
// closes the TLS connection cleanly (close_notify, then FIN).
func (s *Server) trojanFallback(c net.Conn, head []byte, in *Inbound) {
	if s.fallbackSlots != nil && !s.fallbackSlots.try() {
		s.failure(failConnections, in.Protocol, in.logIndex)
		c.Close()
		return
	}
	if s.fallbackSlots != nil {
		defer s.fallbackSlots.release()
	}
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.Limits.DialTimeout.value())
	defer cancel()
	if e := s.dialSlots.acquire(ctx); e != nil {
		s.failure(failDialBudget, in.Protocol, in.logIndex)
		c.Close()
		return
	}
	s.counters.Dials.Add(1)
	out, e := (&net.Dialer{}).DialContext(ctx, "tcp", in.Fallback)
	s.dialSlots.release()
	s.counters.Dials.Add(-1)
	if e != nil {
		s.failure(failFallback, in.Protocol, in.logIndex)
		c.Close() // TLS close_notify, then FIN
		return
	}
	defer out.Close()
	s.fallbacks.Add(1)
	c.SetDeadline(time.Time{})
	if len(head) > 0 {
		_ = out.SetWriteDeadline(time.Now().Add(s.cfg.Limits.HandshakeTimeout.value()))
		if e := writeAll(out, head); e != nil {
			return
		}
		_ = out.SetWriteDeadline(time.Time{})
	}
	_ = s.relay(s.ctx, c, out)
}
