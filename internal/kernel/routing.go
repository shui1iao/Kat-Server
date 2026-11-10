package kernel

import (
	"context"
	"net"
	"net/netip"
	"strings"
)

// lookup resolves host using Kat's DNS configuration (system or configured upstreams).
func (s *Server) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" {
			return nil, errDNS
		}
		return []netip.Addr{ip.Unmap()}, nil
	}
	name, e := dnsName(host)
	if e != nil {
		return nil, errDNS
	}
	if s.dns == nil {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	}
	return s.dns.lookup(ctx, name)
}

// customDNS reports whether custom DNS upstreams are configured instead of system DNS.
func (s *Server) customDNS() bool {
	return s.dns != nil && len(s.dns.upstreams) > 0
}

// routeUDP resolves a datagram target. With system DNS it uses s.resolve (single
// address); with custom DNS upstreams it acquires a dial slot and resolves all
// candidate addresses via s.lookup.
func (s *Server) routeUDP(ctx context.Context, a Address) ([]netip.AddrPort, error) {
	if !s.customDNS() {
		ip, e := s.resolve(ctx, a)
		if e != nil {
			return nil, e
		}
		return []netip.AddrPort{ip}, nil
	}
	if a.Port == 0 {
		return nil, errDNS
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.DialTimeout.value())
	defer cancel()
	if e := s.dialSlots.acquire(ctx); e != nil {
		return nil, e
	}
	s.counters.Dials.Add(1)
	defer func() { s.dialSlots.release(); s.counters.Dials.Add(-1) }()
	ips, e := s.lookup(ctx, a.Host)
	if e != nil {
		return nil, e
	}
	out := make([]netip.AddrPort, 0, len(ips))
	for _, ip := range ips {
		out = append(out, netip.AddrPortFrom(ip, a.Port))
	}
	return out, nil
}

// ---- client source and inbound metadata ----

type sourceKey struct{}

func withSource(ctx context.Context, a net.Addr) context.Context {
	if sourceOf(ctx).IsValid() {
		return ctx
	}
	ip := addrIP(a)
	if !ip.IsValid() {
		return ctx
	}
	return withSourceIP(ctx, ip)
}

func withSourceIP(ctx context.Context, ip netip.Addr) context.Context {
	if !ip.IsValid() {
		return ctx
	}
	return context.WithValue(ctx, sourceKey{}, ip.WithZone("").Unmap())
}

func sourceOf(ctx context.Context) netip.Addr {
	if ctx == nil {
		return netip.Addr{}
	}
	ip, _ := ctx.Value(sourceKey{}).(netip.Addr)
	return ip
}

func addrIP(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.TCPAddr:
		if v == nil {
			return netip.Addr{}
		}
		return v.AddrPort().Addr().WithZone("").Unmap()
	case *net.UDPAddr:
		if v == nil {
			return netip.Addr{}
		}
		return v.AddrPort().Addr().WithZone("").Unmap()
	case nil:
		return netip.Addr{}
	}
	ap, e := netip.ParseAddrPort(a.String())
	if e != nil {
		return netip.Addr{}
	}
	return ap.Addr().WithZone("").Unmap()
}

type inboundMeta struct {
	name, typ string
}

type inMetaKey struct{}

func withInboundMeta(ctx context.Context, in *Inbound, _, _ net.Addr) context.Context {
	return context.WithValue(ctx, inMetaKey{}, &inboundMeta{name: in.Name, typ: in.Protocol})
}

func inboundMetaOf(ctx context.Context) *inboundMeta {
	m, _ := ctx.Value(inMetaKey{}).(*inboundMeta)
	return m
}

func (s *Server) currentInboundMeta(ctx context.Context, _ *Server) context.Context {
	return ctx
}

var _ = strings.TrimSuffix
