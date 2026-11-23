package kernel

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/ss"
)

type ssHandshakeBuffer struct{ *bytes.Buffer }

func (ssHandshakeBuffer) Close() error { return nil }

func TestSSProtectionTransactionalReload(t *testing.T) {
	in := ssIn()
	in.Listen = "127.0.0.1:0"
	base := socksCfg()
	base.DNS = &DNSOptions{Server: "system"}
	base.Limits.UDPIdle = Duration(time.Minute)
	base.Inbounds = []Inbound{in}
	next := base
	s := startReloadable(t, base, &next)
	rt := s.cfg.Inbounds[0].ssRuntime
	accept := func(codec *ss.Server, wire []byte) error {
		c, e := codec.Accept(ssHandshakeBuffer{bytes.NewBuffer(wire)})
		if e == nil {
			c.Close()
		}
		return e
	}
	target, client := localUDP(t), localUDP(t)
	dst := addrFromNet(target.LocalAddr())
	endpoint := net.UDPAddrFromAddrPort(s.Addresses()[0].(*net.TCPAddr).AddrPort())
	peer := client.LocalAddr().(*net.UDPAddr).AddrPort()
	first := udp2022(t, dst, 101, 1, []byte("original"))
	if _, e := client.WriteToUDP(first, endpoint); e != nil {
		t.Fatal(e)
	}
	_, out := recvUDP(t, target)
	tcpA := tcp2022(t, dst, 1)
	if e := accept(rt.codec, tcpA); e != nil {
		t.Fatal(e)
	}
	// Fail after prepareEncrypted: a real *test-owned* socket occupies the
	// extra inbound. Neither replay state nor the proposed smaller limits apply.
	hold, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer hold.Close()
	smaller := ssIn()
	smaller.Listen = in.Listen
	smaller.SS.TCPSalts = 1
	smaller.SS.Sessions = 1
	next = base
	next.Inbounds = []Inbound{smaller, {Protocol: "socks5", Listen: hold.Addr().String()}}
	next.Limits.UDPIdle = Duration(2 * time.Minute)
	r, e := s.Reload("test")
	if e == nil || r.Stage != "bind_tcp" {
		t.Fatal("expected late bind failure", r, e)
	}
	if e = accept(rt.codec, tcpA); !errors.Is(e, ss.ErrReplay) {
		t.Fatal("aborted prepare forgot salt", e)
	}
	tcpB := tcp2022(t, dst, 2)
	if e = accept(rt.codec, tcpB); e != nil {
		t.Fatal("aborted candidate changed TCP capacity", e)
	}
	oldCap, e := rt.codec.DecodeUDP(udp2022(t, dst, 102, 1, nil), peer)
	if e != nil {
		t.Fatal("aborted candidate changed UDP capacity", e)
	}
	next.Inbounds = next.Inbounds[:1]
	if _, e = s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	live := s.current().cfg.Inbounds[0].ssRuntime
	if live.codec != rt.codec || live.ssRoutes != rt.ssRoutes {
		t.Fatal("same key lost runtime state")
	}
	for _, wire := range [][]byte{tcpA, tcpB} {
		if e = accept(live.codec, wire); !errors.Is(e, ss.ErrReplay) {
			t.Fatal("lost live TCP salt on shrink", e)
		}
	}
	if e = accept(live.codec, tcp2022(t, dst, 3)); !errors.Is(e, ss.ErrCapacity) {
		t.Fatal("new TCP limit not published", e)
	}
	if _, e = live.codec.DecodeUDP(first, peer); e != ss.ErrReplay {
		t.Fatal("lost UDP replay window", e)
	}
	if _, e = live.codec.DecodeUDP(udp2022(t, dst, 103, 1, nil), peer); e != ss.ErrCapacity {
		t.Fatal("new UDP limit not published", e)
	}
	if _, _, e = live.codec.EncodeUDP(oldCap, ss.Address{Host: dst.Host, Port: dst.Port}, nil); e != nil {
		t.Fatal("old capability invalidated", e)
	}
	if _, e = client.WriteToUDP(udp2022(t, dst, 101, 2, []byte("after")), endpoint); e != nil {
		t.Fatal(e)
	}
	body, out2 := recvUDP(t, target)
	if string(body) != "after" || out2.String() != out.String() {
		t.Fatal("native association changed during policy-only reload")
	}
}

func TestSSMigrationChecksCurrentSourcePolicy(t *testing.T) {
	for _, mode := range []string{"acl", "ban"} {
		t.Run(mode, func(t *testing.T) {
			in := ssIn()
			in.Listen = "127.0.0.1:0"
			base := socksCfg()
			base.DNS = &DNSOptions{Server: "system"}
			base.Inbounds = []Inbound{in}
			base.Limits.UDPIdle = Duration(time.Minute)
			base.Security.AuthBan = &AuthBanOptions{Enabled: true, Threshold: 1, Window: Duration(time.Minute), Duration: Duration(time.Minute)}
			next := base
			s := startReloadable(t, base, &next)
			target, client, valid := localUDP(t), localUDP(t), localUDP(t)
			other, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
			if e != nil {
				t.Fatal(e)
			}
			defer other.Close()
			dst := addrFromNet(target.LocalAddr())
			ep := net.UDPAddrFromAddrPort(s.Addresses()[0].(*net.TCPAddr).AddrPort())
			send := func(c *net.UDPConn, b []byte) {
				t.Helper()
				if _, e = c.WriteToUDP(b, ep); e != nil {
					t.Fatal(e)
				}
			}
			send(client, udp2022(t, dst, 33, 1, []byte("first")))
			_, out := recvUDP(t, target)
			if mode == "acl" {
				in.Sources = &SourceOptions{Deny: []string{"127.0.0.2/32"}}
				next.Inbounds = []Inbound{in}
				if _, e = s.Reload("test"); e != nil {
					t.Fatal(e)
				}
			} else {
				s.guard.authFailure(netip.MustParseAddr("127.0.0.2"), s.cfg.authBan(), in.Protocol, 0)
			}
			before := s.guard.refusedCIDR.Load() + s.guard.refusedBanned.Load()
			move := udp2022(t, dst, 33, 2, []byte("move"))
			send(other, move)
			waitFor(t, func() bool { return s.guard.refusedCIDR.Load()+s.guard.refusedBanned.Load() == before+1 })
			if _, e = target.WriteToUDP([]byte("still-original"), out); e != nil {
				t.Fatal(e)
			}
			recvUDP(t, client)
			// Exactly the same eligible sequence number must still be unused. A valid
			// NAT rebind keeps its egress socket and becomes the authenticated peer.
			send(valid, move)
			b, out2 := recvUDP(t, target)
			if string(b) != "move" || out2.String() != out.String() {
				t.Fatal("valid migration changed association")
			}
			if _, e = target.WriteToUDP([]byte("moved"), out2); e != nil {
				t.Fatal(e)
			}
			recvUDP(t, valid)
		})
	}
}

func TestSSRemovedBindingDrainsOnlyCurrentPeer(t *testing.T) {
	old, keep := ssIn(), ssIn()
	old.Listen = reloadPort(t)
	keep.Listen = "127.0.0.1:0"
	base := socksCfg()
	base.DNS = &DNSOptions{Server: "system"}
	base.Limits.UDPIdle = Duration(time.Minute)
	base.Inbounds = []Inbound{old, keep}
	next := base
	s := startReloadable(t, base, &next)
	target, client, mover := localUDP(t), localUDP(t), localUDP(t)
	dst := addrFromNet(target.LocalAddr())
	ep := func(i int) *net.UDPAddr { return net.UDPAddrFromAddrPort(s.Addresses()[i].(*net.TCPAddr).AddrPort()) }
	removed, kept := ep(0), ep(1)
	send := func(c *net.UDPConn, endpoint *net.UDPAddr, id uint64) {
		t.Helper()
		if _, e := c.WriteToUDP(udp2022(t, dst, 44, id, []byte("flow")), endpoint); e != nil {
			t.Fatal(e)
		}
	}
	send(client, removed, 1)
	_, out := recvUDP(t, target)
	next.Inbounds = []Inbound{keep}
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	dropped := s.Stats().Dropped
	send(mover, removed, 2)
	waitFor(t, func() bool { return s.Stats().Dropped > dropped })
	if _, e := target.WriteToUDP([]byte("original"), out); e != nil {
		t.Fatal(e)
	}
	recvUDP(t, client)
	send(client, removed, 2)
	_, out2 := recvUDP(t, target)
	if out.String() != out2.String() {
		t.Fatal("existing peer lost draining association")
	}
	send(mover, kept, 3)
	recvUDP(t, target)
	if _, e := target.WriteToUDP([]byte("new"), out); e != nil {
		t.Fatal(e)
	}
	_, from := recvUDP(t, mover)
	if from.Port != kept.Port {
		t.Fatal("did not migrate to live listener")
	}
}
