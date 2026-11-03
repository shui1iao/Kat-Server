package group

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// emptyGroup is a dynamic group (use / include_all*) whose providers and
// filters currently yield no member. Every connection fails with
// ErrNoMember until a provider update brings members.
type emptyGroup struct{ cfg config }

func (g *emptyGroup) ClientAlive() bool               { return false }
func (g *emptyGroup) ClientHealth() (bool, time.Time) { return false, time.Time{} }
func (g *emptyGroup) Name() string                    { return g.cfg.name }
func (g *emptyGroup) Type() string                    { return g.cfg.kind }
func (g *emptyGroup) Close() error                    { return nil }
func (g *emptyGroup) Start(context.Context)           {}
func (g *emptyGroup) Members() []string               { return nil }
func (g *emptyGroup) Current() string                 { return g.cfg.fixed }
func (g *emptyGroup) UDP() bool                       { return false }
func (g *emptyGroup) Snapshot() Snapshot {
	return Snapshot{Name: g.cfg.name, Type: g.cfg.kind, Current: g.cfg.fixed, Fixed: g.cfg.fixed, SelectionMode: g.cfg.scope, Reason: "insufficient_data", ConfirmRequired: g.cfg.confirms}
}
func (g *emptyGroup) Select(name string) error {
	return fmt.Errorf("group %q: %q is not a member", g.cfg.name, name)
}
func (g *emptyGroup) DialTCP(context.Context, outbound.Addr) (net.Conn, error) {
	return nil, noMember(g.cfg.name, "TCP")
}
func (g *emptyGroup) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, noMember(g.cfg.name, "UDP")
}
