package kernel

import (
	"context"
	"net"
	"sync"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/anytls"
	"github.com/shui1iao/Kat/internal/outbound/group"
)

type carrierChoiceKey struct{}
type carrierChoice struct {
	mu   sync.Mutex
	name string
}

// dialCarrier records only choices made while an AnyTLS physical session is
// established. It does not select members, resolve names, or change group policy.
func dialCarrier(ctx context.Context, d outbound.Dialer, dst outbound.Addr) (net.Conn, error) {
	g, ok := d.(group.Group)
	if !ok {
		return d.DialTCP(ctx, dst)
	}
	branch, commit := anytls.SessionRouteBranch(ctx)
	if commit == nil {
		return d.DialTCP(ctx, dst)
	}
	choice := &carrierChoice{}
	branch = context.WithValue(branch, carrierChoiceKey{}, choice)
	c, err := d.DialTCP(branch, dst)
	if err == nil {
		choice.mu.Lock()
		selected := choice.name
		choice.mu.Unlock()
		anytls.RecordSessionRoute(branch, func() bool {
			// Per-destination / per-connection policies have no stable Current path.
			// A fresh carrier invokes their existing selection instead of guessing.
			switch g.Type() {
			case group.TypeSelect, group.TypeURLTest, group.TypeFallback:
				return selected != "" && g.Current() == selected
			default:
				return false
			}
		})
		commit()
	}
	return c, err
}
