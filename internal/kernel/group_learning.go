package kernel

import (
	"github.com/shui1iao/Kat/internal/outbound/group"
	"reflect"
)

// A different proxy/network identity discards quality. Preference-only edits
// keep measurements but reset confirmations. This is not persistence: a new
// process/Start has no previous generation and always learns from scratch.
func (s *Server) inheritGroupLearning(prev *Server) {
	if prev.rt == nil || !reflect.DeepEqual(s.cfg.Outbounds, prev.cfg.Outbounds) || !reflect.DeepEqual(s.cfg.DNS, prev.cfg.DNS) || s.cfg.UDPBindIPv4 != prev.cfg.UDPBindIPv4 || s.cfg.UDPBindIPv6 != prev.cfg.UDPBindIPv6 {
		return
	}
	a, b := append([]GroupConfig(nil), s.cfg.Groups...), append([]GroupConfig(nil), prev.cfg.Groups...)
	for _, gs := range [][]GroupConfig{a, b} {
		for i := range gs {
			gs[i].Selected = ""
			gs[i].Fixed = ""
			gs[i].Priority = nil
			gs[i].Damping = nil
			gs[i].Smart = nil
			gs[i].Tolerance = 0
			gs[i].ToleranceSet = false
		}
	}
	if !reflect.DeepEqual(a, b) {
		return
	}
	old := map[string]group.Group{}
	for _, g := range prev.rt.groups {
		old[g.Name()] = g
	}
	for _, g := range s.rt.groups {
		if copy, ok := g.(interface{ InheritLearning(group.Group) }); ok && old[g.Name()] != nil {
			copy.InheritLearning(old[g.Name()])
		}
	}
}
