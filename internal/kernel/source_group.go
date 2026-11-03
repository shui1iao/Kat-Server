package kernel

import (
	"encoding/json"
	"fmt"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
)

// Relay is an ordered route, not a set of interchangeable nodes. Refuse it
// anywhere in a source subtree rather than silently dismantling its via chain.
// Called after the normal dependency graph has been checked for cycles.
func validateSourceGroups(groups []GroupConfig) error {
	byName := map[string]GroupConfig{}
	for _, g := range groups {
		byName[g.Name] = g
	}
	var visit func(string, map[string]bool) error
	visit = func(name string, seen map[string]bool) error {
		g, ok := byName[name]
		if !ok {
			return fmt.Errorf("unknown source group %q", name)
		}
		if seen[name] {
			return nil
		}
		seen[name] = true
		if g.Type == group.TypeRelay {
			return fmt.Errorf("source group subtree contains relay %q: ordered chains cannot be included as nodes", name)
		}
		for _, m := range g.Members {
			if _, ok := byName[m]; ok {
				if e := visit(m, seen); e != nil {
					return e
				}
			}
		}
		if g.IncludeGroup != "" {
			return visit(g.IncludeGroup, seen)
		}
		return nil
	}
	for _, g := range groups {
		if g.IncludeGroup != "" {
			if e := visit(g.IncludeGroup, map[string]bool{}); e != nil {
				return e
			}
		}
	}
	return nil
}

// groupLeaves reads effective member lists (after all dynamic expansion). It
// never reads a selector's Current: nested groups contribute all their leaves.
func groupLeaves(groups []GroupConfig, name string) ([]string, error) {
	byName := map[string]GroupConfig{}
	for _, g := range groups {
		byName[g.Name] = g
	}
	if _, ok := byName[name]; !ok {
		return nil, fmt.Errorf("unknown source group %q", name)
	}
	leaves := []string{}
	seen, active, done := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(n string) error {
		g, ok := byName[n]
		if !ok {
			if !seen[n] {
				seen[n] = true
				leaves = append(leaves, n)
			}
			return nil
		}
		if active[n] {
			return fmt.Errorf("source group dependency cycle")
		}
		if done[n] {
			return nil
		}
		if g.Type == group.TypeRelay {
			return fmt.Errorf("source group subtree contains relay %q", n)
		}
		active[n] = true
		for _, m := range g.Members {
			if e := visit(m); e != nil {
				return e
			}
		}
		delete(active, n)
		done[n] = true
		return nil
	}
	if e := visit(name); e != nil {
		return nil, e
	}
	return leaves, nil
}

// Resolve dependencies before expanding include_group, irrespective of source
// declaration order. Legacy dynamic expansion has already run for every group.
func expandSourceGroups(groups []GroupConfig, labels, types map[string]string, explicitCounts map[string]int) error {
	indices := map[string]int{}
	for i, g := range groups {
		indices[g.Name] = i
	}
	state := make([]byte, len(groups))
	var resolve func(int) error
	resolve = func(i int) error {
		if state[i] == 2 {
			return nil
		}
		if state[i] == 1 {
			return fmt.Errorf("source group dependency cycle")
		}
		state[i] = 1
		g := &groups[i]
		for _, m := range g.Members {
			if j, ok := indices[m]; ok {
				if e := resolve(j); e != nil {
					return e
				}
			}
		}
		if g.IncludeGroup != "" {
			j, ok := indices[g.IncludeGroup]
			if !ok {
				return fmt.Errorf("group %q: unknown source group %q", g.Name, g.IncludeGroup)
			}
			if e := resolve(j); e != nil {
				return e
			}
			leaves, e := groupLeaves(groups, g.IncludeGroup)
			if e != nil {
				return e
			}
			keep, e := group.MemberFilter(group.Options(*g))
			if e != nil {
				return e
			}
			seen := map[string]bool{}
			explicit := explicitCounts[g.Name]
			for _, n := range g.Members[:explicit] {
				seen[n] = true
			}
			// Copy before appending: caller-owned unexpanded member slices must not
			// acquire preview/refresh nodes through shared backing arrays.
			members := append([]string(nil), g.Members[:explicit]...)
			for _, n := range leaves {
				label, typ := labels[n], types[n]
				if n == "direct" || n == "reject" {
					label, typ = n, n
				}
				if !seen[n] && len(members) < 1024 && keep(label, typ) {
					seen[n] = true
					members = append(members, n)
				}
			}
			// Existing use/include_all* remain additive, after the new source.
			for _, n := range g.Members[explicit:] {
				if !seen[n] && len(members) < 1024 {
					seen[n] = true
					members = append(members, n)
				}
			}
			g.Members = members
		}
		state[i] = 2
		return nil
	}
	for i := range groups {
		if e := resolve(i); e != nil {
			return e
		}
	}
	return nil
}

// PreviewSourceGroup is the read-only desktop preview projection. A running
// configuration is already expanded; a stopped one loads only local provider
// files/caches, exactly as CheckProviders does (never network or writes).
// target, when nonempty, checks the proposed include edge in the existing
// dependency graph. No expanded member list is persisted to the source bytes.
func PreviewSourceGroup(c Config, source, target string, filters group.Options) ([]string, error) {
	if target != "" {
		// Validate the new edge against the unexpanded source configuration; old
		// expanded nodes must not introduce dependencies from the former source.
		raw := c
		if len(c.raw) > 0 {
			var e error
			raw, e = decodeConfig(c.raw)
			if e != nil {
				return nil, e
			}
		}
		raw.Groups = append([]GroupConfig(nil), raw.Groups...)
		found := false
		for i := range raw.Groups {
			if raw.Groups[i].Name == target {
				raw.Groups[i].IncludeGroup = source
				raw.Groups[i].Filter = filters.Filter
				raw.Groups[i].ExcludeFilter = filters.ExcludeFilter
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown target group %q", target)
		}
		if _, _, e := CheckProviders(raw); e != nil {
			return nil, e
		}
	}
	if !c.expanded {
		// Deep-copy before normalization; even defaults must not mutate Host state.
		b, e := json.Marshal(c)
		if e != nil {
			return nil, e
		}
		c, e = decodeConfig(b)
		if e != nil {
			return nil, e
		}
		provs := map[string]*providerRT{}
		for _, pc := range c.Providers {
			p := newProviderRT(nil, pc, c.statsFile())
			_, _ = p.loadLocal()
			provs[pc.Name] = p
		}
		if _, e := expandProviders(&c, provs); e != nil {
			return nil, e
		}
		if e := c.Validate(); e != nil {
			return nil, e
		}
	}
	leaves, e := groupLeaves(c.Groups, source)
	if e != nil {
		return nil, e
	}
	keep, e := group.MemberFilter(filters)
	if e != nil {
		return nil, e
	}
	nodes := map[string]outbound.Options{}
	for _, o := range c.Outbounds {
		nodes[o.Name] = outbound.Options(o)
	}
	names := []string{}
	for _, n := range leaves {
		label, typ := n, n
		if o, ok := nodes[n]; ok {
			label, typ = o.FilterLabel(), o.Type
		}
		if keep(label, typ) {
			names = append(names, n)
		}
	}
	return names, nil
}
