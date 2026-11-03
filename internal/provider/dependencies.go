package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
)

var ErrDependency = errors.New("invalid subscription dependency graph")

func (r Result) hasVia() bool {
	for _, n := range r.Nodes {
		if n.Options.Via != "" {
			return true
		}
	}
	return false
}

// Only evaluate groups referenced by retained nodes. include-all is source-local.
func clashDependencies(r *Result, raw []any, gs []map[string]any) error {
	if !r.hasVia() {
		return nil
	}
	if len(raw) > MaxNodes {
		return ErrDependency
	}
	counts := map[string]int{}
	for _, v := range raw {
		if m, ok := v.(map[string]any); ok {
			n, _ := cleanName(str(m, "name"))
			counts[n]++
		}
	}
	nodes := map[string]Node{}
	groups := map[string]map[string]any{}
	gc := map[string]int{}
	for _, n := range r.Nodes {
		if counts[n.Options.Name] != 1 || n.Options.Name == "direct" || n.Options.Name == "reject" {
			return ErrDependency
		}
		nodes[n.Options.Name] = n
	}
	for _, g := range gs {
		n := str(g, "name")
		groups[n] = g
		gc[n]++
	}
	required := map[string]group.Options{}
	color := map[string]int{}
	depth := map[string]int{}
	var visit func(string) error
	visit = func(name string) error {
		if name == "direct" {
			return nil
		}
		if name == "reject" || color[name] == 1 {
			return ErrDependency
		}
		if color[name] == 2 {
			return nil
		}
		color[name] = 1
		d := 0
		if n, ok := nodes[name]; ok {
			if gc[name] > 0 {
				return ErrDependency
			}
			if n.Options.Via != "" {
				if e := visit(n.Options.Via); e != nil {
					return e
				}
				d = depth[n.Options.Via]
			}
			d++
		} else {
			m, ok := groups[name]
			if !ok || gc[name] != 1 || counts[name] != 0 || str(m, "type") != "url-test" {
				return ErrDependency
			}
			if _, ok := cleanName(name); !ok {
				return ErrDependency
			}
			allowed := map[string]bool{}
			for _, k := range strings.Fields("name type proxies include-all filter exclude-filter exclude-type url interval timeout tolerance lazy expected-status icon") {
				allowed[k] = true
			}
			for k := range m {
				if !allowed[k] {
					return ErrDependency
				}
			}
			if v, exists := m["url"]; exists {
				s, ok := v.(string)
				if !ok || s == "" {
					return ErrDependency
				}
			}
			g := group.Options{Name: name, Type: group.TypeURLTest, Probe: &group.ProbeOptions{URL: str(m, "url")}}
			if v, ok := m["proxies"]; ok {
				a, ok := v.([]any)
				if !ok {
					return ErrDependency
				}
				for _, v := range a {
					s, ok := v.(string)
					if !ok || s == "" {
						return ErrDependency
					}
					g.Members = append(g.Members, s)
				}
			}
			if v, ok := m["include-all"]; ok {
				if _, ok := v.(bool); !ok {
					return ErrDependency
				}
			}
			f, e := group.MemberFilter(group.Options{Filter: str(m, "filter"), ExcludeFilter: str(m, "exclude-filter"), ExcludeType: str(m, "exclude-type")})
			if e != nil {
				return ErrDependency
			}
			if flag(m, "include-all") {
				seen := map[string]bool{}
				for _, s := range g.Members {
					seen[s] = true
				}
				for _, n := range r.Nodes {
					if !seen[n.Options.Name] && f(n.Options.Name, n.Options.Type) {
						seen[n.Options.Name] = true
						g.Members = append(g.Members, n.Options.Name)
					}
				}
			}
			duration := func(k string, unit time.Duration) (outbound.Duration, error) {
				if !has(m, k) {
					return 0, nil
				}
				v, e := strconv.ParseInt(str(m, k), 10, 64)
				if e != nil || v < 0 || v > 604800000 {
					return 0, ErrDependency
				}
				return outbound.Duration(time.Duration(v) * unit), nil
			}
			if g.Probe.Interval, e = duration("interval", time.Second); e != nil {
				return e
			}
			if g.Probe.Timeout, e = duration("timeout", time.Millisecond); e != nil {
				return e
			}
			_, g.ToleranceSet = m["tolerance"]
			if g.Tolerance, e = duration("tolerance", time.Millisecond); e != nil {
				return e
			}
			if v, ok := m["lazy"]; ok {
				b, ok := v.(bool)
				if !ok {
					return ErrDependency
				}
				g.Lazy = &b
			}
			g.Probe.ExpectedStatus = str(m, "expected-status")
			// Validate all fields except the intentionally absent URL, before storing.
			probe := *g.Probe
			test := g
			if probe.URL == "" {
				probe.URL = "https://example.invalid/"
			}
			test.Probe = &probe
			if group.Validate(test) != nil {
				return ErrDependency
			}
			required[name] = g
			for _, m := range g.Members {
				if e := visit(m); e != nil {
					return e
				}
				if depth[m] > d {
					d = depth[m]
				}
			}
		}
		if d > 4 {
			return ErrDependency
		}
		depth[name] = d
		color[name] = 2
		return nil
	}
	for _, n := range r.Nodes {
		if e := visit(n.Options.Name); e != nil {
			return e
		}
	}
	for _, g := range gs {
		if v, ok := required[str(g, "name")]; ok {
			r.DependencyGroups = append(r.DependencyGroups, v)
		}
	}
	if len(r.DependencyGroups) > 64 {
		return ErrDependency
	}
	return nil
}

// Materialize closes a root selection, supplies ONLY missing probe URLs and
// remaps declarations/references together. It never mutates the Result snapshot.
// namespace is empty for an import draft, provider name for dynamic graphs.
func (r Result) Materialize(namespace, probeURL string, taken map[string]bool, keep func(string, string) bool) ([]outbound.Options, []group.Options, []string, error) {
	nodes := map[string]Node{}
	gs := map[string]group.Options{}
	for _, n := range r.Nodes {
		if _, ok := nodes[n.Options.Name]; ok {
			return nil, nil, nil, ErrDependency
		}
		nodes[n.Options.Name] = n
	}
	for _, g := range r.DependencyGroups {
		if _, ok := gs[g.Name]; ok {
			return nil, nil, nil, ErrDependency
		}
		gs[g.Name] = g
	}
	selected := map[string]bool{}
	roots := []string{}
	color := map[string]int{}
	var visit func(string) error
	visit = func(n string) error {
		// Built-ins are references only when no source declaration owns
		// the name. A plain subscription proxy named direct/reject must be
		// materialized and aliased, never silently become a built-in route.
		_, declaredNode := nodes[n]
		_, declaredGroup := gs[n]
		if n == "direct" && !declaredNode && !declaredGroup {
			return nil
		}
		if (n == "reject" && !declaredNode && !declaredGroup) || color[n] == 1 {
			return ErrDependency
		}
		if color[n] == 2 {
			return nil
		}
		color[n] = 1
		selected[n] = true
		if o, ok := nodes[n]; ok {
			if _, ok := gs[n]; ok {
				return ErrDependency
			}
			if o.Options.Via != "" {
				if e := visit(o.Options.Via); e != nil {
					return e
				}
			}
		} else if g, ok := gs[n]; ok {
			for _, m := range g.Members {
				if e := visit(m); e != nil {
					return e
				}
			}
		} else {
			return ErrDependency
		}
		color[n] = 2
		return nil
	}
	for _, n := range r.Nodes {
		if keep == nil || keep(n.Options.Name, n.Options.Type) {
			roots = append(roots, n.Options.Name)
			if e := visit(n.Options.Name); e != nil {
				return nil, nil, nil, e
			}
		}
	}
	if taken == nil {
		taken = map[string]bool{}
	}
	taken["direct"] = true
	taken["reject"] = true
	names := map[string]string{"direct": "direct"}
	alloc := func(name, kind string) error {
		desired := name
		if namespace != "" {
			desired = name + "@" + namespace + "." + kind
		}
		candidate := safeName(desired, namespace+"\x00"+kind+"\x00"+name)
		for i := 0; taken[candidate]; i++ {
			if i > 4096 {
				return ErrDependency
			}
			candidate = safeAlias(desired, namespace+"\x00"+kind+"\x00"+name+"\x00"+strconv.Itoa(i))
		}
		names[name] = candidate
		taken[candidate] = true
		return nil
	}
	for _, n := range r.Nodes {
		if selected[n.Options.Name] {
			if e := alloc(n.Options.Name, "n"); e != nil {
				return nil, nil, nil, e
			}
		}
	}
	for _, g := range r.DependencyGroups {
		if selected[g.Name] {
			if e := alloc(g.Name, "g"); e != nil {
				return nil, nil, nil, e
			}
		}
	}
	outs := []outbound.Options{}
	groups := []group.Options{}
	for _, n := range r.Nodes {
		if !selected[n.Options.Name] {
			continue
		}
		o := n.OutboundOptions()
		o.Name = names[o.Name]
		if o.Via != "" {
			o.Via = names[o.Via]
		}
		outs = append(outs, o)
	}
	for _, g := range r.DependencyGroups {
		if !selected[g.Name] {
			continue
		}
		g.Name = names[g.Name]
		members := []string{}
		for _, m := range g.Members {
			members = append(members, names[m])
		}
		g.Members = members
		if g.Probe == nil {
			return nil, nil, nil, ErrDependency
		}
		p := *g.Probe
		if p.URL == "" {
			p.URL = probeURL
		}
		g.Probe = &p
		if group.Validate(g) != nil {
			return nil, nil, nil, ErrDependency
		}
		groups = append(groups, g)
	}
	for i, n := range roots {
		roots[i] = names[n]
	}
	return outs, groups, roots, nil
}
func safeName(s, key string) string {
	if s != "" && len(s) <= 64 && utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) || r == '=' }) {
		return s
	}
	return safeAlias(s, key)
}
func safeAlias(s, key string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '=' {
			return '_'
		}
		return r
	}, s)
	if s == "" {
		s = "node"
	}
	if len(s) > 51 {
		s = s[:51]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	h := sha256.Sum256([]byte(key))
	return s + "~" + hex.EncodeToString(h[:6])
}
