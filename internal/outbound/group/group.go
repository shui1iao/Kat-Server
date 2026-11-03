// Package group implements Kat's policy groups: select, url-test, fallback,
// smart and load-balance (relay groups are expanded by the kernel into via
// chains and never reach this package at run time). A group is itself an outbound.Outbound, so groups can be nested and
// used as the "via" hop of a protocol outbound.
//
// The smart group is Kat's own design. Its inputs and parameters were chosen
// after reading the public descriptions of similar features in other products,
// but it is not a reproduction of any of them; see smart.go for the exact,
// fully specified algorithm.
//
// All state is in memory only. Selection changes apply to new connections;
// established connections and UDP sessions keep the member they started with.
package group

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// Group types.
const (
	TypeSelect   = "select"
	TypeURLTest  = "url-test"
	TypeFallback = "fallback"
	TypeSmart    = "smart"
	// TypeLoadBalance spreads connections over the healthy members.
	TypeLoadBalance = "load-balance"
	// TypeRelay chains its members (first = closest to Kat). The kernel turns
	// it into the equivalent via chain; New refuses it.
	TypeRelay = "relay"
)

// Load-balance strategies.
const (
	StrategyRoundRobin        = "round-robin"
	StrategyConsistentHashing = "consistent-hashing"
	StrategyStickySessions    = "sticky-sessions"
)

// Fixed parameters (design constants; not configurable).
const (
	maxMembers             = 64   // explicitly written members
	maxExpandedMembers     = 1024 // after provider/include_all expansion
	maxRelayMembers        = 4
	defaultStickyTTL       = 10 * time.Minute
	maxStickyTTL           = 24 * time.Hour
	maxFailedTimesLimit    = 100
	lbDefaultMaxFailed     = 5
	maxAttempts            = 3 // members tried per connection before giving up
	probeConcurrency       = 4
	defaultInterval        = 10 * time.Minute // server fallback / load-balance
	defaultURLTestInterval = time.Minute
	defaultSmartInterval   = 5 * time.Minute
	minInterval            = time.Second
	defaultTimeout         = 5 * time.Second
	maxTimeout             = 60 * time.Second
	defaultTolerance       = 20 * time.Millisecond
	maxPriority            = 100

	urlTestFailWindow = 60 * time.Second // url-test: N real failures within this window ...
	urlTestFailCount  = 3                // ... trigger an immediate re-test
	fallbackFailLimit = 2                // fallback: consecutive real failures that mark a member down
	noReplyTimeout    = 3 * time.Second  // smart: data written / datagram sent but nothing came back
)

// ProbeOptions configures active HTTP(S) probing.
type ProbeOptions struct {
	// Prepare is supplied only by the runtime. It prepares cold nested/via/relay
	// dependencies before a background probe reserves shared HTTP capacity.
	Prepare func(context.Context, string) error `json:"-"`
	// Desktop runtime-only semantics; not accepted from or emitted to server JSON.
	ClientHead    bool              `json:"-"`
	ClientUnified bool              `json:"-"`
	URL           string            `json:"url"`                // required (http/https); no built-in default
	Interval      outbound.Duration `json:"interval,omitempty"` // url-test default 1m; smart 5m; fallback/LB server 10m, desktop 5m
	Timeout       outbound.Duration `json:"timeout,omitempty"`  // default 5s, max 60s
	// ExpectedStatus restricts the HTTP statuses that count as success:
	// "204", "200/204", "200-299/302" or "*". Empty = any status below 500.
	ExpectedStatus string `json:"expected_status,omitempty"`
}

// Options is one entry of the root "groups" array.
type DampingOptions struct {
	RelativeImprovement *float64           `json:"relative_improvement,omitempty"`
	ConfirmRounds       int                `json:"confirm_rounds,omitempty"`
	MinDwell            *outbound.Duration `json:"min_dwell,omitempty"`
}

func (d *DampingOptions) UnmarshalJSON(b []byte) error {
	type plain DampingOptions
	var p plain
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&p); e != nil {
		return e
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	if _, ok := fields["confirm_rounds"]; ok && (p.ConfirmRounds < 2 || p.ConfirmRounds > 5) {
		return errors.New("damping.confirm_rounds must be 2..5")
	}
	*d = DampingOptions(p)
	return nil
}

type SmartOptions struct {
	Scope           string  `json:"scope,omitempty"`
	ExplorationRate float64 `json:"exploration_rate,omitempty"`
	AdaptiveDial    *bool   `json:"adaptive_dial,omitempty"`
}

// All automatic groups use stable selection; there is deliberately no legacy
// algorithm switch. Preserve omitted vs explicit zero tolerance, including
// mihomo's numeric millisecond spelling. Source bytes remain client-owned.
type Options struct {
	Icon         string             `json:"icon,omitempty"` // display only, never used for routing
	Name         string             `json:"name"`
	Type         string             `json:"type"`                // select | url-test | fallback | smart
	Members      []string           `json:"members,omitempty"`   // 1..64, unique
	Fixed        string             `json:"fixed,omitempty"`     // automatic types: persistent healthy-first preference
	Selected     string             `json:"selected,omitempty"`  // select only
	Probe        *ProbeOptions      `json:"probe,omitempty"`     // required for url-test/fallback/smart, forbidden for select
	Tolerance    outbound.Duration  `json:"tolerance,omitempty"` // url-test / smart; numeric input is milliseconds
	ToleranceSet bool               `json:"-"`
	Damping      *DampingOptions    `json:"damping,omitempty"`
	Smart        *SmartOptions      `json:"smart,omitempty"`
	Priority     map[string]float64 `json:"priority,omitempty"` // smart/url-test; member name -> (0, 100], default 1

	// load-balance only.
	Strategy  string            `json:"strategy,omitempty"`   // round-robin | consistent-hashing (default) | sticky-sessions
	StickyTTL outbound.Duration `json:"sticky_ttl,omitempty"` // sticky-sessions, default 10m

	// Health checking (url-test, fallback, smart, load-balance).
	Lazy           *bool `json:"lazy,omitempty"`             // probe only while the group is used (default true; smart default: probe from start)
	MaxFailedTimes int   `json:"max_failed_times,omitempty"` // real failures that trigger a re-test / mark a member down

	// Dynamic members (expanded by the kernel; never valid for relay).
	IncludeGroup        string   `json:"include_group,omitempty"` // one source group; recursively include all effective leaves
	Use                 []string `json:"use,omitempty"`           // provider names
	Filter              string   `json:"filter,omitempty"`        // RE2 on member names; ` separates alternatives
	ExcludeFilter       string   `json:"exclude_filter,omitempty"`
	ExcludeType         string   `json:"exclude_type,omitempty"` // e.g. "shadowsocks|socks5"
	IncludeAll          bool     `json:"include_all,omitempty"`
	IncludeAllProxies   bool     `json:"include_all_proxies,omitempty"`
	IncludeAllProviders bool     `json:"include_all_providers,omitempty"`

	// Set by the kernel when Members holds the expanded member list.
	Expanded bool `json:"-"`
	// ConfigDefault is the configured default of an expanded select group:
	// selected, else the first written member, else "" (first available).
	ConfigDefault string `json:"-"`
}

func (o *Options) UnmarshalJSON(b []byte) error {
	type plain Options
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return err
	}
	tolerance, present := fields["tolerance"]
	if present {
		delete(fields, "tolerance")
	}
	rest, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(rest))
	dec.DisallowUnknownFields()
	var v plain
	if err = dec.Decode(&v); err != nil {
		return err
	}
	*o = Options(v)
	o.ToleranceSet = present
	if present {
		if len(tolerance) > 0 && tolerance[0] == '"' {
			return o.Tolerance.UnmarshalJSON(tolerance)
		}
		var n float64
		if string(tolerance) == "null" || json.Unmarshal(tolerance, &n) != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return errors.New("invalid tolerance")
		}
		o.Tolerance = outbound.Duration(n * float64(time.Millisecond))
	}
	return nil
}
func (o Options) MarshalJSON() ([]byte, error) {
	type plain Options
	b, e := json.Marshal(plain(o))
	if e != nil {
		return nil, e
	}
	if o.ToleranceSet && o.Tolerance == 0 {
		var m map[string]json.RawMessage
		_ = json.Unmarshal(b, &m)
		m["tolerance"] = json.RawMessage(`"0s"`)
		return json.Marshal(m)
	}
	return b, nil
}

// Dynamic reports whether the group takes members from a source group, providers or include_all*.
func (o Options) Dynamic() bool {
	return o.IncludeGroup != "" || len(o.Use) > 0 || o.IncludeAll || o.IncludeAllProxies || o.IncludeAllProviders
}

// Group is a policy group. It is an outbound.Outbound itself.
type Group interface {
	outbound.Outbound
	// Members returns the member names in configuration order.
	Members() []string
	// Current returns the group-level choice. Automatic Smart reports empty
	// until its first successful full probe bootstrap; fixed remains explicit.
	Current() string
	// Start starts background probing (lazy for url-test/fallback). Probing
	// stops when ctx ends or Close is called. Calling Start twice is a no-op.
	Start(ctx context.Context)
}

// Selector is implemented only by select groups (for a future GUI).
type Selector interface {
	Select(name string) error
}

// Snapshotter is implemented by every group returned by New.
type Snapshotter interface {
	Snapshot() Snapshot
}

// Snapshot is a point-in-time view of a group. It never contains destination
// or client addresses.
type Snapshot struct {
	Name            string
	Type            string
	Current         string
	Fixed           string
	Members         []MemberSnapshot
	SelectionMode   string
	MostUsedMember  string
	LearnedSites    int
	Reason          string
	Candidate       string
	ConfirmProgress int
	ConfirmRequired int
	RemainingDwell  time.Duration
}

// MemberSnapshot describes one member. Fields not used by the group type are zero.
type MemberSnapshot struct {
	Name             string
	ScoreParts       ScoreParts
	EffectiveSamples float64
	SampleCount      int
	SuccessRate      *float64
	HealthState      string
	CooldownUntil    time.Time
	DecisionKnown    bool
	DialLatency      time.Duration
	UDP              bool
	// Last probe round result (url-test / fallback / smart).
	Probed       bool
	ProbeOK      bool
	ProbeLatency time.Duration
	ProbeAt      time.Time
	// Failures: url-test = real failures in the last 60s; fallback/smart =
	// consecutive real failures since the last success.
	Failures int
	// Smart only.
	Latency  time.Duration // decayed real transport-first-response mean; 0 = unknown
	Penalty  time.Duration // failure penalty decayed to the snapshot time
	Priority float64
	Score    time.Duration // (latency or probe timeout when unknown) + penalty, times priority
}

// Validate statically checks o. Member existence is checked by the kernel.
func Validate(o Options) error {
	_, err := normalize(o)
	return err
}

type config struct {
	name         string
	kind         string
	members      []string
	selected     int
	fixed        string
	fixedIndex   int
	url          string
	target       outbound.Addr
	interval     time.Duration
	timeout      time.Duration
	tolerance    time.Duration
	relative     float64
	confirms     int
	dwell        time.Duration
	scope        string
	exploration  float64
	adaptiveDial bool
	priority     []float64

	strategy  string
	stickyTTL time.Duration
	lazy      bool
	maxFailed int
	head      bool
	unified   bool
	expected  func(int) bool // nil: status < 500
	prepare   func(context.Context, string) error
}

func normalize(o Options) (config, error) {
	if !ValidIcon(o.Icon) {
		return config{}, errors.New("invalid group icon")
	}
	c := config{fixedIndex: -1}
	fail := func(format string, a ...any) (config, error) {
		return config{}, fmt.Errorf("group %q: "+format, append([]any{o.Name}, a...)...)
	}
	if strings.TrimSpace(o.Name) == "" {
		return fail("name is required")
	}
	switch o.Type {
	case TypeSelect, TypeURLTest, TypeFallback, TypeSmart, TypeLoadBalance:
	case TypeRelay:
		return normalizeRelay(o, fail)
	default:
		return fail("unknown type %q", o.Type)
	}
	dynamic := o.Dynamic()
	limit := maxMembers
	if o.Expanded {
		limit = maxExpandedMembers
	}
	if len(o.Members) > limit || (len(o.Members) == 0 && !dynamic) {
		if dynamic {
			return fail("members must have at most %d entries", limit)
		}
		return fail("members must have 1..%d entries", limit)
	}
	if _, err := memberFilter(o); err != nil {
		return fail("%v", err)
	}
	if !dynamic && (o.Filter != "" || o.ExcludeFilter != "" || o.ExcludeType != "") {
		return fail("filter, exclude_filter and exclude_type need include_group, use or include_all*")
	}
	seenUse := map[string]bool{}
	for _, u := range o.Use {
		if u == "" || seenUse[u] {
			return fail("empty or duplicate provider in use")
		}
		seenUse[u] = true
	}
	index := make(map[string]int, len(o.Members))
	for i, m := range o.Members {
		if m == "" {
			return fail("empty member name")
		}
		if m == o.Name {
			return fail("group cannot contain itself")
		}
		if _, dup := index[m]; dup {
			return fail("duplicate member %q", m)
		}
		if o.Type != TypeSelect && m == "reject" {
			return fail("%s group cannot contain reject", o.Type)
		}
		index[m] = i
	}
	c.name, c.kind, c.members = o.Name, o.Type, append([]string(nil), o.Members...)
	if o.Selected != "" {
		if o.Type != TypeSelect {
			return fail("selected is only valid for select groups")
		}
		i, ok := index[o.Selected]
		// A dynamic group may name a provider node that is resolved later.
		if !ok && (o.Expanded || !dynamic) {
			return fail("selected %q is not a member", o.Selected)
		}
		c.selected = i
	}
	if o.Fixed != "" {
		if o.Type != TypeSmart && o.Type != TypeURLTest && o.Type != TypeFallback && o.Type != TypeLoadBalance {
			return fail("fixed is only valid for automatic groups")
		}
		c.fixed = o.Fixed
		if i, ok := index[o.Fixed]; ok {
			c.fixedIndex = i
		} else if !dynamic {
			return fail("fixed target is not a member")
		}
	}
	if (o.ToleranceSet || o.Tolerance != 0) && o.Type != TypeURLTest && o.Type != TypeSmart {
		return fail("tolerance is only valid for url-test/smart groups")
	}
	if o.Tolerance < 0 || o.Tolerance.Value() > 5*time.Second {
		return fail("tolerance must be in 0..5s")
	}
	if len(o.Priority) != 0 && o.Type != TypeSmart && o.Type != TypeURLTest {
		return fail("priority is only valid for smart/url-test groups")
	}
	if (o.Strategy != "" || o.StickyTTL != 0) && o.Type != TypeLoadBalance {
		return fail("strategy and sticky_ttl are only valid for load-balance groups")
	}
	if o.Type == TypeSelect {
		if o.Damping != nil || o.Smart != nil {
			return fail("damping/smart are only valid for automatic groups")
		}
		if o.Probe != nil {
			return fail("probe is not valid for select groups")
		}
		if o.Lazy != nil || o.MaxFailedTimes != 0 {
			return fail("lazy and max_failed_times are not valid for select groups")
		}
		return c, nil
	}
	if o.Probe == nil {
		return fail("probe is required for %s groups", o.Type)
	}
	u, err := url.Parse(o.Probe.URL)
	if err != nil || u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return fail("probe.url must be an absolute http or https URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fail("probe.url must be an absolute http or https URL")
	}
	host := strings.ToLower(u.Hostname())
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" {
			return fail("probe.url host must not have a zone")
		}
		host = ip.Unmap().String()
	}
	port := uint16(80)
	if scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		n, e := strconv.ParseUint(p, 10, 16)
		if e != nil || n == 0 {
			return fail("probe.url has an invalid port")
		}
		port = uint16(n)
	}
	c.url, c.target = o.Probe.URL, outbound.Addr{Host: host, Port: port}
	c.interval = o.Probe.Interval.Value()
	switch {
	case c.interval < 0 || (c.interval > 0 && c.interval < minInterval):
		return fail("probe.interval must be at least %s", minInterval)
	case c.interval == 0 && o.Type == TypeURLTest:
		c.interval = defaultURLTestInterval
	case c.interval == 0 && (o.Type == TypeSmart || o.Probe.ClientHead):
		c.interval = defaultSmartInterval
	case c.interval == 0:
		c.interval = defaultInterval
	}
	c.head, c.unified = o.Probe.ClientHead, o.Probe.ClientUnified
	c.prepare = o.Probe.Prepare
	c.timeout = o.Probe.Timeout.Value()
	switch {
	case c.timeout < 0 || c.timeout > maxTimeout:
		return fail("probe.timeout must be in (0, %s]", maxTimeout)
	case c.timeout == 0:
		c.timeout = defaultTimeout
	}
	if o.Probe.ExpectedStatus != "" {
		f, e := parseExpectedStatus(o.Probe.ExpectedStatus)
		if e != nil {
			return fail("probe.expected_status: %v", e)
		}
		c.expected = f
	}
	// lazy: url-test, fallback and load-balance default to probing only
	// while used (their previous behaviour); smart defaults to probing from
	// Start and pausing when idle.
	c.lazy = o.Type != TypeSmart
	if o.Lazy != nil {
		c.lazy = *o.Lazy
	}
	switch o.Type {
	case TypeURLTest:
		c.maxFailed = urlTestFailCount
	case TypeFallback:
		c.maxFailed = fallbackFailLimit
	case TypeLoadBalance:
		c.maxFailed = lbDefaultMaxFailed
	case TypeSmart:
		if o.MaxFailedTimes != 0 {
			return fail("max_failed_times is not valid for smart groups (v2 circuit and attribution)")
		}
	}
	if o.MaxFailedTimes != 0 {
		if o.MaxFailedTimes < 1 || o.MaxFailedTimes > maxFailedTimesLimit {
			return fail("max_failed_times must be 1..%d", maxFailedTimesLimit)
		}
		c.maxFailed = o.MaxFailedTimes
	}
	c.tolerance = 50 * time.Millisecond
	if o.Type == TypeURLTest || o.Type == TypeSmart {
		c.tolerance = defaultTolerance
	}
	if o.ToleranceSet || o.Tolerance != 0 {
		c.tolerance = o.Tolerance.Value()
	}
	c.relative, c.confirms, c.dwell = 0.2, 2, 60*time.Second
	if o.Type == TypeURLTest || o.Type == TypeSmart {
		c.relative, c.dwell = 0.1, 30*time.Second
	}
	if d := o.Damping; d != nil {
		if d.RelativeImprovement != nil {
			c.relative = *d.RelativeImprovement
		}
		if d.ConfirmRounds != 0 {
			c.confirms = d.ConfirmRounds
		}
		if d.MinDwell != nil {
			c.dwell = d.MinDwell.Value()
		}
		if math.IsNaN(c.relative) || math.IsInf(c.relative, 0) || c.relative < 0 || c.relative > 0.9 || c.confirms < 2 || c.confirms > 5 || c.dwell < 0 || c.dwell > 30*time.Minute {
			return fail("invalid damping: relative_improvement 0..0.9, confirm_rounds 2..5, min_dwell 0..30m")
		}
		if o.Type == TypeFallback || o.Type == TypeLoadBalance {
			return fail("performance damping fields apply only to url-test/smart; recovery is always enabled")
		}
	}
	c.scope, c.adaptiveDial = "site", true
	if v := o.Smart; v != nil {
		if o.Type != TypeSmart {
			return fail("smart is only valid for smart groups")
		}
		if v.Scope != "" {
			c.scope = v.Scope
		}
		c.exploration = v.ExplorationRate
		if v.AdaptiveDial != nil {
			c.adaptiveDial = *v.AdaptiveDial
		}
		if (c.scope != "site" && c.scope != "group") || math.IsNaN(c.exploration) || math.IsInf(c.exploration, 0) || c.exploration < 0 || c.exploration > 0.05 {
			return fail("smart.scope must be site/group; exploration_rate must be 0..0.05")
		}
	}

	if o.Type == TypeLoadBalance {
		c.strategy = o.Strategy
		switch c.strategy {
		case "":
			c.strategy = StrategyConsistentHashing
		case StrategyRoundRobin, StrategyConsistentHashing, StrategyStickySessions:
		default:
			return fail("unknown strategy %q", o.Strategy)
		}
		if o.StickyTTL != 0 && c.strategy != StrategyStickySessions {
			return fail("sticky_ttl is only valid with strategy sticky-sessions")
		}
		c.stickyTTL = o.StickyTTL.Value()
		switch {
		case c.stickyTTL == 0:
			c.stickyTTL = defaultStickyTTL
		case c.stickyTTL < time.Second || c.stickyTTL > maxStickyTTL:
			return fail("sticky_ttl must be between 1s and %s", maxStickyTTL)
		}
	}
	if o.Type == TypeSmart || o.Type == TypeURLTest {
		c.priority = make([]float64, len(o.Members))
		for i := range c.priority {
			c.priority[i] = 1
		}
		for name, v := range o.Priority {
			i, ok := index[name]
			if math.IsNaN(v) || v <= 0 || v > maxPriority {
				return fail("priority for %q must be in (0, %d]", name, maxPriority)
			}
			if !ok {
				if dynamic {
					continue // may name a provider node absent from this expansion
				}
				return fail("priority refers to unknown member %q", name)
			}
			c.priority[i] = v
		}
	}
	return c, nil
}

// normalizeRelay checks a relay group: 1..4 written members, nothing else.
func normalizeRelay(o Options, fail func(string, ...any) (config, error)) (config, error) {
	if o.Dynamic() || o.Filter != "" || o.ExcludeFilter != "" || o.ExcludeType != "" {
		return fail("relay members must be written explicitly (no include_group, use, filter or include_all*)")
	}
	if o.Damping != nil || o.Smart != nil || o.ToleranceSet || o.Fixed != "" || o.Selected != "" || o.Probe != nil || o.Tolerance != 0 || len(o.Priority) != 0 || o.Strategy != "" || o.StickyTTL != 0 || o.Lazy != nil || o.MaxFailedTimes != 0 {
		return fail("relay groups take only name, type and members")
	}
	if len(o.Members) == 0 || len(o.Members) > maxRelayMembers {
		return fail("relay members must have 1..%d entries", maxRelayMembers)
	}
	seen := map[string]bool{}
	for _, m := range o.Members {
		if m == "" || m == o.Name || seen[m] {
			return fail("empty, duplicate or self relay member")
		}
		if m == "direct" || m == "reject" {
			return fail("relay members must be outbounds or groups, not %s", m)
		}
		seen[m] = true
	}
	return config{name: o.Name, kind: TypeRelay, members: append([]string(nil), o.Members...)}, nil
}

// parseExpectedStatus parses "*", "204", "200/204" and ranges "200-299".
func parseExpectedStatus(s string) (func(int) bool, error) {
	s = strings.TrimSpace(s)
	if s == "*" {
		return func(int) bool { return true }, nil
	}
	type span struct{ lo, hi int }
	var spans []span
	for _, part := range strings.Split(s, "/") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, e1 := strconv.Atoi(strings.TrimSpace(lo))
		b := a
		var e2 error
		if isRange {
			b, e2 = strconv.Atoi(strings.TrimSpace(hi))
		}
		if e1 != nil || e2 != nil || a < 100 || b > 599 || a > b {
			return nil, fmt.Errorf("invalid status %q (use 204, 200/204, 200-299 or *)", part)
		}
		spans = append(spans, span{a, b})
		if len(spans) > 32 {
			return nil, errors.New("too many status entries")
		}
	}
	return func(code int) bool {
		for _, sp := range spans {
			if code >= sp.lo && code <= sp.hi {
				return true
			}
		}
		return false
	}, nil
}

// MemberFilter returns the predicate a dynamic member (name, Kat outbound
// type) must satisfy to join group o: filter (any alternative matches, when
// set), no exclude_filter alternative matches, type not in exclude_type.
// Written members are never filtered.
func MemberFilter(o Options) (func(name, typ string) bool, error) { return memberFilter(o) }

func memberFilter(o Options) (func(name, typ string) bool, error) {
	compile := func(field, s string) ([]*regexp.Regexp, error) {
		if s == "" {
			return nil, nil
		}
		var out []*regexp.Regexp
		for _, p := range strings.Split(s, "`") {
			if p == "" {
				continue
			}
			re, e := regexp.Compile(p)
			if e != nil {
				return nil, fmt.Errorf("%s: invalid regular expression %q (RE2 syntax; look-around is not supported)", field, p)
			}
			out = append(out, re)
		}
		return out, nil
	}
	o.Filter, o.ExcludeFilter = NormalizeFilters(o.Filter, o.ExcludeFilter)
	inc, e := compile("filter", o.Filter)
	if e != nil {
		return nil, e
	}
	exc, e := compile("exclude_filter", o.ExcludeFilter)
	if e != nil {
		return nil, e
	}
	types := map[string]bool{}
	if o.ExcludeType != "" {
		for _, t := range strings.Split(o.ExcludeType, "|") {
			t = strings.ToLower(strings.TrimSpace(t))
			switch t {
			case "ss":
				t = "shadowsocks"
			case "socks":
				t = "socks5"
			}
			switch t {
			case "shadowsocks", "socks5", "trojan", "anytls":
			default:
				return nil, fmt.Errorf("exclude_type: unknown type %q (shadowsocks|ss, socks5|socks, trojan, anytls)", t)
			}
			types[t] = true
		}
	}
	return func(name, typ string) bool {
		if types[typ] {
			return false
		}
		for _, re := range exc {
			if re.MatchString(name) {
				return false
			}
		}
		if len(inc) == 0 {
			return true
		}
		for _, re := range inc {
			if re.MatchString(name) {
				return true
			}
		}
		return false
	}, nil
}

// New builds a group. members must be the resolved outbounds for o.Members,
// in the same order. New performs no network IO; probing starts with Start.
// Close does not close the members (they are owned by the caller).
func New(o Options, members []outbound.Outbound, events outbound.EventSink) (Group, error) {
	return newGroup(o, members, events, hooks{})
}

// hooks are package-internal injection points used by tests.
type hooks struct {
	clk   clock
	probe probeFunc   // replaces the HTTP prober
	tls   *tls.Config // base TLS config for https probes (tests inject a private root)
}

func newGroup(o Options, members []outbound.Outbound, events outbound.EventSink, h hooks) (Group, error) {
	c, err := normalize(o)
	if err != nil {
		return nil, err
	}
	if c.kind == TypeRelay {
		return nil, fmt.Errorf("group %q: relay groups are built by the kernel as via chains", c.name)
	}
	if len(members) != len(c.members) {
		return nil, fmt.Errorf("group %q: got %d member outbounds for %d member names", c.name, len(members), len(c.members))
	}
	for i, m := range members {
		if m == nil {
			return nil, fmt.Errorf("group %q: member %q is nil", c.name, c.members[i])
		}
		if m.Name() != c.members[i] {
			return nil, fmt.Errorf("group %q: member %d is %q, want %q", c.name, i, m.Name(), c.members[i])
		}
		if c.kind != TypeSelect && m.Type() == "reject" {
			return nil, fmt.Errorf("group %q: %s group cannot contain reject member %q", c.name, c.kind, c.members[i])
		}
	}
	ms := append([]outbound.Outbound(nil), members...)
	if h.clk == nil {
		h.clk = realClock{}
	}
	if len(ms) == 0 {
		// A dynamic group whose providers/filters currently yield nothing.
		return &emptyGroup{cfg: c}, nil
	}
	if c.kind == TypeSelect {
		return &selectGroup{cfg: c, members: ms, events: events, sel: c.selected}, nil
	}
	if h.probe == nil {
		h.probe = (&httpProber{url: c.url, target: c.target, tls: h.tls, clk: h.clk, expected: c.expected, head: c.head, unified: c.unified}).probe
	}
	return newAutoGroup(c, ms, events, h), nil
}

func emitSwitch(events outbound.EventSink, group, from, to string) {
	events.Emit("group_switch", "group", group, "from", from, "to", to)
}

func noMember(name, network string) error {
	return fmt.Errorf("group %q: no usable %s member: %w", name, network, outbound.ErrNoMember)
}

func isCanceled(ctx context.Context) bool { return errors.Is(ctx.Err(), context.Canceled) }

// clock abstracts time for tests.
type clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) (stop func() bool)
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) AfterFunc(d time.Duration, f func()) func() bool {
	return time.AfterFunc(d, f).Stop
}

// Display metadata is bounded and never fetched by a group runtime.
func ValidIcon(s string) bool {
	if s == "" {
		return true
	}
	if strings.HasPrefix(strings.TrimSpace(s), "<svg") {
		return len(s) <= 64<<10
	}
	if len(s) > 2048 {
		return false
	}
	u, e := url.Parse(s)
	return e == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil
}

// Clash's common negative lookahead is representable as an exclusion in RE2.
// The same normalization is used by import, runtime expansion and live preview.
func NormalizeFilters(filter, exclude string) (string, string) {
	if strings.HasPrefix(filter, "^(?!.*(") && strings.HasSuffix(filter, ")).*$") {
		body := strings.TrimSuffix(strings.TrimPrefix(filter, "^(?!.*("), ")).*$")
		if exclude != "" {
			exclude = "(?:" + exclude + ")|(?:" + body + ")"
		} else {
			exclude = body
		}
		filter = ".*"
	}
	return filter, exclude
}
