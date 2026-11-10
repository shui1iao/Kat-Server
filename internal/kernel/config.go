package kernel

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	A "github.com/shui1iao/Kat/internal/anytls"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("duration must be a string")
	}
	v, e := time.ParseDuration(s)
	if e != nil {
		return errors.New("invalid duration")
	}
	*d = Duration(v)
	return nil
}
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }
func (d Duration) value() time.Duration         { return time.Duration(d) }

type removedConfigError struct{ msg string }

func (e removedConfigError) Error() string { return e.msg }

type User struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func (u *User) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if e := json.Unmarshal(b, &m); e != nil {
		return e
	}
	for k := range m {
		for _, rem := range []string{"uuid", "flow"} {
			if strings.EqualFold(k, rem) {
				return removedConfigError{fmt.Sprintf("user field %q is not supported in Kat-Server (VLESS has been removed)", rem)}
			}
		}
	}
	type plain User
	var p plain
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&p); e != nil {
		return e
	}
	*u = User(p)
	return nil
}

type TLSConfig struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
	// 0.7.0 (Trojan/AnyTLS inbounds only, all optional): see tls_config.go.
	Certificates  []TLSCertFile `json:"certificates,omitempty"`
	Watch         bool          `json:"watch,omitempty"`
	WatchInterval Duration      `json:"watch_interval,omitempty"`
	ALPN          []string      `json:"alpn,omitempty"`
	MinVersion    string        `json:"min_version,omitempty"`
	MaxVersion    string        `json:"max_version,omitempty"`
	CipherSuites  []string      `json:"cipher_suites,omitempty"`
	ACME          *ACMEConfig   `json:"acme,omitempty"`
}
type Inbound struct {
	logIndex     int
	AnyTLS       *AnyTLSOptions `json:"anytls,omitempty"`
	anytlsAuth   *anyTLSAuthority
	anytlsServer *A.Server
	Protocol     string     `json:"protocol"`
	Listen       string     `json:"listen"`
	Users        []User     `json:"users,omitempty"`
	TLS          *TLSConfig `json:"tls,omitempty"`
	SS           *SSOptions `json:"ss,omitempty"`
	ssRuntime    *ssRuntime
	tlsConfig    *tls.Config
	TCPFastOpen  bool       `json:"tcp_fast_open,omitempty"`
	serverTLS    *serverTLS // Trojan/AnyTLS certificate sources (tls_config.go)
	// Codec configurations, compared by a reload to reuse identical codecs.
	anytlsConf A.Config
	// tlsWritten: the JSON object had a "tls" member (even null).
	// ephemeralTLS: tlsConfig holds a generated in-memory certificate.
	tlsWritten   bool
	ephemeralTLS bool
	// 0.7.0: source lists (all inbounds), Trojan fallback, SOCKS5 options.
	Sources           *SourceOptions `json:"sources,omitempty"`
	Fallback          string         `json:"fallback,omitempty"`
	SOCKS5            *SOCKS5Options `json:"socks5,omitempty"`
	srcAllow, srcDeny []netip.Prefix
	// anytlsSessionsAuto is the max_sessions value Validate derived from
	// limits.connections for an omitted/0 AnyTLS max_sessions (0 = written
	// explicitly). Like Limits.logicalAuto, re-validation derives it again.
	anytlsSessionsAuto int

	Name string `json:"name,omitempty"`
}
type Limits struct {
	LogicalStreams   int      `json:"logical_streams"`
	Connections      int      `json:"connections"`
	Handshakes       int      `json:"handshakes"`
	Dials            int      `json:"dials"`
	UDPAssociations  int      `json:"udp_associations"`
	UDPQueueBytes    int      `json:"udp_queue_bytes"`
	UDPQueue         int      `json:"udp_queue"`
	UDPTargets       int      `json:"udp_targets"`
	BufferSize       int      `json:"buffer_size"`
	PoolBuffers      int      `json:"pool_buffers"`
	HandshakeTimeout Duration `json:"handshake_timeout"`
	DialTimeout      Duration `json:"dial_timeout"`
	DrainTimeout     Duration `json:"drain_timeout"`
	TCPIdle          Duration `json:"tcp_idle"`
	UDPIdle          Duration `json:"udp_idle"`
	DisableFastPath  bool     `json:"disable_fast_path"`
	UDPFragmentBytes int      `json:"udp_fragment_bytes,omitempty"` // 0.7.0: SOCKS5 UDP reassembly, all associations
	// logicalAuto is the value Validate derived for an omitted/0
	// logical_streams (0 = written explicitly). While LogicalStreams still
	// holds that value, re-validation recomputes it as
	// max(defaultLogicalStreams, sum of AnyTLS identity max_streams).
	logicalAuto int
}

// Defaults sized for several users with Surge/mihomo/sing-box clients that
// open one AnyTLS session (or one TCP connection) per concurrent request.
// All values remain hard bounded and explicit values keep 0.6.1 semantics.
const (
	defaultConnections     = 4096
	defaultLogicalStreams  = 8192
	defaultHandshakes      = 512
	defaultDials           = 512
	defaultUDPAssociations = 1024
	defaultUDPTargets      = 256
	maxResourceCount       = 65536
)

type Config struct {
	DNS         *DNSOptions `json:"dns,omitempty"`
	UDPBindIPv4 string      `json:"udp_bind_ipv4,omitempty"`
	UDPBindIPv6 string      `json:"udp_bind_ipv6,omitempty"`
	Inbounds    []Inbound   `json:"inbounds"`
	Limits      Limits      `json:"limits"`

	raw      []byte
	defaults [2]string
	stateDir string // default ACME storage root

	// Runtime (0.7.0, all optional).
	Log      *LogOptions      `json:"log,omitempty"`
	Stats    *StatsOptions    `json:"stats,omitempty"`
	API      *APIOptions      `json:"api,omitempty"`
	Security *SecurityOptions `json:"security,omitempty"`

	// 0.7.0: built-in direct outbound options (optional).
	Direct *DirectOptions `json:"direct,omitempty"`
}

func Load(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, errors.New("cannot open configuration")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return c, errors.New("configuration exceeds 1 MiB or cannot be read")
	}
	return decodeConfig(b)
}

func decodeConfig(b []byte) (Config, error) {
	var c Config
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&c); e != nil {
		var re removedConfigError
		if errors.As(e, &re) {
			return c, re
		}
		return c, errors.New("invalid configuration JSON or unknown field")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return c, errors.New("trailing configuration data")
	}
	c.raw = append([]byte(nil), b...)
	return c, c.Validate()
}
func validInboundName(s string) bool {
	if len(s) == 0 || len(s) > 64 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (c *Config) validateInboundNames() error {
	names := map[string]bool{}
	for i := range c.Inbounds {
		in := &c.Inbounds[i]
		if in.Name != "" {
			if !validInboundName(in.Name) || names[in.Name] {
				return fmt.Errorf("inbound %d: invalid or duplicate name", i)
			}
			names[in.Name] = true
		}
	}
	return nil
}

func (c *Config) Validate() error {
	if e := c.validateNetwork(); e != nil {
		return e
	}
	if e := c.validateInboundNames(); e != nil {
		return e
	}
	if e := c.validateRuntime(); e != nil {
		return e
	}
	for _, b := range []struct {
		value string
		v4    bool
	}{{c.UDPBindIPv4, true}, {c.UDPBindIPv6, false}} {
		if b.value != "" {
			ip := net.ParseIP(b.value)
			if ip == nil || (ip.To4() != nil) != b.v4 {
				return errors.New("invalid UDP bind address family")
			}
		}
	}
	l := &c.Limits
	def := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	logicalAuto := l.LogicalStreams == 0 || (l.logicalAuto != 0 && l.LogicalStreams == l.logicalAuto)
	l.logicalAuto = 0
	if logicalAuto {
		// Raised below to cover all AnyTLS identity worker budgets.
		l.LogicalStreams = defaultLogicalStreams
		l.logicalAuto = l.LogicalStreams
	}
	def(&l.Connections, defaultConnections)
	def(&l.Handshakes, defaultHandshakes)
	def(&l.Dials, defaultDials)
	def(&l.UDPAssociations, defaultUDPAssociations)
	def(&l.UDPQueue, 16)
	def(&l.UDPQueueBytes, l.UDPQueue*maxDatagram)
	def(&l.UDPTargets, defaultUDPTargets)
	def(&l.BufferSize, 16384)
	def(&l.PoolBuffers, 128)
	dd := func(p *Duration, v time.Duration) {
		if *p == 0 {
			*p = Duration(v)
		}
	}
	dd(&l.HandshakeTimeout, 10*time.Second)
	dd(&l.DialTimeout, 5*time.Second)
	dd(&l.DrainTimeout, 5*time.Second)
	dd(&l.UDPIdle, 60*time.Second)

	for _, v := range []int{l.Connections, l.LogicalStreams, l.Handshakes, l.Dials, l.UDPAssociations, l.PoolBuffers} {
		if v < 1 || v > maxResourceCount {
			return errors.New("resource count must be between 1 and 65536")
		}
	}
	if l.UDPQueueBytes < 1 || l.UDPQueueBytes > 256*maxDatagram {
		return errors.New("invalid UDP queue byte budget")
	}
	if l.UDPQueue < 1 || l.UDPQueue > 256 || l.UDPTargets < 1 || l.UDPTargets > 1024 || l.BufferSize < 1024 || l.BufferSize > 65536 {
		return errors.New("invalid queue, target or buffer limit")
	}
	for _, v := range []Duration{l.HandshakeTimeout, l.DialTimeout, l.DrainTimeout, l.UDPIdle} {
		if v.value() < time.Millisecond || v.value() > 24*time.Hour {
			return errors.New("timeouts must be between 1ms and 24h")
		}
	}
	if l.TCPIdle < 0 || l.TCPIdle.value() > 24*time.Hour {
		return errors.New("invalid TCP idle timeout (0 disables for non-Snell)")
	}
	if len(c.Inbounds) == 0 || len(c.Inbounds) > 64 {
		return errors.New("need 1..64 inbounds")
	}
	for i := range c.Inbounds {
		in := &c.Inbounds[i]
		host, _, e := net.SplitHostPort(in.Listen)
		if e != nil {
			return fmt.Errorf("inbound %d: invalid listen address", i)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("inbound %d: listen host must be a literal IP", i)
		}
		a, e := net.ResolveTCPAddr("tcp", in.Listen)
		if e != nil || a.Port < 0 {
			return fmt.Errorf("inbound %d: invalid listen port", i)
		}
		if len(in.Users) > 1024 {
			return errors.New("too many users")
		}
		if in.Protocol != "shadowsocks" && in.SS != nil {
			return errors.New("protocol options do not match inbound")
		}
		if in.Protocol != "anytls" && in.AnyTLS != nil {
			return errors.New("AnyTLS options do not match protocol")
		}
		switch in.Protocol {
		case "anytls":
			// Omitted "tls" = ephemeral certificate; a written but null "tls" stays an error.
			if (in.TLS == nil && in.tlsWritten) || len(in.Users) != 0 {
				return errors.New("AnyTLS requires TLS and single password options")
			}
			// An omitted max_sessions follows limits.connections. While the
			// options still hold the derived value, re-validation (as Start
			// does) derives it again from the current connections.
			if o := in.AnyTLS; o != nil && in.anytlsSessionsAuto != 0 && o.MaxSessions == in.anytlsSessionsAuto {
				o.MaxSessions = 0
			}
			sessionsAuto := in.AnyTLS != nil && in.AnyTLS.MaxSessions == 0
			in.anytlsSessionsAuto = 0
			if e := in.AnyTLS.normalize(l.Connections); e != nil {
				return e
			}
			if sessionsAuto {
				in.anytlsSessionsAuto = in.AnyTLS.MaxSessions
			}
		case "shadowsocks":
			if in.TLS != nil || len(in.Users) != 0 {
				return errors.New("SS uses its own encrypted transport and single identity")
			}
			if in.SS == nil {
				return errors.New("SS options required")
			}
			if e := in.SS.validate(); e != nil {
				return e
			}
		case "socks5":
			if len(in.Users) == 0 && !ip.IsLoopback() {
				return errors.New("non-loopback SOCKS5 requires users")
			}
			if in.TLS != nil {
				return errors.New("SOCKS5 TLS wrapper is not implemented")
			}
			seen := map[string]bool{}
			for _, u := range in.Users {
				if len(u.Username) < 1 || len(u.Username) > 255 || len(u.Password) < 1 || len(u.Password) > 255 || seen[u.Username] {
					return errors.New("invalid or duplicate SOCKS5 user")
				}
				seen[u.Username] = true
			}
		case "trojan":
			if in.TLS == nil || len(in.Users) == 0 {
				return errors.New("Trojan requires TLS and password users")
			}
			seen := map[string]bool{}
			for _, u := range in.Users {
				if u.Password == "" || len(u.Password) > 4096 || u.Username != "" || seen[u.Password] {
					return errors.New("invalid or duplicate Trojan credential")
				}
				seen[u.Password] = true
			}
		case "vless", "snell", "http":
			return fmt.Errorf("inbound protocol %q is not supported in Kat-Server (supported: shadowsocks, anytls, trojan, socks5)", in.Protocol)
		default:
			return errors.New("unsupported inbound protocol")
		}
		if in.TLS != nil && (in.Protocol == "trojan" || in.Protocol == "anytls") {
			if e := in.validateServerTLS(); e != nil {
				return e
			}
		} else if in.Protocol == "anytls" && !in.ephemeralTLS {
			// One certificate per loaded configuration: Start re-validating
			// the same Config keeps it; every new Load generates a new one.
			cfg, e := ephemeralTLSConfig(time.Now())
			if e != nil {
				return errors.New("cannot generate TLS certificate")
			}
			in.tlsConfig, in.ephemeralTLS = cfg, true
		}
	}
	if e := c.validateSecurity(); e != nil {
		return e
	}
	seenAny := map[string]AnyTLSOptions{}
	seenSS := map[string]SSOptions{}
	for _, in := range c.Inbounds {
		if in.AnyTLS != nil {
			if old, ok := seenAny[in.AnyTLS.Password]; ok && old != *in.AnyTLS {
				return errors.New("same AnyTLS identity has conflicting limits or padding scheme")
			}
			seenAny[in.AnyTLS.Password] = *in.AnyTLS
		}
		if in.SS != nil {
			id, _ := in.SS.identity()
			if prev, ok := seenSS[id]; ok && prev.protection() != in.SS.protection() {
				return errors.New("same SS identity has conflicting settings")
			}
			seenSS[id] = *in.SS
		}
	}
	totalAnyWorkers := 0
	for _, o := range seenAny {
		totalAnyWorkers += o.MaxStreams
	}
	if logicalAuto && totalAnyWorkers > l.LogicalStreams {
		if totalAnyWorkers > maxResourceCount {
			return errors.New("AnyTLS identity worker budgets exceed the 65536 logical_streams maximum; set explicit max_streams per identity")
		}
		l.LogicalStreams = totalAnyWorkers
		l.logicalAuto = l.LogicalStreams
	}
	if totalAnyWorkers > l.LogicalStreams {
		return errors.New("AnyTLS identity worker budgets exceed logical_streams; allocate explicit bounded identity quotas")
	}
	return nil
}
