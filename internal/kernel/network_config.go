package kernel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

var errNetworkConfig = errors.New("invalid DNS or routing configuration")

type DNSOptions struct {
	Server       string   `json:"server,omitempty"`
	Servers      []string `json:"servers,omitempty"`
	CacheEntries *int     `json:"cache_entries,omitempty"`
}

// All new optional objects reject explicit null, unknown keys and null members.
func strictNetworkJSON(b []byte, v any) error {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil || m == nil {
		return errNetworkConfig
	}
	for _, v := range m {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return errNetworkConfig
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errNetworkConfig
	}
	return nil
}
func (c *Config) UnmarshalJSON(b []byte) error {
	type plain Config
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return errNetworkConfig
	}
	for k := range raw {
		for _, rem := range []string{"routing", "outbounds", "groups", "providers", "rule_sets", "geoip", "geosite", "asn"} {
			if strings.EqualFold(k, rem) {
				return removedConfigError{fmt.Sprintf("top-level field %q is not supported in Kat-Server (outbound proxies, policy groups, providers, routing rules and rule databases have been removed)", rem)}
			}
		}
	}
	if v, ok := raw["dns"]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
		return errNetworkConfig
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode((*plain)(c))
}
func (o *DNSOptions) UnmarshalJSON(b []byte) error {
	type plain DNSOptions
	var p plain
	if e := strictNetworkJSON(b, &p); e != nil {
		return e
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	if _, ok := m["server"]; ok && p.Server == "" {
		return errNetworkConfig
	}
	if _, ok := m["servers"]; ok {
		if _, both := m["server"]; both || len(p.Servers) == 0 {
			return errNetworkConfig
		}
	}
	if _, e := dnsEndpoints((*DNSOptions)(&p)); e != nil {
		return e
	}
	*o = DNSOptions(p)
	return nil
}
func dnsName(s string) (string, error) {
	s = strings.TrimSuffix(s, ".")
	if len(s) < 1 || len(s) > 253 {
		return "", errNetworkConfig
	}
	lower := true
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			label := s[start:i]
			if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", errNetworkConfig
			}
			start = i + 1
			continue
		}
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		case c >= 'A' && c <= 'Z':
			lower = false
		default:
			return "", errNetworkConfig
		}
	}
	if !lower {
		s = strings.ToLower(s)
	}
	return s, nil
}

type dnsEndpoint struct{ scheme, host, port, url string }

func parseDNS(s string) (dnsEndpoint, error) {
	if s == "" || s == "system" {
		return dnsEndpoint{scheme: "system"}, nil
	}
	scheme := "udp"
	authority := s
	path := ""
	if strings.Contains(s, "://") {
		u, e := url.Parse(s)
		if e != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") {
			return dnsEndpoint{}, errNetworkConfig
		}
		scheme = u.Scheme
		authority = u.Host
		path = u.EscapedPath()
		if scheme != "udp" && scheme != "tcp" && scheme != "https" {
			return dnsEndpoint{}, errNetworkConfig
		}
		if scheme == "https" {
			if path == "" || path[0] != '/' {
				return dnsEndpoint{}, errNetworkConfig
			}
		} else if path != "" {
			return dnsEndpoint{}, errNetworkConfig
		}
	}
	host := authority
	port := "53"
	if scheme == "https" {
		port = "443"
	}
	if ip, e := netip.ParseAddr(authority); e == nil {
		host = ip.String()
	} else if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		host = authority[1 : len(authority)-1]
	} else if strings.Contains(authority, ":") {
		h, p, e := net.SplitHostPort(authority)
		if e != nil {
			return dnsEndpoint{}, errNetworkConfig
		}
		host, port = h, p
	} else if strings.HasPrefix(authority, "[") {
		return dnsEndpoint{}, errNetworkConfig
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" {
			return dnsEndpoint{}, errNetworkConfig
		}
		host = ip.String()
	} else {
		h, e := dnsName(host)
		if e != nil {
			return dnsEndpoint{}, e
		}
		host = h
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return dnsEndpoint{}, errNetworkConfig
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return dnsEndpoint{}, errNetworkConfig
		}
	}
	ep := dnsEndpoint{scheme: scheme, host: host, port: strconv.Itoa(n)}
	if scheme == "https" {
		ep.url = "https://" + net.JoinHostPort(host, ep.port) + path
	}
	return ep, nil
}

const maxDNSServers = 16

// A nil list means explicit system-only DNS; an omitted block uses the defaults.
func dnsEndpoints(o *DNSOptions) ([]dnsEndpoint, error) {
	servers := []string{"udp://8.8.8.8:53", "udp://1.1.1.1:53"}
	if o != nil {
		if o.Server != "" && o.Servers != nil || o.Servers != nil && (len(o.Servers) == 0 || len(o.Servers) > maxDNSServers) {
			return nil, errNetworkConfig
		}
		if o.Server == "system" {
			return nil, nil
		}
		if o.Server != "" {
			servers = []string{o.Server}
		} else if o.Servers != nil {
			servers = o.Servers
		}
	}
	eps := make([]dnsEndpoint, 0, len(servers))
	for _, server := range servers {
		ep, e := parseDNS(server)
		if e != nil || ep.scheme == "system" {
			return nil, errNetworkConfig
		}
		eps = append(eps, ep)
	}
	return eps, nil
}

func cloneDNSOptions(o *DNSOptions) *DNSOptions {
	if o == nil {
		return nil
	}
	v := *o
	if o.Servers != nil {
		v.Servers = append([]string{}, o.Servers...)
	}
	if o.CacheEntries != nil {
		n := *o.CacheEntries
		v.CacheEntries = &n
	}
	return &v
}

func (c *Config) validateNetwork() error {
	eps, e := dnsEndpoints(c.DNS)
	if e != nil {
		return e
	}
	if c.DNS != nil && c.DNS.CacheEntries != nil {
		n := *c.DNS.CacheEntries
		if n < 0 || n > 4096 || len(eps) == 0 && n != 0 {
			return errNetworkConfig
		}
	}
	return nil
}
