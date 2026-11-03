package provider

import (
	"strings"
	"testing"
)

const closureFixture = `proxies:
 - {name: "前置 A", type: ss, server: 127.0.0.1, port: 1234, cipher: aes-128-gcm, password: fixture, udp: true}
 - {name: "后置 B", type: ss, server: 127.0.0.1, port: 2345, cipher: 2022-blake3-aes-128-gcm, password: QUFBQUFBQUFBQUFBQUFBQQ==, udp: true, dialer-proxy: 前置组}
proxy-groups:
 - {name: 前置组, type: url-test, include-all: true, filter: "^前置"}
 - {name: 无关组, type: select, proxies: [not-a-node]}
rules: [nonsense]
`

func TestDependencyClosureMaterialization(t *testing.T) {
	r, e := Parse([]byte(closureFixture), FormatAuto)
	if e != nil || len(r.Nodes) != 2 || len(r.DependencyGroups) != 1 || len(r.DependencyGroups[0].Members) != 1 {
		t.Fatal("closure")
	}
	if _, _, _, e = r.Materialize("p", "", nil, nil); e == nil {
		t.Fatal("missing fallback accepted")
	}
	taken := map[string]bool{"前置组": true}
	os, gs, roots, e := r.Materialize("p", "https://example.com/", taken, func(n, typ string) bool { return strings.HasPrefix(n, "后置") })
	if e != nil || len(os) != 2 || len(gs) != 1 || len(roots) != 1 || os[1].Via != gs[0].Name || gs[0].Members[0] != os[0].Name || roots[0] != os[1].Name {
		t.Fatal("filtered closure or mapping")
	}
	if strings.Contains(os[0].Name, " ") || len(os[0].Name) > 64 || !strings.Contains(os[0].Name, "前置") {
		t.Fatal("alias")
	}
	os2, _, _, e := r.Materialize("other", "https://example.com/", taken, nil)
	if e != nil || os[0].Name == os2[0].Name {
		t.Fatal("namespace")
	}
	if r.Nodes[1].Options.Via != "前置组" || r.DependencyGroups[0].Probe.URL != "" {
		t.Fatal("snapshot mutated")
	}
	explicit := strings.Replace(closureFixture, "filter: \"^前置\"", "filter: \"^前置\", url: https://example.org/", 1)
	r, e = Parse([]byte(explicit), FormatAuto)
	if e != nil {
		t.Fatal("explicit")
	}
	_, gs, _, e = r.Materialize("", "https://example.com/", nil, nil)
	if e != nil || gs[0].Probe.URL != "https://example.org/" {
		t.Fatal("explicit URL overwritten")
	}
}
func TestDependencyFailuresNeverDropVia(t *testing.T) {
	for _, bad := range []string{
		strings.Replace(closureFixture, "dialer-proxy: 前置组", "dialer-proxy: missing", 1),
		strings.Replace(closureFixture, "filter: \"^前置\"", "filter: \"^前置\", url: null", 1),
		strings.Replace(closureFixture, "filter: \"^前置\"", "filter: \"^前置\", url: ''", 1),
		strings.Replace(closureFixture, "filter: \"^前置\"", "filter: \".*\"", 1),
		strings.Replace(closureFixture, "type: url-test", "type: select", 1),
		strings.Replace(closureFixture, "filter: \"^前置\"", "filter: \"nomatch\"", 1),
		strings.Replace(closureFixture, "name: \"后置 B\"", "name: \"前置 A\"", 1),
		strings.Replace(closureFixture, "filter: \"^前置\"", "proxies: [missing]", 1),
	} {
		if _, e := Parse([]byte(bad), FormatAuto); e == nil {
			t.Fatal("broken graph accepted")
		}
	}
}
