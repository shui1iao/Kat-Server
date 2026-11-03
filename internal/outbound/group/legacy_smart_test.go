package group

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRestoredSmartOptionsPreserveExplicitAndDynamic(t *testing.T) {
	const old = `{"name":"same","type":"smart","members":["a","b"],"use":["p"],"include_group":"source","include_all":true,"include_all_proxies":true,"include_all_providers":true,"filter":"a|b","exclude_filter":"gone","exclude_type":"socks5","fixed":"a","priority":{"a":1.5,"temporarily-absent":0.5},"probe":{"url":"https://probe.invalid/custom","timeout":"9s","expected_status":"204"},"tolerance":0,"damping":{"relative_improvement":0,"confirm_rounds":3,"min_dwell":"0s"},"smart":{"scope":"site","exploration_rate":0.02,"adaptive_dial":false}}`
	var o Options
	if e := json.Unmarshal([]byte(old), &o); e != nil {
		t.Fatal(e)
	}
	if o.Type != TypeSmart || o.Name != "same" || o.Fixed != "a" || o.Priority["temporarily-absent"] != .5 {
		t.Fatal(o)
	}
	c, e := normalize(o)
	if e != nil || c.interval != 5*time.Minute || c.timeout != 9*time.Second || c.tolerance != 0 || c.relative != 0 || c.dwell != 0 || c.confirms != 3 {
		t.Fatal(c, e)
	}
	out, e := json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	var a, b map[string]json.RawMessage
	_ = json.Unmarshal([]byte(old), &a)
	_ = json.Unmarshal(out, &b)
	// Numeric zero and explicit duration zero have identical preserved semantics.
	delete(a, "tolerance")
	delete(b, "tolerance")
	var va, vb any
	_ = json.Unmarshal(mustJSON(a), &va)
	_ = json.Unmarshal(mustJSON(b), &vb)
	if !reflect.DeepEqual(va, vb) {
		t.Fatal("non-Smart fields changed", string(out))
	}
	o.Members = []string{"b", "temporarily-absent", "a"}
	o.Expanded = true
	c, e = normalize(o)
	if e != nil || !reflect.DeepEqual(c.priority, []float64{1, .5, 1.5}) {
		t.Fatal(c.priority, e)
	}
	o.Members = []string{"a", "b"}
	g := newAuto(t, o, members(newFake("a"), newFake("b")), newFakeClock(), nil, nil)
	if g.Type() != TypeSmart || g.Snapshot().Type != TypeSmart {
		t.Fatal("Smart runtime missing")
	}
	// A directly constructed runtime type is not a new/alternate Smart entry.
	if Validate(Options{Name: "g", Type: "smart", Members: []string{"a"}, Probe: probeOpts()}) != nil {
		t.Fatal("native Smart runtime rejected")
	}
	for _, interval := range []string{"0s", "7m"} {
		var v Options
		input := strings.Replace(old, `"timeout":"9s"`, `"interval":"`+interval+`","timeout":"9s"`, 1)
		if e := json.Unmarshal([]byte(input), &v); e != nil {
			t.Fatal(e)
		}
		cc, e := normalize(v)
		want := 5 * time.Minute
		if interval == "7m" {
			want = 7 * time.Minute
		}
		if e != nil || cc.interval != want {
			t.Fatal(interval, cc, e)
		}
	}
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func TestRestoredSmartInvalidStillRejected(t *testing.T) {
	base := `{"name":"g","type":"smart","members":["a"],"probe":{"url":"http://probe.invalid/"}}`
	for _, extra := range []string{`,"smart":{"unknown":true}`, `,"smart":{"scope":"other"}`, `,"smart":{"exploration_rate":0.1}`, `,"smart":{"adaptive_dial":"yes"}`, `,"unknown":true`, `,"max_failed_times":3`, `,"priority":{"a":0}`} {
		var o Options
		e := json.Unmarshal([]byte(strings.TrimSuffix(base, "}")+extra+"}"), &o)
		if e == nil {
			e = Validate(o)
		}
		if e == nil {
			t.Fatal("invalid accepted", extra)
		}
	}
	var o Options
	if json.Unmarshal([]byte(strings.Replace(base, `"smart"`, `"url-test"`, 1)[:len(base)-3]), &o) == nil {
		t.Fatal("invalid JSON accepted")
	}
}
func TestNoSmartFallbackFixedRemainsHealthyFirst(t *testing.T) {
	c := newFakeClock()
	g := newAuto(t, Options{Type: TypeFallback, Fixed: "b"}, members(newFake("a"), newFake("b")), c, nil, nil)
	v2Round(g, c, 10*time.Millisecond, 30*time.Millisecond)
	if g.Current() != "b" || g.Snapshot().Current != "b" {
		t.Fatal("healthy fixed ignored")
	}
	c.Advance(time.Second)
	g.RecordProbe("b", 0, c.Now(), errors.New("down"))
	if g.Current() != "b" {
		t.Fatal("partial sample changed fixed preference")
	}
	acceptedFallbackFailure(t, g, c, "b")
	if g.Current() != "a" || g.Snapshot().Fixed != "b" {
		t.Fatal("soft fixed lost")
	}
	for _, d := range []time.Duration{time.Second, 5 * time.Second, 5 * time.Second} {
		c.Advance(d)
		g.RecordProbe("b", 30*time.Millisecond, c.Now(), nil)
	}
	if g.Current() != "b" {
		t.Fatal("fixed did not recover")
	}
	if e := g.SetFixed(""); e != nil {
		t.Fatal(e)
	}
	if g.Current() != "a" {
		t.Fatal("automatic fallback order changed")
	}
}
