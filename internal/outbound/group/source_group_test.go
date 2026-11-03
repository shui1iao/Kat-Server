package group

import (
	"encoding/json"
	"testing"
)

func TestSourceGroupOptionsRoundTripAndValidation(t *testing.T) {
	var o Options
	if e := json.Unmarshal([]byte(`{"name":"target","type":"select","include_group":"source","filter":""}`), &o); e != nil {
		t.Fatal(e)
	}
	if o.IncludeGroup != "source" || !o.Dynamic() {
		t.Fatal(o)
	}
	if e := Validate(o); e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	var next Options
	if e := json.Unmarshal(b, &next); e != nil || next.IncludeGroup != "source" {
		t.Fatal(string(b), e)
	}
	o.Type = TypeRelay
	o.Members = []string{"node"}
	if e := Validate(o); e == nil {
		t.Fatal("relay accepted dynamic source")
	}
	o = Options{Name: "legacy", Type: TypeSelect, Members: []string{"direct"}}
	if o.Dynamic() {
		t.Fatal("legacy static group became dynamic")
	}
	if e := Validate(o); e != nil {
		t.Fatal(e)
	}
}
