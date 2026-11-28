package stats

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func TestCounterCacheLineIsolationAndPersistenceCompatibility(t *testing.T) {
	if sz := unsafe.Sizeof(Counter{}); sz < 128 {
		t.Fatalf("expected Counter to span two 64B cache lines (>=128B), got %dB", sz)
	}
	var c Counter
	if off := unsafe.Offsetof(c.down) - unsafe.Offsetof(c.up); off < 64 {
		t.Fatalf("expected up and down to be separated by >=64B, got %dB", off)
	}

	now := time.Unix(1730000000, 0).UTC()
	reg := New([]string{"in-a"}, []string{"direct"}, []string{"rule-1"}, now)
	reg.Total.AddUp(100)
	reg.Total.AddDown(200)
	reg.Inbound("in-a").AddUp(100)
	reg.Inbound("in-a").AddDown(200)

	snapBytes, err := json.Marshal(reg.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(snapBytes), ":null") {
		t.Fatalf("Snapshot JSON contains null slice: %s", string(snapBytes))
	}

	stateFile := filepath.Join(t.TempDir(), "kat.stats.json")
	if err := reg.Save(stateFile, now); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reg2 := New([]string{"in-a"}, []string{"direct"}, []string{"rule-1"}, now)
	if err := reg2.Load(stateFile); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := reg2.Total.Load(); got.Up != 100 || got.Down != 200 {
		t.Fatalf("loaded Total mismatch: %+v", got)
	}
}

func BenchmarkPerfCompareStatsCounterParallel(b *testing.B) {
	var c Counter
	var seq atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		isUp := seq.Add(1)%2 == 0
		for pb.Next() {
			if isUp {
				c.AddUp(1024)
			} else {
				c.AddDown(1024)
			}
		}
	})
}
