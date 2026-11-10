package kernel

import (
	"errors"
	"time"

	"github.com/shui1iao/Kat/internal/stats"
)

// ---- instance state files ----
//
// The statistics file lives in the state directory and uses an instance lock
// (<stats file>.lock):
//   <name>.stats.json   cumulative traffic (stats.persist)

// openState takes the instance lock before the first generation is prepared.
// Problems only warn.
func (k *core) openState(c *Config) {
	if c.Stats == nil || c.Stats.File == "" {
		return
	}
	path := c.Stats.File
	release, e := stats.Lock(path)
	switch {
	case errors.Is(e, stats.ErrLocked):
		k.notice(levelWarn, "kat event=stats_persist_disabled reason=file_in_use file="+eventToken(path, 256))
		return
	case e != nil:
		k.notice(levelWarn, "kat event=stats_persist_disabled reason=lock_failed file="+eventToken(path, 256))
		return
	}
	k.statsMu.Lock()
	k.statsRelease = release
	k.lockedFile = path
	k.statsMu.Unlock()
}

// loadStats loads persisted counters into the (already keyed) registry.
func (k *core) loadStats(c *Config) {
	k.statsMu.Lock()
	defer k.statsMu.Unlock()
	if !c.persistStats() || k.lockedFile != c.Stats.File {
		return
	}
	path := c.Stats.File
	if e := k.reg.Load(path); errors.Is(e, stats.ErrCorrupt) {
		moved, _ := stats.QuarantineCorrupt(path, time.Now())
		k.notice(levelWarn, "kat event=stats_load_failed reason=corrupt action=start_from_zero moved_to="+eventToken(moved, 300))
		k.statsPath = path
	} else if e != nil {
		k.notice(levelWarn, "kat event=stats_persist_disabled reason=load_failed file="+eventToken(path, 256))
	} else {
		k.statsPath = path
	}
}

func (k *core) releaseStatsLock() {
	k.statsMu.Lock()
	defer k.statsMu.Unlock()
	if k.statsRelease != nil {
		k.statsRelease()
		k.statsRelease = nil
	}
}

// startStats loads persisted counters (when configured) and starts the rate
// sampler and periodic saver. Persistence problems only warn.
func (k *core) startStats(c *Config) {
	k.loadStats(c)
	k.saveInterval.Store(int64(c.statsSaveInterval()))
	k.bgStop, k.bgDone = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(k.bgDone)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		last := time.Now()
		k.reg.Sample(last)
		for {
			select {
			case <-k.bgStop:
				return
			case now := <-tick.C:
				k.reg.Sample(now)
				if now.Sub(last) >= time.Duration(k.saveInterval.Load()) {
					last = now
					k.saveStats()
				}
			}
		}
	}()
}

// saveStats persists the counters; failures warn and never affect forwarding.
func (k *core) saveStats() error {
	k.saveMu.Lock()
	defer k.saveMu.Unlock()
	return k.saveStatsLocked()
}

// Caller holds saveMu; state paths cannot change until the write completes.
func (k *core) saveStatsLocked() error {
	k.statsMu.Lock()
	path := k.statsPath
	k.statsMu.Unlock()
	if path == "" {
		return nil
	}
	e := k.reg.Save(path, time.Now())
	k.lastSave.Store(time.Now().UnixNano())
	if e != nil {
		k.saveErrors.Add(1)
		k.notice(levelWarn, "kat event=stats_save_failed reason=io file="+eventToken(path, 256))
		return e
	}
	k.notice(levelDebug, "kat event=stats_saved")
	return nil
}

// stopStats stops the background loop, saves once more and releases the lock.
func (k *core) stopStats() {
	if k.bgStop == nil {
		k.releaseStatsLock()
		return
	}
	k.stopOnce.Do(func() {
		close(k.bgStop)
		<-k.bgDone
		k.saveStats()
		k.releaseStatsLock()
	})
}

func (k *core) persistedPath() string {
	k.statsMu.Lock()
	defer k.statsMu.Unlock()
	return k.statsPath
}
