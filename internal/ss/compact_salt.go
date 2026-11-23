package ss

import (
	"hash/maphash"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"
)

// Full salt bytes, never a truncated digest: hashing only chooses a chain.
// 32M entries cover >=61s * 2 *259375pps, with no early eviction. On-demand
// chunks avoid a multi-GiB cold allocation. ALL identities share a2GiB raw
// table budget; exhaustion fails closed. Cleanup returns budget only when an
// unreachable chunk is reclaimed, not while any server can still access it.
const default2017Salts = 32 * 1024 * 1024
const compactBudget = int64(2 << 30)
const compactChunkBits = 12
const compactChunkSize = 1 << compactChunkBits
const compactBucketBits = 23
const compactBucketCount = 1 << compactBucketBits

var compactRetained atomic.Int64

type compactEntry struct {
	salt    [32]byte
	expires int64
	order   uint32 // slot+1 in expiry FIFO, or next free slot when unused
	next    uint32 // slot+1; zero is end
}
type compactEntries struct {
	data [compactChunkSize]compactEntry
}
type compactBuckets struct {
	data [compactChunkSize]uint32
	live int
}

func reserveCompact(n int64) bool {
	for {
		old := compactRetained.Load()
		if old+n > compactBudget {
			return false
		}
		if compactRetained.CompareAndSwap(old, old+n) {
			return true
		}
	}
}
func releaseCompact(n int64) { compactRetained.Add(-n) }

type compactSaltStore struct {
	pages            []*compactEntries
	buckets          []*compactBuckets
	seed             maphash.Seed
	capacity, count  int
	head, last, tail uint32 // FIFO endpoints (zero based); tail is fresh-slot high water
	free             uint32 // slot+1
	spareBuckets     []*compactBuckets
	keyLen           int
	lastNow          int64
	epoch            time.Time
}

func (c *compactSaltStore) init(n int) { *c = compactSaltStore{capacity: n, seed: maphash.MakeSeed()} }
func (c *compactSaltStore) at(slot uint32) *compactEntry {
	return &c.pages[int(slot)>>compactChunkBits].data[int(slot)&(compactChunkSize-1)]
}
func (c *compactSaltStore) bucket(key []byte) uint32 {
	return uint32(maphash.Bytes(c.seed, key)) & (compactBucketCount - 1)
}
func (c *compactSaltStore) headAt(bucket uint32) *uint32 {
	page := int(bucket) >> compactChunkBits
	if page >= len(c.buckets) || c.buckets[page] == nil {
		return nil
	}
	return &c.buckets[page].data[int(bucket)&(compactChunkSize-1)]
}
func (c *compactSaltStore) expire(now time.Time) {
	ns := now.Sub(c.epoch).Nanoseconds()
	for c.count > 0 {
		e := c.at(c.head)
		if e.expires > ns {
			break
		}
		bucket := c.bucket(e.salt[:c.keyLen])
		b := c.headAt(bucket)
		id := c.head + 1
		for *b != id {
			b = &c.at(*b - 1).next
		}
		*b = e.next
		bp := int(bucket) >> compactChunkBits
		page := c.buckets[bp]
		page.live--
		if page.live == 0 {
			c.buckets[bp] = nil
			c.spareBuckets = append(c.spareBuckets, page)
		}
		next := e.order
		*e = compactEntry{order: c.free}
		c.free = id
		if next != 0 {
			c.head = next - 1
		}
		c.count--
	}
}
func (c *compactSaltStore) admit(salt []byte, now time.Time) error {
	if len(salt) != 16 && len(salt) != 32 {
		return ErrFormat
	}
	if c.keyLen != 0 && len(salt) != c.keyLen {
		return ErrFormat
	}
	c.expire(now)
	var key [32]byte
	copy(key[:], salt)
	bucket := c.bucket(salt)
	head := c.headAt(bucket)
	if head != nil {
		for id := *head; id != 0; id = c.at(id - 1).next {
			if c.at(id-1).salt == key {
				return ErrReplay
			}
		}
	}
	if c.count >= c.capacity {
		return ErrCapacity
	}
	if c.buckets == nil {
		c.buckets = make([]*compactBuckets, compactBucketCount/compactChunkSize)
	}
	bp := int(bucket) >> compactChunkBits
	if c.buckets[bp] == nil {
		if n := len(c.spareBuckets); n > 0 {
			c.buckets[bp] = c.spareBuckets[n-1]
			c.spareBuckets[n-1] = nil
			c.spareBuckets = c.spareBuckets[:n-1]
		} else {
			size := int64(unsafe.Sizeof(compactBuckets{}))
			if !reserveCompact(size) {
				return ErrCapacity
			}
			p := new(compactBuckets)
			runtime.AddCleanup(p, releaseCompact, size)
			c.buckets[bp] = p
		}
	}
	// Reuse an expired slot before advancing the physical high water. The
	// expiry FIFO is independent of slot order and of the logical capacity.
	slot := c.tail
	if c.free != 0 {
		slot = c.free - 1
	}
	if int(slot)>>compactChunkBits == len(c.pages) {
		size := int64(unsafe.Sizeof(compactEntries{}))
		if !reserveCompact(size) {
			if p := c.buckets[bp]; p.live == 0 {
				c.spareBuckets = append(c.spareBuckets, p)
				c.buckets[bp] = nil
			}
			return ErrCapacity
		}
		p := new(compactEntries)
		runtime.AddCleanup(p, releaseCompact, size)
		c.pages = append(c.pages, p)
	}
	head = c.headAt(bucket)
	e := c.at(slot)
	if c.free != 0 {
		c.free = e.order
	} else {
		c.tail++
	}
	if c.epoch.IsZero() {
		c.epoch = now
	}
	// Epoch/Sub retains Go monotonic time when supplied by time.Now.
	// Clamp backwards test/wall-clock steps rather than expire a later-inserted salt
	// too early; monotone expiry makes the insertion FIFO an exact expiry queue.
	ns := now.Sub(c.epoch).Nanoseconds()
	if ns < c.lastNow {
		ns = c.lastNow
	}
	c.lastNow = ns
	*e = compactEntry{salt: key, expires: ns + int64(replayTTL), next: *head}
	*head = slot + 1
	if c.count == 0 {
		c.head = slot
	} else {
		c.at(c.last).order = slot + 1
	}
	c.last = slot
	c.buckets[bp].live++
	c.keyLen = len(salt)
	c.count++
	return nil
}
