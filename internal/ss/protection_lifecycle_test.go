package ss

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestCompactRollingPhysicalHighWater(t *testing.T) {
	var c compactSaltStore
	c.init(default2017Salts)
	// Continually overlapping lifetimes, never empty after startup: resetting
	// only an empty FIFO would not fix this case. Cross many former slot pages.
	const live = 61
	for i := 0; i < compactChunkSize*4; i++ {
		now := testTime.Add(time.Duration(i) * time.Second)
		if err := c.admit(compactKey(uint64(i), 16), now); err != nil {
			t.Fatal(i, err)
		}
		if i >= live {
			if err := c.admit(compactKey(uint64(i-live+1), 16), now); err != ErrReplay {
				t.Fatalf("lost unexpired oldest salt at %d: %v", i, err)
			}
		}
	}
	pages := len(c.spareBuckets)
	for _, p := range c.buckets {
		if p != nil {
			pages++
		}
	}
	if c.count != live || c.tail != live || len(c.pages) != 1 || pages > live {
		t.Fatalf("live=%d fresh slots=%d entry pages=%d bucket pages=%d", c.count, c.tail, len(c.pages), pages)
	}
}

func TestProtectionShrinkDoesNotEvictLiveEntries(t *testing.T) {
	s := server(t, AES128GCM)
	now := testTime
	for i := 0; i < 3; i++ {
		salt := compactKey(uint64(i), 16)
		if e := s.tcpSalts.admit(salt, now); e != nil {
			t.Fatal(e)
		}
		if e := s.oldSalts.admit(salt, now); e != nil {
			t.Fatal(e)
		}
	}
	smaller, e := (Config{MaxTCPSalts: 1, Max2017Salts: 1, MaxUDPSessions: 1}).ProtectionLimits()
	if e != nil {
		t.Fatal(e)
	}
	s.ApplyProtection(smaller)
	for _, admit := range []func([]byte, time.Time) error{s.tcpSalts.admit, s.oldSalts.admit} {
		for i := 0; i < 3; i++ {
			if e := admit(compactKey(uint64(i), 16), now); e != ErrReplay {
				t.Fatal("live salt lost", e)
			}
		}
		if e := admit(compactKey(4, 16), now); e != ErrCapacity {
			t.Fatal("admitted over shrunken capacity", e)
		}
		now2 := now.Add(replayTTL)
		if e := admit(compactKey(5, 16), now2); e != nil {
			t.Fatal(e)
		}
		if e := admit(compactKey(6, 16), now2); e != ErrCapacity {
			t.Fatal("new limit not enforced after expiry", e)
		}
	}
}

func TestProtectionUDPActiveRetention(t *testing.T) {
	s, clock := idleServer(t, AES128GCM2022, 4*time.Minute)
	req := func(id, pid uint64) (*Packet, error) {
		return s.DecodeUDP(udpRequest(t, s, id, pid, uint64(s.now().Unix()), testTarget, nil), testPeer)
	}
	p, e := req(10, 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = req(11, 1); e != nil {
		t.Fatal(e)
	}
	policy, e := (Config{MaxUDPSessions: 1, UDPIdle: time.Second}).ProtectionLimits()
	if e != nil {
		t.Fatal(e)
	}
	s.ApplyProtection(policy)
	if _, e = req(12, 1); e != ErrCapacity {
		t.Fatal(e)
	}
	if _, e = req(10, 1); e != ErrReplay {
		t.Fatal(e)
	}
	if _, _, e = s.EncodeUDP(p, testTarget, nil); e != nil {
		t.Fatal("old capability lost", e)
	}
	clock.Add(int64(2 * time.Minute))
	q, e := req(10, 2)
	if e != nil || q.session != p.session || q.session.nextPacket != 1 {
		t.Fatal("old active association reset", e)
	}
	clock.Add(int64(4 * time.Minute))
	n, e := req(12, 1)
	if e != nil || n.session.expires.Sub(s.now()) != replayTTL {
		t.Fatal("new session did not take new idle", e)
	}
	if _, _, e = s.EncodeUDP(p, testTarget, nil); e != ErrSessionExpired {
		t.Fatal(e)
	}
}

func TestAESUDPActiveIDsDisjoint(t *testing.T) {
	for _, name := range []string{AES128GCM2022, AES256GCM2022} {
		t.Run(name, func(t *testing.T) {
			s := server(t, name)
			var ids []byte
			for _, n := range []uint64{31, 11, 31, 22, 32} {
				ids = binary.BigEndian.AppendUint64(ids, n)
			}
			s.random = bytes.NewReader(ids)
			req := func(id uint64) (*Packet, error) {
				return s.DecodeUDP(udpRequest(t, s, id, 1, uint64(testTime.Unix()), testTarget, nil), testPeer)
			}
			a, e := req(11)
			if e != nil || a.session.serverID != 31 {
				t.Fatal(e)
			}
			if _, e = req(31); !errors.Is(e, ErrReplay) || len(s.udp.entries) != 1 {
				t.Fatal("accepted live outbound ID as client ID", e)
			}
			b, e := req(22)
			if e != nil || b.session.serverID != 32 {
				t.Fatal("did not exclude live incoming/outgoing/self IDs", e)
			}
			for id := range s.udp.entries {
				if s.udp.serverIDs[id] {
					t.Fatal("overlapping active IDs")
				}
			}
		})
	}
}
