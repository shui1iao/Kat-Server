package ss

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"testing"
	"time"
)

func TestReplayWindowAndSaltBoundaries(t *testing.T) {
	// 1. packetWindow edge cases: 0, duplicate 0, jump 64, jump 65, jump 1024, uint64 max wraparound!
	var w packetWindow
	if !w.accept(0) {
		t.Fatal("packetWindow rejected initial seq 0")
	}
	if w.accept(0) {
		t.Fatal("packetWindow accepted duplicate seq 0")
	}
	for _, seq := range []uint64{64, 65, 128} {
		if !w.accept(seq) || w.accept(seq) {
			t.Fatalf("packetWindow failed at seq %d", seq)
		}
	}
	if !w.accept(1) || w.accept(1) {
		t.Fatal("packetWindow failed out-of-order seq 1 within 1024 window")
	}
	if !w.accept(128 + udpWindowSize) {
		t.Fatal("packetWindow rejected +1024 jump")
	}
	if w.accept(128) {
		t.Fatal("packetWindow accepted expired seq 128 at exact window boundary")
	}
	if !w.accept(129) {
		t.Fatal("packetWindow rejected seq 129 inside window [129..1152]")
	}

	var wMax packetWindow
	if !wMax.accept(math.MaxUint64-1) || !wMax.accept(math.MaxUint64) {
		t.Fatal("packetWindow rejected MaxUint64")
	}
	if wMax.accept(0) || wMax.accept(math.MaxUint64) {
		t.Fatal("packetWindow accepted wraparound 0 or duplicate MaxUint64")
	}

	// 2. saltStore expiry boundary: exact timestamp vs -1ns, and capacity fail-closed!
	var st saltStore
	st.init(4)
	t0 := time.Unix(1700000000, 0)
	for i := 0; i < 4; i++ {
		var s [16]byte
		s[0] = byte(i + 1)
		if err := st.admit(s[:], t0); err != nil {
			t.Fatalf("admit %d: %v", i, err)
		}
	}
	if err := st.admit([]byte("5555555555555555"), t0.Add(replayTTL-time.Nanosecond)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("expected ErrCapacity before TTL, got %v", err)
	}
	var s1 [16]byte
	s1[0] = 1
	if err := st.admit(s1[:], t0.Add(replayTTL-time.Nanosecond)); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay 1ns before expiry, got %v", err)
	}
	if err := st.admit([]byte("5555555555555555"), t0.Add(replayTTL)); err != nil {
		t.Fatalf("expected admit at exact expiry to succeed, got %v", err)
	}

	// 3. compactSaltStore progressive bucket growth: verify salt written right before growBuckets is NOT lost!
	var cs compactSaltStore
	cs.init(16384)
	cs.keyLen = 16
	inserted := make([][16]byte, 9000)
	for i := range inserted {
		binary.LittleEndian.PutUint64(inserted[i][:8], uint64(i+1))
		binary.LittleEndian.PutUint64(inserted[i][8:], uint64(0xdeadbeefcafe0000)+uint64(i))
		if err := cs.admit(inserted[i][:], t0); err != nil {
			t.Fatalf("compactSaltStore admit %d: %v", i, err)
		}
	}
	if cs.bits() <= compactInitBucketBits {
		t.Fatalf("expected bucketBits to grow beyond %d, got %d", compactInitBucketBits, cs.bits())
	}
	for i := range inserted {
		if err := cs.admit(inserted[i][:], t0.Add(time.Second)); !errors.Is(err, ErrReplay) {
			t.Fatalf("salt %d lost across growBuckets: got %v", i, err)
		}
	}

	// 4. SS2022 UDP client session cache capacity boundary & expiry reuse.
	var key [16]byte
	_, _ = rand.Read(key[:])
	srv, err := NewServer(Config{
		Method:         AES128GCM2022,
		Key:            key[:],
		MaxUDPSessions: 4,
		MaxTCPSalts:    64,
		UDPIdle:        time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	curNow := testTime
	srv.now = func() time.Time { return curNow }
	for sid := uint64(1); sid <= 4; sid++ {
		wire := udpRequest(t, srv, sid, 1, uint64(curNow.Unix()), testTarget, []byte("ping"))
		if _, err := srv.DecodeUDP(wire, testPeer); err != nil {
			t.Fatalf("session %d decode failed: %v", sid, err)
		}
	}
	wire5 := udpRequest(t, srv, 5, 1, uint64(curNow.Unix()), testTarget, []byte("ping"))
	if _, err := srv.DecodeUDP(wire5, testPeer); !errors.Is(err, ErrCapacity) {
		t.Fatalf("expected ErrCapacity on 5th UDP session, got: %v", err)
	}
	curNow = curNow.Add(62 * time.Second)
	wire5Later := udpRequest(t, srv, 5, 1, uint64(curNow.Unix()), testTarget, []byte("ping"))
	if _, err := srv.DecodeUDP(wire5Later, testPeer); err != nil {
		t.Fatalf("expected session admission after idle expiry, got: %v", err)
	}
}

func BenchmarkSS2022UDPRoundTripZeroAlloc(b *testing.B) {
	var key [16]byte
	_, _ = rand.Read(key[:])
	srv, err := NewServer(Config{Method: AES128GCM2022, Key: key[:], MaxUDPSessions: 16})
	if err != nil {
		b.Fatal(err)
	}
	srv.now = func() time.Time { return testTime }
	payload := make([]byte, 64)
	dummyT := &testing.T{}
	const ring = 512
	var wires [ring][]byte
	for i := 0; i < ring; i++ {
		wires[i] = udpRequest(dummyT, srv, 999, uint64(i+1), uint64(testTime.Unix()), testTarget, payload)
	}
	srvRun, _ := NewServer(Config{Method: AES128GCM2022, Key: key[:], MaxUDPSessions: 16})
	srvRun.now = func() time.Time { return testTime }
	dstBuf := make([]byte, 0, 2048)
	outBuf := make([]byte, 0, 2048)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%ring == 0 {
			srvRun.udp.init(16)
		}
		p, err := srvRun.DecodeUDPTo(dstBuf[:0], wires[i%ring], testPeer)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := srvRun.EncodeUDPTo(outBuf[:0], p, testTarget, p.Payload); err != nil {
			b.Fatal(err)
		}
	}
}
