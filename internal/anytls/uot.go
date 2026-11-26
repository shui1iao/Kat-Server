package anytls

import (
	"bufio"
	"encoding/binary"
	"io"
	"sync"
	"time"
)

const uotSmallWireCap = 2048

var uotWirePool = sync.Pool{
	New: func() any {
		b := make([]byte, uotSmallWireCap)
		return &b
	},
}

func releaseUoTWire(b []byte) {
	if cap(b) == uotSmallWireCap {
		s := b[:uotSmallWireCap]
		uotWirePool.Put(&s)
	}
}

// DatagramConn adapts UoT v2, not native UDP and not UoT v1. In connected mode
// both directions implicitly use Target. In non-connected mode per-packet
// ATYP is 0=IPv4/1=IPv6/2=domain, distinct from the SOCKS request header's 1/4/3.
// Do not mix raw Stream reads/writes with this adapter.
type DatagramConn struct {
	stream    *Stream
	br        *bufio.Reader
	connected bool
	target    Address
	rMu, wMu  sync.Mutex
}

func newDatagram(st *Stream) (*DatagramConn, error) {
	br := bufio.NewReaderSize(st, 16*1024)
	var b [1]byte
	if _, e := io.ReadFull(br, b[:]); e != nil {
		return nil, unexpected(e)
	}
	if b[0] > 1 {
		return nil, ErrProtocol
	}
	target, e := readAddress(br, false)
	if e != nil {
		return nil, e
	}
	return &DatagramConn{stream: st, br: br, connected: b[0] == 1, target: target}, nil
}
func (d *DatagramConn) Connected() bool { return d.connected }
func (d *DatagramConn) Target() Address { return d.target }

// ReadPacket owns a new payload (including zero-length UDP datagrams).
func (d *DatagramConn) ReadPacket() (Address, []byte, error) {
	d.rMu.Lock()
	defer d.rMu.Unlock()
	target := d.target
	if !d.connected {
		var e error
		target, e = readAddress(d.br, true)
		if e != nil {
			return Address{}, nil, e
		}
	}
	var length [2]byte
	if _, e := io.ReadFull(d.br, length[:]); e != nil {
		if !d.connected {
			e = unexpected(e)
		}
		return Address{}, nil, e
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	payload := make([]byte, n)
	if _, e := io.ReadFull(d.br, payload); e != nil {
		return Address{}, nil, unexpected(e)
	}
	return target, payload, nil
}

// WritePacket enforces the fixed connected address because that wire mode has no
// per-packet source field. For a domain resolved by the router, pass Target() for
// connected responses, not an unrepresentable resolved-IP source address.
func (d *DatagramConn) WritePacket(from Address, payload []byte) error {
	if len(payload) > 65535 {
		return ErrProtocol
	}
	d.wMu.Lock()
	defer d.wMu.Unlock()
	var addrBuf [259]byte
	var addrBytes []byte
	if d.connected {
		if from != d.target {
			return ErrConnectedAddress
		}
	} else {
		var e error
		addrBytes, e = from.appendMarshal(addrBuf[:0], true)
		if e != nil {
			return e
		}
	}
	bodyLen := len(addrBytes) + 2 + len(payload)
	maxFrame := d.stream.session.server.cfg.MaxFrameData
	if bodyLen <= maxFrame {
		need := 7 + bodyLen
		var wire []byte
		var release func([]byte)
		if need <= uotSmallWireCap {
			p := uotWirePool.Get().(*[]byte)
			wire = (*p)[:need]
			release = releaseUoTWire
		} else {
			wire = make([]byte, need)
		}
		pos := 7
		pos += copy(wire[pos:], addrBytes)
		binary.BigEndian.PutUint16(wire[pos:pos+2], uint16(len(payload)))
		pos += 2
		copy(wire[pos:], payload)
		n, e := d.stream.WriteOwnedFrame(wire, release)
		if e == nil && n != bodyLen {
			e = io.ErrShortWrite
		}
		return e
	}
	wire := make([]byte, bodyLen)
	pos := copy(wire, addrBytes)
	binary.BigEndian.PutUint16(wire[pos:pos+2], uint16(len(payload)))
	pos += 2
	copy(wire[pos:], payload)
	n, e := d.stream.Write(wire)
	if e == nil && n != len(wire) {
		e = io.ErrShortWrite
	}
	return e
}
func (d *DatagramConn) Close() error                       { return d.stream.Close() }
func (d *DatagramConn) SetReadDeadline(t time.Time) error  { return d.stream.SetReadDeadline(t) }
func (d *DatagramConn) SetWriteDeadline(t time.Time) error { return d.stream.SetWriteDeadline(t) }

// WritePacketBatch packs multiple UoT v2 datagrams into coalesced PSH frames
// under one write lock so high-PPS UDP return traffic avoids per-packet TLS records.
func (d *DatagramConn) WritePacketBatch(froms []Address, payloads [][]byte) error {
	if len(payloads) == 0 {
		return nil
	}
	if len(payloads) == 1 {
		return d.WritePacket(froms[0], payloads[0])
	}
	d.wMu.Lock()
	defer d.wMu.Unlock()
	maxFrame := d.stream.session.server.cfg.MaxFrameData
	if maxFrame <= 0 {
		maxFrame = 65535
	}
	var addrBuf [259]byte
	// Compute total size needed to avoid over-allocating frame buffers.
	frame := make([]byte, 7, 7+min(maxFrame, 32<<10))
	flush := func() error {
		bodyLen := len(frame) - 7
		if bodyLen <= 0 {
			return nil
		}
		n, err := d.stream.WriteOwnedFrame(frame, nil)
		if err == nil && n != bodyLen {
			err = io.ErrShortWrite
		}
		frame = nil
		return err
	}
	for i, payload := range payloads {
		if len(payload) > 65535 {
			return ErrProtocol
		}
		var addrBytes []byte
		if d.connected {
			if froms[i] != d.target {
				return ErrConnectedAddress
			}
		} else {
			var e error
			addrBytes, e = froms[i].appendMarshal(addrBuf[:0], true)
			if e != nil {
				return e
			}
		}
		recLen := len(addrBytes) + 2 + len(payload)
		if recLen > maxFrame {
			if err := flush(); err != nil {
				return err
			}
			wire := make([]byte, recLen)
			pos := copy(wire, addrBytes)
			binary.BigEndian.PutUint16(wire[pos:pos+2], uint16(len(payload)))
			copy(wire[pos+2:], payload)
			if n, err := d.stream.Write(wire); err != nil {
				return err
			} else if n != len(wire) {
				return io.ErrShortWrite
			}
			continue
		}
		if frame != nil && (len(frame)-7)+recLen > maxFrame {
			if err := flush(); err != nil {
				return err
			}
		}
		if frame == nil {
			frame = make([]byte, 7, 7+min(maxFrame, 32<<10))
		}
		frame = append(frame, addrBytes...)
		frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
		frame = append(frame, payload...)
	}
	return flush()
}
