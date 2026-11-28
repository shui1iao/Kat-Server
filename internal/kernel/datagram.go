package kernel

import (
	"encoding/binary"
	"errors"
	"io"
)

// datagramCodec is frame-only: one owned payload per successful read and no
// background work. UDP association lifetime, quotas and return filtering remain shared.
type datagramCodec interface {
	ReadPacket(io.Reader, Address) (packet, error)
	AppendPacket([]byte, Address, []byte) []byte
}

type trojanDatagrams struct {
	cacheIP4  [4]byte
	cacheHost string
	cacheInit bool
}

func readDatagramBody(r io.Reader, crlf bool) ([]byte, []byte, error) {
	var hdr [4]byte
	need := 2
	if crlf {
		need = 4
	}
	if e := readExact(r, hdr[:need]); e != nil {
		return nil, nil, e
	}
	n := int(binary.BigEndian.Uint16(hdr[:2]))
	if n > maxDatagram {
		return nil, nil, errors.New("UDP frame too large")
	}
	if crlf && (hdr[2] != 13 || hdr[3] != 10) {
		return nil, nil, errors.New("invalid CRLF")
	}
	if n <= udpSmallBufCap {
		buf := getUDPPlainBuf()
		payload := buf[:n]
		if e := readExact(r, payload); e != nil {
			putUDPPlainBuf(buf)
			return nil, nil, e
		}
		return payload, buf, nil
	}
	payload := make([]byte, n)
	if e := readExact(r, payload); e != nil {
		return nil, nil, e
	}
	return payload, nil, nil
}

func (d *trojanDatagrams) ReadPacket(r io.Reader, _ Address) (packet, error) {
	poolBuf := getUDPPlainBuf()
	scratch := poolBuf[:264]
	if e := readExact(r, scratch[:1]); e != nil {
		putUDPPlainBuf(poolBuf)
		return packet{}, e
	}
	var hdrEnd int
	switch scratch[0] {
	case 1:
		hdrEnd = 11 // 1(ATYP) + 4(IPv4) + 2(Port) + 2(Len) + 2(CRLF)
		if e := readExact(r, scratch[1:hdrEnd]); e != nil {
			putUDPPlainBuf(poolBuf)
			return packet{}, e
		}
	case 4:
		hdrEnd = 23 // 1(ATYP) + 16(IPv6) + 2(Port) + 2(Len) + 2(CRLF)
		if e := readExact(r, scratch[1:hdrEnd]); e != nil {
			putUDPPlainBuf(poolBuf)
			return packet{}, e
		}
	case 3:
		if e := readExact(r, scratch[1:2]); e != nil {
			putUDPPlainBuf(poolBuf)
			return packet{}, e
		}
		if scratch[1] == 0 {
			putUDPPlainBuf(poolBuf)
			return packet{}, errors.New("empty domain")
		}
		hdrEnd = 2 + int(scratch[1]) + 6 // 2 + dlen + 2(Port) + 2(Len) + 2(CRLF)
		if e := readExact(r, scratch[2:hdrEnd]); e != nil {
			putUDPPlainBuf(poolBuf)
			return packet{}, e
		}
	default:
		putUDPPlainBuf(poolBuf)
		return packet{}, errors.New("unsupported address type")
	}

	var a Address
	var consumed int
	var e error
	if d != nil {
		a, consumed, e = parseAddressBytes(scratch[:hdrEnd-4], &d.cacheIP4, &d.cacheHost, &d.cacheInit)
	} else {
		a, consumed, e = parseAddressBytes(scratch[:hdrEnd-4], nil, nil, nil)
	}
	if e != nil {
		putUDPPlainBuf(poolBuf)
		return packet{}, e
	}
	n := int(binary.BigEndian.Uint16(scratch[consumed : consumed+2]))
	if n > maxDatagram {
		putUDPPlainBuf(poolBuf)
		return packet{}, errors.New("UDP frame too large")
	}
	if scratch[consumed+2] != 13 || scratch[consumed+3] != 10 {
		putUDPPlainBuf(poolBuf)
		return packet{}, errors.New("invalid CRLF")
	}
	if n <= udpSmallBufCap {
		payload := poolBuf[:n]
		if e := readExact(r, payload); e != nil {
			putUDPPlainBuf(poolBuf)
			return packet{}, e
		}
		return packet{target: a, payload: payload, pooled: poolBuf}, nil
	}
	putUDPPlainBuf(poolBuf)
	payload := make([]byte, n)
	if e := readExact(r, payload); e != nil {
		return packet{}, e
	}
	return packet{target: a, payload: payload}, nil
}

func (*trojanDatagrams) AppendPacket(b []byte, a Address, p []byte) []byte {
	b = appendAddress(b, a, false)
	b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
	b = append(b, 13, 10)
	return append(b, p...)
}
