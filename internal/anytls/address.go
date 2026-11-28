package anytls

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Address struct {
	Host string
	Port uint16
}

func (a Address) String() string                 { return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port))) }
func (a Address) MarshalBinary() ([]byte, error) { return a.marshal(false) }
func (a Address) marshal(uot bool) ([]byte, error) {
	return a.appendMarshal(nil, uot)
}
func (a Address) appendMarshal(b []byte, uot bool) ([]byte, error) {
	if a.Host == "" || strings.ContainsRune(a.Host, 0) {
		return nil, ErrProtocol
	}
	ip, e := netip.ParseAddr(a.Host)
	if e == nil {
		if ip.Zone() != "" {
			return nil, ErrProtocol
		}
		ip = ip.Unmap()
		if ip.Is4() {
			typ := byte(1)
			if uot {
				typ = 0
			}
			v := ip.As4()
			b = append(b, typ, v[0], v[1], v[2], v[3])
		} else {
			typ := byte(4)
			if uot {
				typ = 1
			}
			v := ip.As16()
			b = append(b, typ)
			b = append(b, v[:]...)
		}
	} else {
		if len(a.Host) > 255 {
			return nil, ErrProtocol
		}
		typ := byte(3)
		if uot {
			typ = 2
		}
		b = append(b, typ, byte(len(a.Host)))
		b = append(b, a.Host...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port), nil
}

func readFullBufio(br *bufio.Reader, b []byte) error {
	got := 0
	for got < len(b) {
		n, err := br.Read(b[got:])
		got += n
		if err != nil {
			if got == len(b) && err == io.EOF {
				return nil
			}
			if err == io.EOF && got > 0 {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

func readFullStream(st *Stream, b []byte) error {
	got := 0
	for got < len(b) {
		n, err := st.Read(b[got:])
		got += n
		if err != nil {
			if got == len(b) && err == io.EOF {
				return nil
			}
			if err == io.EOF && got > 0 {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

func readFullBytes(br *bytes.Reader, b []byte) error {
	got := 0
	for got < len(b) {
		n, err := br.Read(b[got:])
		got += n
		if err != nil {
			if got == len(b) && err == io.EOF {
				return nil
			}
			if err == io.EOF && got > 0 {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

func decodeAddressTail(typ, domain byte, b []byte, n int) (Address, error) {
	var host string
	if typ == domain {
		host = string(b[:n])
		for i := 0; i < len(host); i++ {
			if host[i] == 0 {
				return Address{}, ErrProtocol
			}
		}
	} else if n == 4 {
		host = netip.AddrFrom4([4]byte(b[:4])).String()
	} else if n == 16 {
		host = netip.AddrFrom16([16]byte(b[:16])).String()
	} else {
		return Address{}, ErrProtocol
	}
	return Address{host, binary.BigEndian.Uint16(b[n:])}, nil
}

func readAddress(r io.Reader, uot bool) (Address, error) {
	ipv4, ipv6, domain := byte(1), byte(4), byte(3)
	if uot {
		ipv4, ipv6, domain = 0, 1, 2
	}

	// Concrete *bufio.Reader fast path (used by uot.go and buffered streams):
	// avoids interface calls so stack buffers never escape to the heap.
	if br, ok := r.(*bufio.Reader); ok {
		typ, e := br.ReadByte()
		if e != nil {
			return Address{}, e
		}
		var n int
		switch typ {
		case ipv4:
			n = 4
		case ipv6:
			n = 16
		case domain:
			lb, e := br.ReadByte()
			if e != nil {
				return Address{}, unexpected(e)
			}
			n = int(lb)
			if n == 0 {
				return Address{}, ErrProtocol
			}
		default:
			return Address{}, ErrProtocol
		}
		if br.Buffered() >= n+2 {
			peeked, e := br.Peek(n + 2)
			if e == nil {
				addr, err := decodeAddressTail(typ, domain, peeked, n)
				_, _ = br.Discard(n + 2)
				return addr, err
			}
		}
		var buf [257]byte
		b := buf[:n+2]
		if e := readFullBufio(br, b); e != nil {
			return Address{}, unexpected(e)
		}
		return decodeAddressTail(typ, domain, b, n)
	}

	if st, ok := r.(*Stream); ok {
		var buf [257]byte
		if e := readFullStream(st, buf[:1]); e != nil {
			return Address{}, e
		}
		typ := buf[0]
		var n int
		switch typ {
		case ipv4:
			n = 4
		case ipv6:
			n = 16
		case domain:
			if e := readFullStream(st, buf[:1]); e != nil {
				return Address{}, unexpected(e)
			}
			n = int(buf[0])
			if n == 0 {
				return Address{}, ErrProtocol
			}
		default:
			return Address{}, ErrProtocol
		}
		b := buf[:n+2]
		if e := readFullStream(st, b); e != nil {
			return Address{}, unexpected(e)
		}
		return decodeAddressTail(typ, domain, b, n)
	}

	if byr, ok := r.(*bytes.Reader); ok {
		typ, e := byr.ReadByte()
		if e != nil {
			return Address{}, e
		}
		var n int
		switch typ {
		case ipv4:
			n = 4
		case ipv6:
			n = 16
		case domain:
			lb, e := byr.ReadByte()
			if e != nil {
				return Address{}, unexpected(e)
			}
			n = int(lb)
			if n == 0 {
				return Address{}, ErrProtocol
			}
		default:
			return Address{}, ErrProtocol
		}
		var buf [257]byte
		b := buf[:n+2]
		if e := readFullBytes(byr, b); e != nil {
			return Address{}, unexpected(e)
		}
		return decodeAddressTail(typ, domain, b, n)
	}

	var first [1]byte
	if _, e := io.ReadFull(r, first[:]); e != nil {
		return Address{}, e
	}
	typ := first[0]
	n := 0
	switch typ {
	case ipv4:
		n = 4
	case ipv6:
		n = 16
	case domain:
		if _, e := io.ReadFull(r, first[:]); e != nil {
			return Address{}, unexpected(e)
		}
		n = int(first[0])
		if n == 0 {
			return Address{}, ErrProtocol
		}
	default:
		return Address{}, ErrProtocol
	}
	var buf [257]byte
	b := buf[:n+2]
	if _, e := io.ReadFull(r, b); e != nil {
		return Address{}, unexpected(e)
	}
	return decodeAddressTail(typ, domain, b, n)
}
