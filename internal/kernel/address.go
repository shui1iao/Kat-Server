package kernel

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
)

type Address struct {
	Host string
	Port uint16
}

func (a Address) String() string { return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port))) }

func readN(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return b, e
}

func readFullBytes(r *bytes.Reader, b []byte) error {
	got := 0
	for got < len(b) {
		n, err := r.Read(b[got:])
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

func readFullBufio(r *bufio.Reader, b []byte) error {
	got := 0
	for got < len(b) {
		n, err := r.Read(b[got:])
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

func readExact(r io.Reader, b []byte) error {
	if br, ok := r.(*bytes.Reader); ok {
		return readFullBytes(br, b)
	}
	if bfr, ok := r.(*bufio.Reader); ok {
		return readFullBufio(bfr, b)
	}
	_, e := io.ReadFull(r, b)
	return e
}

func validateDomainHost(host string) error {
	for i := 0; i < len(host); i++ {
		switch host[i] {
		case 0, '\r', '\n', ' ', ':', '/', '\\':
			return errors.New("invalid domain")
		}
	}
	return nil
}

func readHost(r io.Reader, _ bool) (Address, error) {
	var scratch [257]byte
	if e := readExact(r, scratch[:1]); e != nil {
		return Address{}, e
	}
	switch scratch[0] {
	case 1:
		if e := readExact(r, scratch[:4]); e != nil {
			return Address{}, e
		}
		return Address{Host: netip.AddrFrom4([4]byte(scratch[:4])).String()}, nil
	case 4:
		if e := readExact(r, scratch[:16]); e != nil {
			return Address{}, e
		}
		return Address{Host: netip.AddrFrom16([16]byte(scratch[:16])).Unmap().String()}, nil
	case 3:
		if e := readExact(r, scratch[:1]); e != nil {
			return Address{}, e
		}
		n := int(scratch[0])
		if n == 0 {
			return Address{}, errors.New("empty domain")
		}
		if e := readExact(r, scratch[:n]); e != nil {
			return Address{}, e
		}
		host := string(scratch[:n])
		if e := validateDomainHost(host); e != nil {
			return Address{}, e
		}
		return Address{Host: host}, nil
	default:
		return Address{}, errors.New("unsupported address type")
	}
}

func appendAddress(b []byte, a Address, _ bool) []byte {
	ip, e := netip.ParseAddr(a.Host)
	if e == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b = append(b, 1)
			x := ip.As4()
			b = append(b, x[:]...)
		} else {
			b = append(b, 4)
			x := ip.As16()
			b = append(b, x[:]...)
		}
	} else {
		b = append(b, 3, byte(len(a.Host)))
		b = append(b, a.Host...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port)
}

func addrFromNet(a net.Addr) Address {
	h, p, _ := net.SplitHostPort(a.String())
	n, _ := strconv.Atoi(p)
	return Address{h, uint16(n)}
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// readAddressBuf reads a SOCKS5/Trojan target address using caller-supplied
// scratch space (len >= 260) to avoid extra per-field heap allocations.
func readAddressBuf(r io.Reader, scratch []byte) (Address, error) {
	if e := readExact(r, scratch[:1]); e != nil {
		return Address{}, e
	}
	switch scratch[0] {
	case 1:
		if e := readExact(r, scratch[1:7]); e != nil {
			return Address{}, e
		}
		a, _, e := parseAddressBytes(scratch[:7], nil, nil, nil)
		return a, e
	case 4:
		if e := readExact(r, scratch[1:19]); e != nil {
			return Address{}, e
		}
		a, _, e := parseAddressBytes(scratch[:19], nil, nil, nil)
		return a, e
	case 3:
		if e := readExact(r, scratch[1:2]); e != nil {
			return Address{}, e
		}
		if scratch[1] == 0 {
			return Address{}, errors.New("empty domain")
		}
		end := 2 + int(scratch[1]) + 2
		if e := readExact(r, scratch[2:end]); e != nil {
			return Address{}, e
		}
		a, _, e := parseAddressBytes(scratch[:end], nil, nil, nil)
		return a, e
	default:
		return Address{}, errors.New("unsupported address type")
	}
}

func readAddress(r io.Reader, _ bool) (Address, error) {
	if br, ok := r.(*bytes.Reader); ok {
		var scratch [260]byte
		t, e := br.ReadByte()
		if e != nil {
			return Address{}, e
		}
		scratch[0] = t
		switch t {
		case 1:
			if e := readFullBytes(br, scratch[1:7]); e != nil {
				return Address{}, e
			}
			a, _, e := parseAddressBytes(scratch[:7], nil, nil, nil)
			return a, e
		case 4:
			if e := readFullBytes(br, scratch[1:19]); e != nil {
				return Address{}, e
			}
			a, _, e := parseAddressBytes(scratch[:19], nil, nil, nil)
			return a, e
		case 3:
			lb, e := br.ReadByte()
			if e != nil {
				return Address{}, e
			}
			if lb == 0 {
				return Address{}, errors.New("empty domain")
			}
			end := 2 + int(lb) + 2
			scratch[1] = lb
			if e := readFullBytes(br, scratch[2:end]); e != nil {
				return Address{}, e
			}
			a, _, e := parseAddressBytes(scratch[:end], nil, nil, nil)
			return a, e
		default:
			return Address{}, errors.New("unsupported address type")
		}
	}
	if bfr, ok := r.(*bufio.Reader); ok {
		var scratch [260]byte
		t, e := bfr.ReadByte()
		if e != nil {
			return Address{}, e
		}
		scratch[0] = t
		switch t {
		case 1:
			if e := readFullBufio(bfr, scratch[1:7]); e != nil {
				return Address{}, e
			}
			a, _, e := parseAddressBytes(scratch[:7], nil, nil, nil)
			return a, e
		case 4:
			if e := readFullBufio(bfr, scratch[1:19]); e != nil {
				return Address{}, e
			}
			a, _, e := parseAddressBytes(scratch[:19], nil, nil, nil)
			return a, e
		case 3:
			lb, e := bfr.ReadByte()
			if e != nil {
				return Address{}, e
			}
			if lb == 0 {
				return Address{}, errors.New("empty domain")
			}
			end := 2 + int(lb) + 2
			scratch[1] = lb
			if e := readFullBufio(bfr, scratch[2:end]); e != nil {
				return Address{}, e
			}
			a, _, e := parseAddressBytes(scratch[:end], nil, nil, nil)
			return a, e
		default:
			return Address{}, errors.New("unsupported address type")
		}
	}
	var scratch [260]byte
	return readAddressBuf(r, scratch[:])
}

func parseAddressBytes(b []byte, cacheIP4 *[4]byte, cacheStr *string, cacheInit *bool) (Address, int, error) {
	if len(b) < 4 {
		return Address{}, 0, io.ErrUnexpectedEOF
	}
	var a Address
	var off int
	switch b[0] {
	case 1:
		if len(b) < 7 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		ip4 := [4]byte(b[1:5])
		if cacheIP4 != nil && cacheStr != nil && cacheInit != nil {
			if !*cacheInit || ip4 != *cacheIP4 {
				*cacheIP4 = ip4
				*cacheStr = netip.AddrFrom4(ip4).String()
				*cacheInit = true
			}
			a.Host = *cacheStr
		} else {
			a.Host = netip.AddrFrom4(ip4).String()
		}
		off = 5
	case 4:
		if len(b) < 19 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		ip16 := [16]byte(b[1:17])
		a.Host = netip.AddrFrom16(ip16).Unmap().String()
		off = 17
	case 3:
		n := int(b[1])
		if n == 0 {
			return Address{}, 0, errors.New("empty domain")
		}
		if len(b) < 2+n+2 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		a.Host = string(b[2 : 2+n])
		if validateDomainHost(a.Host) != nil {
			return Address{}, 0, errors.New("invalid domain")
		}
		off = 2 + n
	default:
		return Address{}, 0, errors.New("unsupported address type")
	}
	a.Port = binary.BigEndian.Uint16(b[off : off+2])
	return a, off + 2, nil
}
