package kernel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net"
)

type request struct {
	Context       context.Context
	UDPRead       func() (packet, error)
	UDPWrite      func(Address, []byte) error
	UDPWriteBatch func([]Address, [][]byte) error
	Reply         func(net.Conn, net.Addr, bool) error
	Command       byte
	Target        Address
	Mode          string
	UserIndex     int      // -1 for intentionally unauthenticated loopback SOCKS
	Stream        net.Conn // optional transforming stream; never expose raw TCP if transforms remain
	Datagrams     datagramCodec
}
type adapter func(net.Conn, Inbound) (request, error)

// errSOCKSAuth is a wrong SOCKS5 username or password.
var errSOCKSAuth = errors.New("authentication failed")

var adapters = map[string]adapter{"socks5": parseSOCKS, "trojan": parseTrojan}

func (r request) respond(c net.Conn, bound net.Addr, ok bool) error {
	if r.Reply != nil {
		return r.Reply(c, bound, ok)
	}
	switch r.Mode {
	case "socks5":
		rep := byte(0)
		if !ok {
			rep = 5
		}
		a := Address{"0.0.0.0", 0}
		if bound != nil {
			a = addrFromNet(bound)
		}
		return writeAll(c, appendAddress([]byte{5, rep, 0}, a, false))
	}
	return nil
}
func parseSOCKS(c net.Conn, in Inbound) (request, error) {
	r := request{Mode: "socks5", UserIndex: -1}
	poolBuf := getUDPPlainBuf()
	defer putUDPPlainBuf(poolBuf)
	scratch := poolBuf[:516]
	if e := readExact(c, scratch[:2]); e != nil {
		return r, e
	}
	if scratch[0] != 5 || scratch[1] == 0 {
		return r, errors.New("invalid SOCKS greeting")
	}
	nMethods := int(scratch[1])
	if e := readExact(c, scratch[:nMethods]); e != nil {
		return r, e
	}
	method := byte(0)
	if len(in.Users) > 0 {
		method = 2
	}
	found := false
	for _, v := range scratch[:nMethods] {
		if v == method {
			found = true
		}
	}
	if !found {
		_ = writeAll(c, []byte{5, 255})
		return r, errors.New("no supported authentication method")
	}
	if e := writeAll(c, []byte{5, method}); e != nil {
		return r, e
	}
	if method == 2 {
		if e := readExact(c, scratch[:2]); e != nil {
			return r, e
		}
		if scratch[0] != 1 || scratch[1] == 0 {
			return r, errors.New("invalid authentication version or username")
		}
		uLen := int(scratch[1])
		uBuf := scratch[:uLen]
		if e := readExact(c, uBuf); e != nil {
			return r, e
		}
		lenSlot := scratch[256:257]
		if e := readExact(c, lenSlot); e != nil {
			return r, e
		}
		if lenSlot[0] == 0 {
			return r, errors.New("empty password")
		}
		pLen := int(lenSlot[0])
		pBuf := scratch[257 : 257+pLen]
		if e := readExact(c, pBuf); e != nil {
			return r, e
		}
		providedUser := sha256.Sum256(uBuf)
		providedPass := sha256.Sum256(pBuf)
		match := 0
		for i, usr := range in.Users {
			expectedUser := sha256.Sum256([]byte(usr.Username))
			expectedPass := sha256.Sum256([]byte(usr.Password))
			m := subtle.ConstantTimeCompare(providedUser[:], expectedUser[:]) & subtle.ConstantTimeCompare(providedPass[:], expectedPass[:])
			match |= m
			if m == 1 {
				r.UserIndex = i
			}
		}
		status := byte(0)
		if match == 0 {
			status = 1
		}
		if e := writeAll(c, []byte{1, status}); e != nil {
			return r, e
		}
		if match == 0 {
			return r, errSOCKSAuth
		}
	}
	if e := readExact(c, scratch[:3]); e != nil {
		return r, e
	}
	if scratch[0] != 5 || scratch[2] != 0 {
		return r, errors.New("invalid SOCKS request")
	}
	r.Command = scratch[1]
	if r.Command != 1 && r.Command != 3 && (r.Command != 2 || in.bindOptions() == nil) {
		_ = writeAll(c, []byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return r, errors.New("unsupported SOCKS command")
	}
	var e error
	r.Target, e = readAddressBuf(c, scratch[:260])
	if e != nil {
		_ = writeAll(c, []byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return r, e
	}
	return r, nil
}

func expectCRLFBuf(r io.Reader, b []byte) error {
	if e := readExact(r, b[:2]); e != nil {
		return e
	}
	if b[0] != 13 || b[1] != 10 {
		return errors.New("invalid CRLF")
	}
	return nil
}

func expectCRLF(r io.Reader) error {
	var b [2]byte
	return expectCRLFBuf(r, b[:])
}
