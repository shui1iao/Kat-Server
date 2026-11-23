package kernel

import (
	"crypto/sha256"
	"errors"
	"github.com/shui1iao/Kat/internal/ss"
	"strings"
)

type SSOptions struct {
	Method    string `json:"method"`
	Password  string `json:"password,omitempty"` // only 2017
	Key       string `json:"key,omitempty"`      // standard base64, only 2022
	TCPSalts  int    `json:"tcp_salts,omitempty"`
	Salts2017 int    `json:"salts_2017,omitempty"`
	Sessions  int    `json:"sessions,omitempty"`
	// Per-listener, SS2017 UDP only: unset/0 = default socket (no change, no
	// charge); 1048576 = require actual 1MiB SO_RCVBUF charged to the 8MiB
	// process extra socket budget. Any other value is rejected.
	UDPRcvBuf2017 int `json:"udp_rcvbuf_2017,omitempty"`
}

// protection is the shared-identity part; the per-listener receive buffer is excluded.
func (o SSOptions) protection() SSOptions {
	o.UDPRcvBuf2017 = 0
	return o
}

func (o *SSOptions) key() ([]byte, error) {
	if o == nil {
		return nil, errors.New("SS options required")
	}
	if strings.HasPrefix(o.Method, "2022-") {
		if o.Password != "" || o.Key == "" {
			return nil, errors.New("SS2022 requires base64 key, not password")
		}
		return ss.KeyFromBase64(o.Method, o.Key)
	}
	if o.Key != "" || o.Password == "" || len(o.Password) > 4096 {
		return nil, errors.New("SS2017 requires password only")
	}
	return ss.PasswordKey2017(o.Method, o.Password)
}
func (o *SSOptions) identity() (string, error) {
	key, e := o.key()
	if e != nil {
		return "", errors.New("invalid SS method/key")
	}
	sum := sha256.Sum256(append([]byte(o.Method+"\x00"), key...))
	return string(sum[:]), nil
}
func (o *SSOptions) validate() error {
	if _, e := o.key(); e != nil {
		return errors.New("invalid SS method or credential")
	}
	if o.Salts2017 < 0 || o.Salts2017 > 32*1024*1024 {
		return errors.New("SS2017 protection capacity must be 0(default)..33554432")
	}
	switch o.UDPRcvBuf2017 {
	case 0:
	case ss2017RcvBufActual:
		if strings.HasPrefix(o.Method, "2022-") {
			return errors.New("udp_rcvbuf_2017 is only supported on SS2017 listeners, not SS2022")
		}
		if !ss2017RcvBufSupported {
			return errSSRcvBufUnsupported
		}
	default:
		return errors.New("udp_rcvbuf_2017 must be unset (default) or exactly 1048576")
	}
	for _, v := range []int{o.TCPSalts, o.Sessions} {
		if v < 0 || v > 1<<20 {
			return errors.New("SS protection capacity must be 0(default)..1048576")
		}
	}
	return nil
}

// prepareEncrypted only stages policy. Reusing protection and routes is safe
// even if a later prepare step fails: neither object is mutated here.
func (s *Server) prepareEncrypted(prev *Server) error {
	previous := map[string]*ssRuntime{}
	if prev != nil {
		for _, in := range prev.cfg.Inbounds {
			if rt := in.ssRuntime; rt != nil {
				previous[rt.identity] = rt
			}
		}
	}
	runtimes := map[string]*ssRuntime{}
	opts := map[string]SSOptions{}
	for i := range s.cfg.Inbounds {
		in := &s.cfg.Inbounds[i]
		if in.Protocol != "shadowsocks" {
			continue
		}
		id, err := in.SS.identity()
		if err != nil {
			return err
		}
		if rt := runtimes[id]; rt != nil {
			if opts[id].protection() != in.SS.protection() {
				return errors.New("same SS method/key must use identical protection settings")
			}
			in.ssRuntime = rt
			continue
		}
		conf := ss.Config{Method: in.SS.Method, MaxTCPSalts: in.SS.TCPSalts, Max2017Salts: in.SS.Salts2017, MaxUDPSessions: in.SS.Sessions, UDPIdle: s.cfg.Limits.UDPIdle.value()}
		limits, err := conf.ProtectionLimits()
		if err != nil {
			return err
		}
		rt := previous[id]
		if rt == nil {
			conf.Key, err = in.SS.key()
			if err != nil {
				return err
			}
			codec, err := ss.NewServer(conf)
			if err != nil {
				return errors.New("cannot initialize SS protection")
			}
			rt = &ssRuntime{codec: codec, identity: id, limits: limits, v2022: strings.HasPrefix(conf.Method, "2022-"), ssRoutes: &ssRoutes{associations: map[ssAssociationID]*ssNativeAssociation{}}}
		} else if rt.limits != limits {
			staged := *rt // all mutable data remains behind shared pointers
			staged.limits = limits
			rt = &staged
		}
		in.ssRuntime = rt
		runtimes[id] = rt
		opts[id] = *in.SS
	}
	return nil
}

// Called only in the no-fail commit phase under bindMu, before rebinding.
func (s *Server) commitSSProtection() {
	for _, in := range s.cfg.Inbounds {
		if rt := in.ssRuntime; rt != nil {
			rt.codec.ApplyProtection(rt.limits)
		}
	}
}
