package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	domainLenMax = 253
	targetMaxLen = 1 + 1 + domainLenMax + 2
)

// Target is a SOCKS-shaped destination. Port zero is invalid.
type Target struct {
	Addr netip.Addr
	Host string
	Port uint16
}

// NewIPTarget constructs an IP target. IPv4-mapped IPv6 addresses are rejected.
func NewIPTarget(addr netip.Addr, port uint16) (Target, error) {
	if !addr.IsValid() || addr.Is4In6() || port == 0 {
		return Target{}, errors.New("nw3: invalid ip target")
	}
	return Target{Addr: addr, Port: port}, nil
}

// NewDomainTarget constructs an ASCII/IDNA domain target.
func NewDomainTarget(host string, port uint16) (Target, error) {
	if err := validateDomain(host); err != nil || port == 0 {
		return Target{}, errors.New("nw3: invalid domain target")
	}
	return Target{Host: host, Port: port}, nil
}

// IsIP reports whether the target is an IP literal.
func (t Target) IsIP() bool { return t.Addr.IsValid() }

// HostPort is the dial address.
func (t Target) HostPort() string {
	host := t.Host
	if t.Addr.IsValid() {
		host = t.Addr.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(t.Port)))
}

func (t Target) String() string { return t.HostPort() }

// AppendTarget encodes the target onto dst.
func AppendTarget(dst []byte, t Target) ([]byte, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	if t.Addr.Is4() {
		dst = append(dst, atypIPv4)
		ip := t.Addr.As4()
		dst = append(dst, ip[:]...)
	} else if t.Addr.IsValid() {
		dst = append(dst, atypIPv6)
		ip := t.Addr.As16()
		dst = append(dst, ip[:]...)
	} else {
		dst = append(dst, atypDomain, byte(len(t.Host)))
		dst = append(dst, t.Host...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], t.Port)
	return append(dst, port[:]...), nil
}

// ReadTarget reads one target from r.
func ReadTarget(r io.Reader) (Target, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Target{}, err
	}
	switch atyp[0] {
	case atypIPv4:
		var buf [6]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return Target{}, err
		}
		addr, ok := netip.AddrFromSlice(buf[:4])
		if !ok {
			return Target{}, errors.New("nw3: invalid ipv4 target")
		}
		return NewIPTarget(addr, binary.BigEndian.Uint16(buf[4:]))
	case atypIPv6:
		var buf [18]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return Target{}, err
		}
		addr, ok := netip.AddrFromSlice(buf[:16])
		if !ok {
			return Target{}, errors.New("nw3: invalid ipv6 target")
		}
		return NewIPTarget(addr, binary.BigEndian.Uint16(buf[16:]))
	case atypDomain:
		var nbuf [1]byte
		if _, err := io.ReadFull(r, nbuf[:]); err != nil {
			return Target{}, err
		}
		n := int(nbuf[0])
		if n == 0 || n > domainLenMax {
			return Target{}, errors.New("nw3: invalid domain length")
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return Target{}, err
		}
		return NewDomainTarget(string(buf[:n]), binary.BigEndian.Uint16(buf[n:]))
	default:
		return Target{}, fmt.Errorf("nw3: unknown address type %d", atyp[0])
	}
}

// WriteFlowRequest writes FlowStart and Target.
func WriteFlowRequest(w io.Writer, kind FlowKind, target Target) error {
	if err := WriteFlowStart(w, kind); err != nil {
		return err
	}
	buf, err := AppendTarget(nil, target)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// ReadFlowRequest reads FlowStart and Target. ok is false on a clean EOF
// before FlowStart (QUIC authentication-only stream).
func ReadFlowRequest(r io.Reader) (FlowKind, Target, bool, error) {
	kind, ok, err := ReadFlowStart(r)
	if err != nil || !ok {
		return 0, Target{}, ok, err
	}
	target, err := ReadTarget(r)
	if err != nil {
		return 0, Target{}, false, err
	}
	return kind, target, true, nil
}

func (t Target) validate() error {
	if t.Port == 0 {
		return errors.New("nw3: zero target port")
	}
	if t.Addr.IsValid() {
		if t.Host != "" || t.Addr.Is4In6() {
			return errors.New("nw3: invalid ip target")
		}
		return nil
	}
	if err := validateDomain(t.Host); err != nil {
		return err
	}
	return nil
}

func validateDomain(host string) error {
	if len(host) == 0 || len(host) > domainLenMax {
		return errors.New("nw3: invalid domain length")
	}
	for i := 0; i < len(host); i++ {
		if host[i] > 127 {
			return errors.New("nw3: domain is not ASCII")
		}
	}
	start := 0
	for i := 0; i <= len(host); i++ {
		if i != len(host) && host[i] != '.' {
			continue
		}
		label := host[start:i]
		if len(label) == 0 || len(label) > 63 {
			return errors.New("nw3: invalid DNS label length")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("nw3: DNS label begins or ends with hyphen")
		}
		for j := 0; j < len(label); j++ {
			c := label[j]
			if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '-' {
				return errors.New("nw3: invalid DNS label bytes")
			}
		}
		start = i + 1
	}
	return nil
}
