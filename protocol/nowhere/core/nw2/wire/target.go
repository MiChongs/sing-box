package wire

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

// SOCKS5-compatible address types.
const (
	TargetIPv4   byte = 0x01
	TargetDomain byte = 0x03
	TargetIPv6   byte = 0x04
)

const (
	targetIPv4Len = 1 + 4 + 2
	targetIPv6Len = 1 + 16 + 2
	// DomainLenMax is the largest accepted wire hostname length.
	DomainLenMax    = 253
	targetDomainMin = 1 + 1 + 1 + 2
	targetMaxLen    = 1 + 1 + DomainLenMax + 2
)

// TargetType is the wire address type discriminator.
type TargetType uint8

const (
	// TargetTypeIPv4 identifies an IPv4 target.
	TargetTypeIPv4 TargetType = 0x01
	// TargetTypeDomain identifies an unresolved ASCII/IDNA hostname.
	TargetTypeDomain TargetType = 0x03
	// TargetTypeIPv6 identifies an IPv6 target.
	TargetTypeIPv6 TargetType = 0x04
)

// Target is a binary destination address carried after an opening flow header.
// Public fields are exposed for low-cost host conversion, but codec callers
// must use the constructors and Validate; the encoder never trusts the fields.
type Target struct {
	Type TargetType
	Addr netip.Addr
	Host string
	Port uint16
}

// NewIPTarget constructs a validated IP target. IPv4-in-6 mapped addresses are
// preserved as IPv6 and encoded with ATYP 0x04; callers holding an explicit
// IPv4 address should keep it IPv4 before construction.
func NewIPTarget(addr netip.Addr, port uint16) (Target, error) {
	if !addr.IsValid() {
		return Target{}, errors.New("nowhere: invalid ip target address")
	}
	if addr.Is4In6() {
		return Target{}, errors.New("nowhere: ipv4-in-6 mapped address must be unmapped")
	}
	if port == 0 {
		return Target{}, errors.New("nowhere: zero target port")
	}
	t := Target{Port: port}
	if addr.Is4() {
		t.Type = TargetTypeIPv4
	} else {
		t.Type = TargetTypeIPv6
	}
	t.Addr = addr
	return t, nil
}

// NewDomainTarget constructs a validated unresolved domain target. The host
// must already be in ASCII/IDNA wire form; the codec does no DNS resolution or
// punycode conversion.
func NewDomainTarget(host string, port uint16) (Target, error) {
	if port == 0 {
		return Target{}, errors.New("nowhere: zero target port")
	}
	if err := validateDomainName(host); err != nil {
		return Target{}, err
	}
	return Target{Type: TargetTypeDomain, Host: host, Port: port}, nil
}

// Validate enforces the constructor invariants. Codec entry points call this.
func (t Target) Validate() error {
	switch t.Type {
	case TargetTypeIPv4:
		if !t.Addr.IsValid() || !t.Addr.Is4() || t.Port == 0 {
			return ErrInvalidTarget
		}
	case TargetTypeIPv6:
		if !t.Addr.IsValid() || t.Addr.Is4() || t.Addr.Is4In6() || t.Port == 0 {
			return ErrInvalidTarget
		}
	case TargetTypeDomain:
		if t.Port == 0 {
			return ErrInvalidTarget
		}
		if err := validateDomainName(t.Host); err != nil {
			return err
		}
		if t.Addr.IsValid() {
			return errors.New("nowhere: domain target must not carry an ip")
		}
	default:
		return ErrInvalidTarget
	}
	// Cross-field consistency: IP types must not set Host, domain must not set Addr.
	if t.Type != TargetTypeDomain && t.Host != "" {
		return ErrInvalidTarget
	}
	return nil
}

// EncodedLen returns the on-wire length after validation.
func (t Target) EncodedLen() (int, error) {
	if err := t.Validate(); err != nil {
		return 0, err
	}
	switch t.Type {
	case TargetTypeIPv4:
		return targetIPv4Len, nil
	case TargetTypeIPv6:
		return targetIPv6Len, nil
	default:
		return 1 + 1 + len(t.Host) + 2, nil
	}
}

// EncodeTarget writes a validated target into a right-sized buffer.
func EncodeTarget(t Target) ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	n, err := t.EncodedLen()
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	if _, err := encodeTargetInto(t, out); err != nil {
		return nil, err
	}
	return out, nil
}

// EncodeTargetInto writes the target into the provided buffer and returns the
// number of bytes written. The buffer must be at least EncodedLen bytes.
func EncodeTargetInto(t Target, out []byte) (int, error) {
	if err := t.Validate(); err != nil {
		return 0, err
	}
	n, err := t.EncodedLen()
	if err != nil {
		return 0, err
	}
	if len(out) < n {
		return 0, errors.New("nowhere: target output buffer too short")
	}
	return encodeTargetInto(t, out)
}

func encodeTargetInto(t Target, out []byte) (int, error) {
	switch t.Type {
	case TargetTypeIPv4:
		out[0] = TargetIPv4
		addr4 := t.Addr.As4()
		copy(out[1:5], addr4[:])
		binary.BigEndian.PutUint16(out[5:7], t.Port)
		return targetIPv4Len, nil
	case TargetTypeIPv6:
		out[0] = TargetIPv6
		addr16 := t.Addr.As16()
		copy(out[1:17], addr16[:])
		binary.BigEndian.PutUint16(out[17:19], t.Port)
		return targetIPv6Len, nil
	case TargetTypeDomain:
		out[0] = TargetDomain
		out[1] = byte(len(t.Host))
		copy(out[2:2+len(t.Host)], t.Host)
		binary.BigEndian.PutUint16(out[2+len(t.Host):2+len(t.Host)+2], t.Port)
		return 1 + 1 + len(t.Host) + 2, nil
	default:
		return 0, ErrInvalidTarget
	}
}

// DecodeTarget decodes one target prefix and reports how many bytes it consumed.
func DecodeTarget(input []byte) (Target, int, error) {
	if len(input) == 0 {
		return Target{}, 0, ErrInvalidTarget
	}
	switch input[0] {
	case TargetIPv4:
		if len(input) < targetIPv4Len {
			return Target{}, 0, ErrTruncated
		}
		addr := netip.AddrFrom4([4]byte{input[1], input[2], input[3], input[4]})
		port := binary.BigEndian.Uint16(input[5:7])
		t, err := NewIPTarget(addr, port)
		if err != nil {
			return Target{}, 0, err
		}
		return t, targetIPv4Len, nil
	case TargetIPv6:
		if len(input) < targetIPv6Len {
			return Target{}, 0, ErrTruncated
		}
		var raw [16]byte
		copy(raw[:], input[1:17])
		addr := netip.AddrFrom16(raw)
		if addr.Is4In6() {
			return Target{}, 0, ErrInvalidTarget
		}
		port := binary.BigEndian.Uint16(input[17:19])
		t, err := NewIPTarget(addr, port)
		if err != nil {
			return Target{}, 0, err
		}
		return t, targetIPv6Len, nil
	case TargetDomain:
		if len(input) < 2 {
			return Target{}, 0, ErrTruncated
		}
		domainLen := int(input[1])
		encodedLen := 1 + 1 + domainLen + 2
		if domainLen == 0 || domainLen > DomainLenMax {
			return Target{}, 0, ErrInvalidTarget
		}
		if len(input) < encodedLen {
			return Target{}, 0, ErrTruncated
		}
		host := string(input[2 : 2+domainLen])
		port := binary.BigEndian.Uint16(input[encodedLen-2 : encodedLen])
		t, err := NewDomainTarget(host, port)
		if err != nil {
			return Target{}, 0, err
		}
		return t, encodedLen, nil
	default:
		return Target{}, 0, ErrInvalidTarget
	}
}

// ReadTarget reads one target, leaving any following initial payload untouched.
func ReadTarget(r io.Reader) (Target, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Target{}, err
	}
	switch atyp[0] {
	case TargetIPv4:
		var buf [targetIPv4Len - 1]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return Target{}, err
		}
		full := append([]byte{TargetIPv4}, buf[:]...)
		t, _, err := DecodeTarget(full)
		return t, err
	case TargetIPv6:
		var buf [targetIPv6Len - 1]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return Target{}, err
		}
		full := append([]byte{TargetIPv6}, buf[:]...)
		t, _, err := DecodeTarget(full)
		return t, err
	case TargetDomain:
		var lenByte [1]byte
		if _, err := io.ReadFull(r, lenByte[:]); err != nil {
			return Target{}, err
		}
		domainLen := int(lenByte[0])
		if domainLen == 0 || domainLen > DomainLenMax {
			return Target{}, ErrInvalidTarget
		}
		encodedLen := 1 + 1 + domainLen + 2
		buf := make([]byte, encodedLen)
		buf[0] = TargetDomain
		buf[1] = lenByte[0]
		if _, err := io.ReadFull(r, buf[2:encodedLen]); err != nil {
			return Target{}, err
		}
		t, _, err := DecodeTarget(buf)
		return t, err
	default:
		return Target{}, ErrInvalidTarget
	}
}

// validateDomainName mirrors nowhere::protocol::util::validate_domain_bytes:
// ASCII/IDNA wire form, 1..253 bytes, each label 1..63, labels are
// alphanumeric or '-' and must not begin/end with '-'.
func validateDomainName(host string) error {
	if len(host) == 0 || len(host) > DomainLenMax {
		return ErrInvalidTarget
	}
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return ErrInvalidTarget
		}
	}
	// reject trailing dot and empty labels here; per-label checks below.
	start := 0
	for i := 0; i <= len(host); i++ {
		if i == len(host) || host[i] == '.' {
			label := host[start:i]
			if len(label) == 0 || len(label) > 63 {
				return ErrInvalidTarget
			}
			if !validLabel(label) {
				return ErrInvalidTarget
			}
			start = i + 1
		}
	}
	return nil
}

func validLabel(label string) bool {
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}
