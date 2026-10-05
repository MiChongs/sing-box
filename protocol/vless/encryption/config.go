package encryption

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	MLKEM768SeedLength   = mlkem.SeedSize
	MLKEM768ClientLength = mlkem.EncapsulationKeySize768
	X25519PasswordSize   = 32
	X25519PrivateKeySize = 32
)

const methodMLKEM768X25519Plus = "mlkem768x25519plus"

// NewClient creates a client from an Xray-core "encryption" value:
//
//	mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>[.padding...].<client key>[.client key...]
//
// It returns nil without error for "" and "none".
func NewClient(encryption string) (*ClientInstance, error) {
	switch encryption {
	case "", "none":
		return nil, nil
	}
	s := strings.Split(encryption, ".")
	if len(s) < 4 || s[0] != methodMLKEM768X25519Plus {
		return nil, E.New("invalid VLESS encryption: ", encryption)
	}
	xorMode, err := parseXorMode(s[1])
	if err != nil {
		return nil, E.Cause(err, "invalid VLESS encryption: ", encryption)
	}
	var seconds uint32
	switch s[2] {
	case "1rtt":
	case "0rtt":
		seconds = 1
	default:
		return nil, E.New("invalid VLESS encryption: unknown RTT mode: ", s[2])
	}
	padding, keys, err := parseKeys(s[3:], func(length int) bool {
		return length == X25519PasswordSize || length == MLKEM768ClientLength
	})
	if err != nil {
		return nil, E.Cause(err, "invalid VLESS encryption: ", encryption)
	}
	client := &ClientInstance{}
	err = client.init(keys, xorMode, seconds, padding)
	if err != nil {
		return nil, E.Cause(err, "initialize VLESS encryption")
	}
	return client, nil
}

// NewServer creates a server from an Xray-core "decryption" value:
//
//	mlkem768x25519plus.<native|xorpub|random>.<seconds>s[.padding...].<server key>[.server key...]
//
// where seconds is the 0-RTT ticket lifetime, a fixed value such as "600s", a
// range such as "300-600s", or "0s" to disable 0-RTT.
// It returns nil without error for "" and "none".
func NewServer(decryption string) (*ServerInstance, error) {
	switch decryption {
	case "", "none":
		return nil, nil
	}
	s := strings.Split(decryption, ".")
	if len(s) < 4 || s[0] != methodMLKEM768X25519Plus {
		return nil, E.New("invalid VLESS decryption: ", decryption)
	}
	xorMode, err := parseXorMode(s[1])
	if err != nil {
		return nil, E.Cause(err, "invalid VLESS decryption: ", decryption)
	}
	t := strings.SplitN(strings.TrimSuffix(s[2], "s"), "-", 2)
	secondsFrom, err := strconv.ParseInt(t[0], 10, 64)
	if err != nil {
		return nil, E.Cause(err, "invalid VLESS decryption: invalid ticket lifetime: ", s[2])
	}
	var secondsTo int64
	if len(t) == 2 {
		secondsTo, err = strconv.ParseInt(t[1], 10, 64)
		if err != nil {
			return nil, E.Cause(err, "invalid VLESS decryption: invalid ticket lifetime: ", s[2])
		}
	}
	padding, keys, err := parseKeys(s[3:], func(length int) bool {
		return length == X25519PrivateKeySize || length == MLKEM768SeedLength
	})
	if err != nil {
		return nil, E.Cause(err, "invalid VLESS decryption: ", decryption)
	}
	server := &ServerInstance{}
	err = server.init(keys, xorMode, secondsFrom, secondsTo, padding)
	if err != nil {
		return nil, E.Cause(err, "initialize VLESS decryption")
	}
	return server, nil
}

func parseXorMode(mode string) (uint32, error) {
	switch mode {
	case "native":
		return 0, nil
	case "xorpub":
		return 1, nil
	case "random":
		return 2, nil
	default:
		return 0, E.New("unknown mode: ", mode)
	}
}

// parseKeys splits the remaining fields into padding parameters, which are
// shorter than 20 characters, and base64 keys, same as Xray-core.
func parseKeys(fields []string, validKeyLength func(length int) bool) (string, [][]byte, error) {
	var (
		paddings []string
		keys     [][]byte
	)
	for _, field := range fields {
		if len(field) < 20 {
			if len(keys) > 0 {
				return "", nil, E.New("padding parameter after keys: ", field)
			}
			paddings = append(paddings, field)
			continue
		}
		key, err := base64.RawURLEncoding.DecodeString(field)
		if err != nil {
			return "", nil, E.Cause(err, "decode key")
		}
		if !validKeyLength(len(key)) {
			return "", nil, E.New("invalid key length: ", len(key))
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return "", nil, E.New("missing key")
	}
	return strings.Join(paddings, "."), keys, nil
}

// GenerateX25519 returns a X25519 server private key and the matching client
// password, both in base64 raw URL encoding. An empty privateKey generates a
// new one.
func GenerateX25519(privateKey string) (privateKeyBase64 string, passwordBase64 string, err error) {
	var keyBytes [X25519PrivateKeySize]byte
	if privateKey != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(privateKey)
		if err != nil {
			return "", "", E.Cause(err, "decode X25519 private key")
		}
		if len(decoded) != X25519PrivateKeySize {
			return "", "", E.New("invalid X25519 private key length: ", len(decoded))
		}
		keyBytes = [X25519PrivateKeySize]byte(decoded)
	} else {
		_, err = rand.Read(keyBytes[:])
		if err != nil {
			return
		}
	}
	// Avoid generating equivalent X25519 private keys, same as Xray-core.
	// https://github.com/XTLS/Xray-core/pull/1747
	keyBytes[0] &= 248
	keyBytes[31] &= 127
	keyBytes[31] |= 64
	key, err := ecdh.X25519().NewPrivateKey(keyBytes[:])
	if err != nil {
		return
	}
	privateKeyBase64 = base64.RawURLEncoding.EncodeToString(keyBytes[:])
	passwordBase64 = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	return
}

// GenerateMLKEM768 returns a ML-KEM-768 server seed and the matching client
// encapsulation key, both in base64 raw URL encoding. An empty seed generates a
// new one.
func GenerateMLKEM768(seed string) (seedBase64 string, clientBase64 string, err error) {
	var seedBytes [MLKEM768SeedLength]byte
	if seed != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(seed)
		if err != nil {
			return "", "", E.Cause(err, "decode ML-KEM-768 seed")
		}
		if len(decoded) != MLKEM768SeedLength {
			return "", "", E.New("invalid ML-KEM-768 seed length: ", len(decoded))
		}
		seedBytes = [MLKEM768SeedLength]byte(decoded)
	} else {
		_, err = rand.Read(seedBytes[:])
		if err != nil {
			return
		}
	}
	key, err := mlkem.NewDecapsulationKey768(seedBytes[:])
	if err != nil {
		return
	}
	seedBase64 = base64.RawURLEncoding.EncodeToString(seedBytes[:])
	clientBase64 = base64.RawURLEncoding.EncodeToString(key.EncapsulationKey().Bytes())
	return
}
