package nowhere

import (
	"fmt"
	"net/url"
)

// PortalKeyMinLen and PortalKeyMaxLen bound the Nowhere 2.2.1 Portal shared-key
// text rule. Both bounds are inclusive and odd lengths are accepted.
const (
	PortalKeyMinLen = 32
	PortalKeyMaxLen = 64
)

// errPortalKeyRule is the Portal key admission error, matching the Rust
// Credentials::for_portal message.
var errPortalKeyRule = fmt.Errorf("nowhere: shared key must be 32\u201364 lowercase hexadecimal characters")

// decodePortalKey percent-decodes a configured Portal shared key the way the
// Rust URL configuration layer decodes the username component, then enforces
// the Portal admission rule: 32\u201364 lowercase hexadecimal characters.
//
// The Portal listener key and every next-hop key use this rule. Client
// (outbound) keys stay lenient: the core accepts 1\u2013255 decoded bytes and
// applies no character rule.
func decodePortalKey(key string) (string, error) {
	decoded, err := url.QueryUnescape(key)
	if err != nil {
		return "", fmt.Errorf("nowhere: invalid shared key encoding: %w", err)
	}
	if err := validatePortalKey(decoded); err != nil {
		return "", err
	}
	return decoded, nil
}

// validatePortalKey applies the Portal key admission rule to an already
// decoded key.
func validatePortalKey(key string) error {
	if len(key) < PortalKeyMinLen || len(key) > PortalKeyMaxLen {
		return errPortalKeyRule
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errPortalKeyRule
		}
	}
	return nil
}
