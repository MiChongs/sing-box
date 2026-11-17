// Package utlsid maps uTLS fingerprint names to ClientHelloIDs, shared by the
// uTLS client and the PTLS client so both present the same fingerprints.
package utlsid

import (
	"math/rand"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"

	utls "github.com/metacubex/utls"
)

var (
	randomFingerprint     utls.ClientHelloID
	randomizedFingerprint utls.ClientHelloID
)

func init() {
	modernFingerprints := []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloEdge_Auto,
		utls.HelloSafari_Auto,
		utls.HelloIOS_Auto,
	}
	randomFingerprint = modernFingerprints[rand.Intn(len(modernFingerprints))]

	// A randomized hello always offers TLS 1.3 and never leads its key shares
	// with P-256: uTLS cannot build every randomized P-256-first hello, and a
	// TLS 1.2-only hello stands out among modern clients. The seed is fixed per
	// process so every connection presents the same randomized fingerprint.
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	randomizedFingerprint = utls.HelloRandomized
	randomizedFingerprint.Seed, _ = utls.NewPRNGSeed()
	randomizedFingerprint.Weights = &weights
}

// ClientHelloID returns the ClientHelloID for a fingerprint name; an empty
// name selects chrome. Names are case-insensitive.
func ClientHelloID(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk":
		fallthrough
	case "chrome", "":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "360":
		return utls.Hello360_Auto, nil
	case "qq":
		return utls.HelloQQ_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "random":
		return randomFingerprint, nil
	case "randomized":
		return randomizedFingerprint, nil
	default:
		return utls.ClientHelloID{}, E.New("unknown uTLS fingerprint: ", name)
	}
}
