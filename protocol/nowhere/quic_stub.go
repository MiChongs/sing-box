//go:build !with_quic

package nowhere

import "github.com/sagernet/sing-box/protocol/nowhere/core/carrier"

const quicIncluded = false

func newQuicBackend(quicBackendOptions) carrier.QuicBackend { return nil }
