package quic

// Recommended QUIC transport parameters aligned with the locked upstream Vector
// (configure_quic_transport). Host backends should apply these defaults when
// constructing their concrete quic-go / sing-quic configs.
const (
	RecommendedStreamReceiveWindow     uint64 = 16 * 1024 * 1024
	RecommendedConnectionReceiveWindow uint64 = 32 * 1024 * 1024
	RecommendedSendWindow              uint64 = 32 * 1024 * 1024
	RecommendedDatagramBufferSize      uint64 = 4 * 1024 * 1024
)
