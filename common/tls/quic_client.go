package tls

import (
	"context"
)

// QUIC 握手由 quic-go 基于 crypto/tls 完成，只能取 STDConfig，uTLS 的 ClientHello
// 指纹无从套用。与 Xray (QUIC 一律使用 GetTLSConfig) 和 mihomo 一致，QUIC 场景下
// 忽略 fingerprint，退回等价的标准库配置；证书校验、SNI、ALPN、ECH 等其余设置不变。

type stdClientConvertible interface {
	stdClientConfig() *STDClientConfig
}

// QUICClientConfig 返回可用于 QUIC 握手的等价客户端配置，不修改传入的 config。
func QUICClientConfig(config Config) (Config, error) {
	switch typedConfig := config.(type) {
	case nil:
		return nil, nil
	case stdClientConvertible:
		return typedConfig.stdClientConfig(), nil
	case *KTLSClientConfig:
		// kTLS 只作用于 TCP 连接。
		return QUICClientConfig(typedConfig.Config)
	case *ECHClientConfig:
		innerConfig, err := QUICClientConfig(typedConfig.ECHCapableConfig)
		if err != nil {
			return nil, err
		}
		return &ECHClientConfig{
			ECHCapableConfig: innerConfig.(ECHCapableConfig),
			dnsRouter:        typedConfig.dnsRouter,
			queryServerName:  typedConfig.queryServerName,
		}, nil
	}
	_, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	return config, nil
}

// QUICDialConfig 返回单次 QUIC 拨号使用的配置。ECH 配置来自 DNS 时，TCP 握手由
// ClientHandshake 按需刷新，QUIC 握手绕过了它，这里补上刷新并返回独立副本，
// 避免与并发刷新竞争。
func QUICDialConfig(ctx context.Context, config Config) (Config, error) {
	echConfig, isECH := config.(*ECHClientConfig)
	if !isECH {
		return config, nil
	}
	echConfig.access.Lock()
	defer echConfig.access.Unlock()
	err := echConfig.fetchECHConfigList(ctx)
	if err != nil {
		return nil, err
	}
	return echConfig.ECHCapableConfig.Clone(), nil
}
