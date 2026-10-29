//go:build with_quic

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

var _ aTLS.Config = (*quicTLSConfig)(nil)

type quicTLSConfig struct {
	*tls.Config
	timeout time.Duration
}

func (c *quicTLSConfig) Client(conn net.Conn) (aTLS.Conn, error) {
	return tls.Client(conn, c.Config), nil
}

func (c *quicTLSConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	tlsConn := tls.Client(conn, c.Config)
	return tlsConn, tlsConn.HandshakeContext(ctx)
}

func (c *quicTLSConfig) STDConfig() (*tls.Config, error) {
	return c.Config.Clone(), nil
}

func (c *quicTLSConfig) Clone() aTLS.Config {
	return &quicTLSConfig{
		Config:  c.Config.Clone(),
		timeout: c.timeout,
	}
}

func (c *quicTLSConfig) ServerName() string {
	return c.Config.ServerName
}

func (c *quicTLSConfig) SetServerName(serverName string) {
	c.Config.ServerName = serverName
}

func (c *quicTLSConfig) NextProtos() []string {
	return c.Config.NextProtos
}

func (c *quicTLSConfig) SetNextProtos(nextProto []string) {
	c.Config.NextProtos = nextProto
}

func (c *quicTLSConfig) HandshakeTimeout() time.Duration {
	return c.timeout
}

func (c *quicTLSConfig) SetHandshakeTimeout(timeout time.Duration) {
	c.timeout = timeout
}

func inspectCertQUIC(ctx context.Context, host string, portStr string, port uint64, sni string) ([]*x509.Certificate, string, error) {
	var (
		udpConn net.Conn
		err     error
	)
	if commandToolsFlagOutbound != "" {
		instance, err := createPreStartedClient()
		if err != nil {
			return nil, "", err
		}
		defer instance.Close()
		dialer, err := createDialer(instance, commandToolsFlagOutbound)
		if err != nil {
			return nil, "", err
		}
		udpConn, err = dialer.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddrHostPort(host, uint16(port)))
		if err != nil {
			return nil, "", E.Cause(err, "dial outbound udp ", commandToolsFlagOutbound)
		}
	} else {
		instance, err := createPreStartedClient()
		if err == nil {
			defer instance.Close()
			dialer, err := createDialer(instance, "")
			if err == nil {
				udpConn, _ = dialer.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddrHostPort(host, uint16(port)))
			}
		}
		if udpConn == nil {
			dialer := &net.Dialer{Timeout: toolsCertTimeout}
			udpConn, err = dialer.DialContext(ctx, "udp", net.JoinHostPort(host, portStr))
			if err != nil {
				return nil, "", E.Cause(err, "dial udp")
			}
		}
	}
	defer udpConn.Close()

	qtls.SetDesiredBufferSizes(udpConn)

	tlsConfig := &quicTLSConfig{
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
		timeout: toolsCertTimeout,
	}

	quicConfig := &quic.Config{
		HandshakeIdleTimeout: toolsCertTimeout,
	}

	qConn, err := qtls.Dial(ctx, udpConn, tlsConfig, quicConfig)
	if err != nil {
		return nil, "", E.Cause(err, "quic dial")
	}
	defer qConn.CloseWithError(quic.ApplicationErrorCode(0), "")

	state := qConn.ConnectionState()
	versionStr := "QUIC (TLS 1.3)"
	return state.TLS.PeerCertificates, versionStr, nil
}