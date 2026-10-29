//go:build !with_quic

package main

import (
	"context"
	"crypto/x509"

	C "github.com/sagernet/sing-box/constant"
)

func inspectCertQUIC(ctx context.Context, host string, portStr string, port uint64, sni string) ([]*x509.Certificate, string, error) {
	return nil, "", C.ErrQUICNotIncluded
}