package sniff_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// recordClientHello captures the first flight of a default crypto/tls client,
// which offers an X25519MLKEM768 key share.
func recordClientHello(t testing.TB, serverName string) []byte {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		_ = tls.Client(clientConn, &tls.Config{ServerName: serverName}).Handshake()
		_ = clientConn.Close()
	}()
	var record bytes.Buffer
	header := make([]byte, 5)
	_, err := io.ReadFull(serverConn, header)
	require.NoError(t, err)
	record.Write(header)
	length := int(header[3])<<8 | int(header[4])
	_, err = io.CopyN(&record, serverConn, int64(length))
	require.NoError(t, err)
	return record.Bytes()
}

func TestSniffTLSClientHello(t *testing.T) {
	t.Parallel()
	clientHello := recordClientHello(t, "example.com")
	var metadata adapter.InboundContext
	err := sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(clientHello))
	require.NoError(t, err)
	require.Equal(t, C.ProtocolTLS, metadata.Protocol)
	require.Equal(t, "example.com", metadata.SniffHost)
}

func TestSniffTLSClientHelloIncomplete(t *testing.T) {
	t.Parallel()
	clientHello := recordClientHello(t, "example.com")
	var metadata adapter.InboundContext
	err := sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(clientHello[:len(clientHello)/2]))
	require.True(t, errors.Is(err, sniff.ErrNeedMoreData), err)
}

func BenchmarkSniffTLSClientHello(b *testing.B) {
	clientHello := recordClientHello(b, "example.com")
	b.ReportAllocs()
	for b.Loop() {
		var metadata adapter.InboundContext
		if err := sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(clientHello)); err != nil {
			b.Fatal(err)
		}
	}
}
