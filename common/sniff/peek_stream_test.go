package sniff_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

// Payload read by an earlier sniff is sniffed without reading the connection
// again: the client is waiting for the server and sends nothing more.
func TestPeekStreamBufferedPayload(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	previous := buf.As([]byte("GET / HTTP/1.1\r\nHost: buffered.example\r\n\r\n"))
	buffer := buf.NewPacket()
	defer buffer.Release()
	var metadata adapter.InboundContext
	start := time.Now()
	err := sniff.PeekStream(context.Background(), &metadata, server, []*buf.Buffer{previous}, buffer, 0, sniff.TLSClientHello, sniff.HTTPHost)
	require.NoError(t, err)
	require.Equal(t, "buffered.example", metadata.SniffHost)
	require.True(t, buffer.IsEmpty(), "nothing more was read")
	require.Less(t, time.Since(start), C.ReadPayloadTimeout)
}

// A buffered prefix that needs more data is completed from the connection.
func TestPeekStreamBufferedNeedsMoreData(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	previous := buf.As([]byte("GET / HTTP/1.1\r\nHost: split"))
	go client.Write([]byte(".example\r\n\r\n"))
	buffer := buf.NewPacket()
	defer buffer.Release()
	var metadata adapter.InboundContext
	err := sniff.PeekStream(context.Background(), &metadata, server, []*buf.Buffer{previous}, buffer, 0, sniff.HTTPHost)
	require.NoError(t, err)
	require.Equal(t, "split.example", metadata.SniffHost)
	require.Equal(t, ".example\r\n\r\n", string(buffer.Bytes()))
}

// Without buffered payload a silent connection still reports the read error.
func TestPeekStreamSilentConnection(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	buffer := buf.NewPacket()
	defer buffer.Release()
	var metadata adapter.InboundContext
	err := sniff.PeekStream(context.Background(), &metadata, server, nil, buffer, 50*time.Millisecond, sniff.HTTPHost)
	require.Error(t, err)
	require.ErrorContains(t, err, "read payload")
}
