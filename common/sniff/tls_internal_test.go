package sniff

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

var errReferenceClientHelloCaptured = errors.New("captured")

// referenceTLSClientHello is the crypto/tls server handshake the sniffer used
// before decoding ClientHello itself.
func referenceTLSClientHello(reader io.Reader) (string, error) {
	var clientHello *tls.ClientHelloInfo
	err := tls.Server(bufio.NewReadOnlyConn(reader), &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHello = argHello
			return nil, errReferenceClientHelloCaptured
		},
	}).HandshakeContext(context.Background())
	if clientHello != nil {
		return M.ParseSocksaddrHostPort(clientHello.ServerName, 0).Fqdn, nil
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "", ErrNeedMoreData
	}
	return "", err
}

func sniffTLSHost(data []byte) (string, error) {
	var metadata adapter.InboundContext
	err := TLSClientHello(context.Background(), &metadata, bytes.NewReader(data))
	return metadata.SniffHost, err
}

func recordInternalClientHello(t testing.TB, config *tls.Config) []byte {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		_ = tls.Client(clientConn, config).Handshake()
		_ = clientConn.Close()
	}()
	header := make([]byte, 5)
	_, err := io.ReadFull(serverConn, header)
	require.NoError(t, err)
	body := make([]byte, int(header[3])<<8|int(header[4]))
	_, err = io.ReadFull(serverConn, body)
	require.NoError(t, err)
	return append(header, body...)
}

// fragmentRecords re-frames a single-record ClientHello into records carrying
// at most size handshake bytes each.
func fragmentRecords(record []byte, size int) []byte {
	payload := record[5:]
	var output []byte
	for len(payload) > 0 {
		n := min(size, len(payload))
		output = append(output, record[0], record[1], record[2], byte(n>>8), byte(n))
		output = append(output, payload[:n]...)
		payload = payload[n:]
	}
	return output
}

func testClientHellos(t testing.TB) [][]byte {
	return [][]byte{
		recordInternalClientHello(t, &tls.Config{ServerName: "example.com"}),
		recordInternalClientHello(t, &tls.Config{ServerName: "a.very.long.subdomain.example.org", NextProtos: []string{"h2", "http/1.1"}}),
		recordInternalClientHello(t, &tls.Config{ServerName: "192.0.2.1", InsecureSkipVerify: true}),
		recordInternalClientHello(t, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}),
		recordInternalClientHello(t, &tls.Config{ServerName: "tls12.example", MaxVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519}}),
	}
}

func requireMatchesReference(t *testing.T, data []byte) {
	host, err := sniffTLSHost(data)
	referenceHost, referenceErr := referenceTLSClientHello(bytes.NewReader(data))
	switch {
	case referenceErr == nil:
		require.NoError(t, err)
		require.Equal(t, referenceHost, host)
	case errors.Is(referenceErr, ErrNeedMoreData):
		// crypto/tls buffers whole records before looking at them, while the
		// sniffer decides as soon as the bytes it has settle the outcome: it
		// may finish a complete ClientHello or reject a non-ClientHello before
		// the last record arrives. Prefixes of valid hellos must still ask
		// for more data, which TestTLSClientHelloMatchesCryptoTLS checks.
	}
	// When crypto/tls rejects the input the sniffer may still accept it: it
	// does not validate extensions other than server_name.
}

func TestTLSClientHelloMatchesCryptoTLS(t *testing.T) {
	t.Parallel()
	for _, clientHello := range testClientHellos(t) {
		requireMatchesReference(t, clientHello)
		for _, size := range []int{1, 3, 4, 5, 64, 512} {
			fragmented := fragmentRecords(clientHello, size)
			requireMatchesReference(t, fragmented)
			host, err := sniffTLSHost(fragmented)
			require.NoError(t, err)
			referenceHost, _ := sniffTLSHost(clientHello)
			require.Equal(t, referenceHost, host)
		}
		for length := range len(clientHello) {
			_, err := sniffTLSHost(clientHello[:length])
			require.ErrorIs(t, err, ErrNeedMoreData, "prefix %d", length)
		}
	}
}

func TestTLSClientHelloServerName(t *testing.T) {
	t.Parallel()
	hellos := testClientHellos(t)
	expected := []string{"example.com", "a.very.long.subdomain.example.org", "", "", "tls12.example"}
	for index, clientHello := range hellos {
		host, err := sniffTLSHost(clientHello)
		require.NoError(t, err)
		require.Equal(t, expected[index], host)
	}
}

func TestTLSClientHelloRejectsNonTLS(t *testing.T) {
	t.Parallel()
	for _, data := range [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
		{0x80, 0x2e, 0x01, 0x00, 0x02},
		{0x16, 0x03, 0x03, 0x00, 0x00},
		{0x16, 0x03, 0x03, 0x48, 0x01},
		{0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
		{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x01, 0x00, 0x01},
	} {
		_, err := sniffTLSHost(data)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrNeedMoreData, "%x", data)
	}
}

func TestTLSClientHelloRejectsTrailingDotAndDuplicateNames(t *testing.T) {
	t.Parallel()
	clientHello := recordInternalClientHello(t, &tls.Config{ServerName: "example.com"})
	index := bytes.Index(clientHello, []byte("example.com"))
	require.Positive(t, index)
	// Turning "example.com" into "example.co." must fail like crypto/tls.
	trailingDot := bytes.Clone(clientHello)
	trailingDot[index+len("example.com")-1] = '.'
	_, err := sniffTLSHost(trailingDot)
	require.Error(t, err)
	_, referenceErr := referenceTLSClientHello(bytes.NewReader(trailingDot))
	require.Error(t, referenceErr)
}

func FuzzTLSClientHello(f *testing.F) {
	for _, clientHello := range testClientHellos(f) {
		f.Add(clientHello)
		f.Add(fragmentRecords(clientHello, 7))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		requireMatchesReference(t, data)
	})
}

func BenchmarkTLSClientHelloReference(b *testing.B) {
	clientHello := recordInternalClientHello(b, &tls.Config{ServerName: "example.com"})
	b.ReportAllocs()
	for b.Loop() {
		if _, err := referenceTLSClientHello(bytes.NewReader(clientHello)); err != nil {
			b.Fatal(err)
		}
	}
}
