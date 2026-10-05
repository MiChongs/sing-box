package encryption

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

const testPadding = "100-111-1111.75-0-111.50-0-3333"

func generateKeys(t *testing.T, kinds ...string) (serverKeys string, clientKeys string) {
	t.Helper()
	var serverKeyList, clientKeyList []string
	for _, kind := range kinds {
		var (
			serverKey, clientKey string
			err                  error
		)
		switch kind {
		case "x25519":
			serverKey, clientKey, err = GenerateX25519("")
		case "mlkem768":
			serverKey, clientKey, err = GenerateMLKEM768("")
		default:
			t.Fatal("unknown key kind: ", kind)
		}
		require.NoError(t, err)
		serverKeyList = append(serverKeyList, serverKey)
		clientKeyList = append(clientKeyList, clientKey)
	}
	return strings.Join(serverKeyList, "."), strings.Join(clientKeyList, ".")
}

func newTestInstances(t *testing.T, mode string, ticket string, rtt string, padding string, kinds ...string) (*ServerInstance, *ClientInstance) {
	t.Helper()
	serverKeys, clientKeys := generateKeys(t, kinds...)
	paddingPart := ""
	if padding != "" {
		paddingPart = padding + "."
	}
	server, err := NewServer("mlkem768x25519plus." + mode + "." + ticket + "." + paddingPart + serverKeys)
	require.NoError(t, err)
	t.Cleanup(func() {
		server.Close()
	})
	client, err := NewClient("mlkem768x25519plus." + mode + "." + rtt + "." + paddingPart + clientKeys)
	require.NoError(t, err)
	return server, client
}

type serverResult struct {
	conn *CommonConn
	err  error
}

func startServer(t *testing.T, server *ServerInstance, handle func(conn *CommonConn)) (string, <-chan serverResult) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	results := make(chan serverResult, 16)
	var wg sync.WaitGroup
	t.Cleanup(func() {
		listener.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				commonConn, err := server.Handshake(conn)
				if err != nil {
					conn.Close()
					results <- serverResult{err: err}
					return
				}
				results <- serverResult{conn: commonConn}
				if handle != nil {
					handle(commonConn)
				}
				commonConn.Close()
			}()
		}
	}()
	return listener.Addr().String(), results
}

func echo(conn *CommonConn) {
	io.Copy(conn, conn)
}

func dialClient(t *testing.T, client *ClientInstance, address string) *CommonConn {
	t.Helper()
	rawConn, err := net.Dial("tcp", address)
	require.NoError(t, err)
	conn, err := client.Handshake(rawConn)
	require.NoError(t, err)
	t.Cleanup(func() {
		conn.Close()
	})
	return conn
}

func testEcho(t *testing.T, conn net.Conn, size int) {
	t.Helper()
	payload := make([]byte, size)
	_, err := rand.Read(payload)
	require.NoError(t, err)
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeErr <- err
	}()
	received := make([]byte, size)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = io.ReadFull(conn, received)
	require.NoError(t, err)
	require.NoError(t, <-writeErr)
	require.True(t, bytes.Equal(payload, received))
}

func TestHandshake(t *testing.T) {
	t.Parallel()
	for _, kinds := range [][]string{{"x25519"}, {"mlkem768"}, {"x25519", "mlkem768"}} {
		for _, mode := range []string{"native", "xorpub", "random"} {
			for _, rtt := range []string{"1rtt", "0rtt"} {
				for _, padding := range []string{"", testPadding} {
					kinds, mode, rtt, padding := kinds, mode, rtt, padding
					name := strings.Join(kinds, "+") + "/" + mode + "/" + rtt
					if padding != "" {
						name += "/padding"
					}
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						server, client := newTestInstances(t, mode, "600s", rtt, padding, kinds...)
						address, results := startServer(t, server, echo)
						for i := 0; i < 3; i++ {
							conn := dialClient(t, client, address)
							if rtt == "0rtt" && i > 0 {
								require.NotNil(t, conn.preWrite, "expected 0-RTT resumption")
							} else {
								require.Nil(t, conn.preWrite)
							}
							for _, size := range []int{1, 100, maxRecordData, maxRecordData + 1, 70000} {
								testEcho(t, conn, size)
							}
							result := <-results
							require.NoError(t, result.err)
						}
					})
				}
			}
		}
	}
}

func TestHandshakeServerWithout0RTT(t *testing.T) {
	t.Parallel()
	server, client := newTestInstances(t, "native", "0s", "0rtt", "", "x25519")
	address, results := startServer(t, server, echo)
	for i := 0; i < 2; i++ {
		conn := dialClient(t, client, address)
		require.Nil(t, conn.preWrite, "server without tickets must keep the client on 1-RTT")
		testEcho(t, conn, 1000)
		require.NoError(t, (<-results).err)
	}
}

func TestHandshakeExpiredTicket(t *testing.T) {
	t.Parallel()
	serverKeys, clientKeys := generateKeys(t, "x25519")
	client, err := NewClient("mlkem768x25519plus.random.0rtt." + clientKeys)
	require.NoError(t, err)
	server, err := NewServer("mlkem768x25519plus.random.600s." + serverKeys)
	require.NoError(t, err)
	defer server.Close()
	address, results := startServer(t, server, echo)
	conn := dialClient(t, client, address)
	testEcho(t, conn, 1000)
	require.NoError(t, (<-results).err)

	// a restarted server does not know the ticket issued before
	restartedServer, err := NewServer("mlkem768x25519plus.random.600s." + serverKeys)
	require.NoError(t, err)
	defer restartedServer.Close()
	address, results = startServer(t, restartedServer, echo)
	conn = dialClient(t, client, address)
	require.NotNil(t, conn.preWrite)
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	require.ErrorContains(t, (<-results).err, "expired ticket")
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = conn.Read(make([]byte, 64))
	require.True(t, errors.Is(err, errNewHandshakeNeeded), err)

	conn = dialClient(t, client, address)
	require.Nil(t, conn.preWrite, "client must fall back to 1-RTT after an expired ticket")
	testEcho(t, conn, 1000)
	require.NoError(t, (<-results).err)
}

type recordConn struct {
	net.Conn
	access  sync.Mutex
	written []byte
}

func (c *recordConn) Write(b []byte) (int, error) {
	c.access.Lock()
	c.written = append(c.written, b...)
	c.access.Unlock()
	return c.Conn.Write(b)
}

func TestHandshakeReplay(t *testing.T) {
	t.Parallel()
	server, client := newTestInstances(t, "native", "600s", "0rtt", "", "x25519")
	address, results := startServer(t, server, echo)
	conn := dialClient(t, client, address)
	testEcho(t, conn, 1000)
	require.NoError(t, (<-results).err)

	rawConn, err := net.Dial("tcp", address)
	require.NoError(t, err)
	recorder := &recordConn{Conn: rawConn}
	conn, err = client.Handshake(recorder)
	require.NoError(t, err)
	defer conn.Close()
	testEcho(t, conn, 1000)
	require.NoError(t, (<-results).err)

	replayConn, err := net.Dial("tcp", address)
	require.NoError(t, err)
	defer replayConn.Close()
	recorder.access.Lock()
	_, err = replayConn.Write(recorder.written)
	recorder.access.Unlock()
	require.NoError(t, err)
	require.ErrorContains(t, (<-results).err, "replay detected")
}

func TestConfig(t *testing.T) {
	t.Parallel()
	serverKey, clientKey := generateKeys(t, "x25519")
	seed, mlkemClientKey := generateKeys(t, "mlkem768")
	for _, value := range []string{"", "none"} {
		client, err := NewClient(value)
		require.NoError(t, err)
		require.Nil(t, client)
		server, err := NewServer(value)
		require.NoError(t, err)
		require.Nil(t, server)
	}
	for _, value := range []string{
		"mlkem768x25519plus.native.0rtt." + clientKey,
		"mlkem768x25519plus.xorpub.1rtt." + mlkemClientKey,
		"mlkem768x25519plus.random.0rtt." + testPadding + "." + clientKey + "." + mlkemClientKey,
	} {
		client, err := NewClient(value)
		require.NoError(t, err, value)
		require.NotNil(t, client)
	}
	for _, value := range []string{
		"mlkem768x25519plus.native.600s." + serverKey,
		"mlkem768x25519plus.xorpub.300-600s." + seed,
		"mlkem768x25519plus.random.0s." + testPadding + "." + serverKey + "." + seed,
	} {
		server, err := NewServer(value)
		require.NoError(t, err, value)
		require.NotNil(t, server)
		server.Close()
	}
	for _, value := range []string{
		"aes-128-gcm",
		"mlkem768x25519plus.native.0rtt",
		"mlkem768x25519plus.unknown.0rtt." + clientKey,
		"mlkem768x25519plus.native.2rtt." + clientKey,
		"mlkem768x25519plus.native.0rtt." + serverKey + "x",
		"mlkem768x25519plus.native.0rtt." + seed,
		"mlkem768x25519plus.native.0rtt.10-111-1111." + clientKey,
		"mlkem768x25519plus.native.0rtt." + clientKey + ".100-111-1111",
		"mlkem768x25519plus.native.0rtt.100-111-1111",
	} {
		_, err := NewClient(value)
		require.Error(t, err, value)
	}
	for _, value := range []string{
		"mlkem768x25519plus.native.0rtt." + serverKey,
		"mlkem768x25519plus.native.600s." + mlkemClientKey,
	} {
		_, err := NewServer(value)
		require.Error(t, err, value)
	}
}

func TestGenerateKeys(t *testing.T) {
	t.Parallel()
	privateKey, password, err := GenerateX25519("")
	require.NoError(t, err)
	samePrivateKey, samePassword, err := GenerateX25519(privateKey)
	require.NoError(t, err)
	require.Equal(t, privateKey, samePrivateKey)
	require.Equal(t, password, samePassword)
	seed, client, err := GenerateMLKEM768("")
	require.NoError(t, err)
	sameSeed, sameClient, err := GenerateMLKEM768(seed)
	require.NoError(t, err)
	require.Equal(t, seed, sameSeed)
	require.Equal(t, client, sameClient)
}

type visionTestHandler struct {
	tlsConfig *tls.Config
}

func (h *visionTestHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	tlsConn := tls.Server(conn, h.tlsConfig)
	io.Copy(tlsConn, tlsConn)
}

func (h *visionTestHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
}

func newTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.org"},
		DNSNames:     []string{"example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{certificate}, PrivateKey: privateKey}
}

func nonceCount(aead *aeadCipher) uint64 {
	return binary.BigEndian.Uint64(aead.nonce[4:])
}

// TestVision runs XTLS Vision over VLESS Encryption on a plain TCP transport,
// which has no TLS for Vision to work on, the same situation as XHTTP.
func TestVision(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"native", "xorpub", "random"} {
		for _, rtt := range []string{"1rtt", "0rtt"} {
			mode, rtt := mode, rtt
			t.Run(mode+"/"+rtt, func(t *testing.T) {
				t.Parallel()
				testVision(t, mode, rtt)
			})
		}
	}
}

func testVision(t *testing.T, mode string, rtt string) {
	server, client := newTestInstances(t, mode, "600s", rtt, testPadding, "x25519")
	user := uuid.Must(uuid.NewV4()).String()
	service := vless.NewService[int](logger.NOP(), &visionTestHandler{
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{newTestCertificate(t)}},
	})
	service.UpdateUsers([]int{0}, []string{user}, []string{vless.FlowVision})
	address, results := startServer(t, server, func(conn *CommonConn) {
		err := service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), func(error) {})
		if err != nil {
			t.Error(err)
		}
	})
	vlessClient, err := vless.NewClient(user, vless.FlowVision, logger.NOP())
	require.NoError(t, err)

	for i := 0; i < 2; i++ {
		commonConn := dialClient(t, client, address)
		visionConn, err := vlessClient.DialEarlyConn(commonConn, M.ParseSocksaddr("example.org:443"))
		require.NoError(t, err)
		tlsConn := tls.Client(visionConn, &tls.Config{
			ServerName:         "example.org",
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		})
		require.NoError(t, tlsConn.Handshake())
		const size = 4 << 20
		testEcho(t, tlsConn, size)
		require.NoError(t, (<-results).err)
		// Vision must have switched to direct copy: the inner TLS records
		// skip the encryption layer instead of costing a record each.
		require.Less(t, nonceCount(commonConn.aead), uint64(32))
		require.Less(t, nonceCount(commonConn.peerAEAD), uint64(32))
		tlsConn.Close()
	}
}
