package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
)

// A mixed inbound listens on a unix socket and relays through a socks outbound
// that dials another mixed inbound over a unix socket.
func TestUnixSocketListenAndDial(t *testing.T) {
	directory, err := os.MkdirTemp("", "sbuds")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(directory) })
	entrySocket := filepath.Join(directory, "entry.sock")
	relaySocket := filepath.Join(directory, "relay.sock")

	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer echoListener.Close()
	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	content := []byte(`{
  "log": {"level": "warning"},
  "inbounds": [
    {"type": "mixed", "tag": "entry", "listen": "` + entrySocket + `,0600"},
    {"type": "mixed", "tag": "relay", "listen": "unix:` + relaySocket + `"}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "socks", "tag": "via-relay", "server": "` + relaySocket + `"}
  ],
  "route": {
    "rules": [{"inbound": ["entry"], "outbound": "via-relay"}],
    "final": "direct"
  }
}`)
	options, err := json.UnmarshalExtendedContext[option.Options](globalCtx, content)
	require.NoError(t, err)
	startInstance(t, options)

	info, err := os.Stat(entrySocket)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	_, err = os.Stat(relaySocket)
	require.NoError(t, err)

	client := socks.NewClient(unixSocketDialer(entrySocket), M.Socksaddr{Fqdn: entrySocket}, socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rawConn, err := client.DialContext(ctx, N.NetworkTCP, M.SocksaddrFromNet(echoListener.Addr()))
	require.NoError(t, err)
	defer rawConn.Close()
	rawConn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = rawConn.Write([]byte("unix socket"))
	require.NoError(t, err)
	response := make([]byte, len("unix socket"))
	_, err = io.ReadFull(rawConn, response)
	require.NoError(t, err)
	require.Equal(t, "unix socket", string(response))
}

type unixSocketDialer string

func (d unixSocketDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "unix", string(d))
}

func (d unixSocketDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
