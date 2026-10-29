package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
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

	rawConn, err := net.DialTimeout("unix", entrySocket, 5*time.Second)
	require.NoError(t, err)
	defer rawConn.Close()
	rawConn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = socks.ClientHandshake5(rawConn, socks.CommandConnect, M.SocksaddrFromNet(echoListener.Addr()), "", "")
	require.NoError(t, err)
	_, err = rawConn.Write([]byte("unix socket"))
	require.NoError(t, err)
	response := make([]byte, len("unix socket"))
	_, err = io.ReadFull(rawConn, response)
	require.NoError(t, err)
	require.Equal(t, "unix socket", string(response))
}
