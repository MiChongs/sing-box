package v2rayxhttp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// closeHandler 像代理转发循环一样回显数据，读写出错即关闭连接并上报该错误。
// closeAfterEcho 时回显第一段数据后由服务端主动关闭；synchronous 时像 VLESS
// 的 mux / XUDP 一样在 NewConnectionEx 里同步处理整条连接。
type closeHandler struct {
	closeAfterEcho bool
	synchronous    bool
	errs           chan error
}

func newCloseHandler(closeAfterEcho bool) *closeHandler {
	return &closeHandler{closeAfterEcho: closeAfterEcho, errs: make(chan error, 16)}
}

func (h *closeHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if h.synchronous {
		h.serve(conn, onClose)
	} else {
		go h.serve(conn, onClose)
	}
}

func (h *closeHandler) serve(conn net.Conn, onClose N.CloseHandlerFunc) {
	buffer := make([]byte, 32*1024)
	var err error
	for {
		var n int
		n, err = conn.Read(buffer)
		if err != nil {
			break
		}
		if _, err = conn.Write(buffer[:n]); err != nil || h.closeAfterEcho {
			break
		}
	}
	_ = conn.Close()
	onClose(err)
	h.errs <- err
}

func (h *closeHandler) next(t *testing.T) error {
	t.Helper()
	select {
	case err := <-h.errs:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("server connection did not finish")
		return nil
	}
}

func requireNormalClose(t *testing.T, side string, err error) {
	t.Helper()
	if err != nil && err != io.EOF && !E.IsClosedOrCanceled(err) {
		t.Fatalf("%s: %q is reported as a connection error", side, err)
	}
	t.Logf("%s: %v", side, err)
}

func echoHello(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Time{})
}

// checkTunnelClose: 隧道由任一端关闭时，另一端看到的都应是正常关闭，
// 而不是 "H3_REQUEST_CANCELLED"、"stream error: ...; CANCEL" 这类连接错误。
func checkTunnelClose(t *testing.T, startServer func(t *testing.T, handler adapter.V2RayServerTransportHandler) M.Socksaddr, newTLSClient func(t *testing.T) boxtls.Config) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			for _, synchronous := range []bool{false, true} {
				name := "client closes"
				if synchronous {
					// 回归: packet-up 的上行队列与请求无关，同步 handler 曾永远等不到
					// 连接关闭，会话泄漏，HTTP/3 Server.Close 也随之卡住。
					name += " synchronous handler"
				}
				t.Run(name, func(t *testing.T) {
					handler := newCloseHandler(false)
					handler.synchronous = synchronous
					client := newTestClient(t, &option.V2RayXHTTPOptions{Path: "/xhttp", Mode: mode}, startServer(t, handler), newTLSClient(t))
					for range 3 {
						conn, err := client.DialContext(context.Background())
						if err != nil {
							t.Fatal(err)
						}
						echoHello(t, conn)
						_ = conn.Close()
						requireNormalClose(t, "server", handler.next(t))
					}
				})
			}
			t.Run("server closes", func(t *testing.T) {
				handler := newCloseHandler(true)
				client := newTestClient(t, &option.V2RayXHTTPOptions{Path: "/xhttp", Mode: mode}, startServer(t, handler), newTLSClient(t))
				for range 3 {
					conn, err := client.DialContext(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					echoHello(t, conn)
					requireNormalClose(t, "server", handler.next(t))
					_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
					_, err = conn.Read(make([]byte, 1))
					requireNormalClose(t, "client", err)
					_ = conn.Close()
				}
			})
		})
	}
}

func startCloseTestServer(tlsConfig func(t *testing.T) boxtls.ServerConfig) func(t *testing.T, handler adapter.V2RayServerTransportHandler) M.Socksaddr {
	return func(t *testing.T, handler adapter.V2RayServerTransportHandler) M.Socksaddr {
		t.Helper()
		server, err := NewServer(context.Background(), logger.NOP(), &option.V2RayXHTTPOptions{Path: "/xhttp"}, tlsConfig(t), handler)
		if err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go server.Serve(listener)
		t.Cleanup(func() {
			_ = server.Close()
			_ = listener.Close()
		})
		return M.SocksaddrFromNet(listener.Addr())
	}
}

func TestE2E_TunnelClose(t *testing.T) {
	t.Run("http1", func(t *testing.T) {
		checkTunnelClose(t,
			startCloseTestServer(func(*testing.T) boxtls.ServerConfig { return nil }),
			func(*testing.T) boxtls.Config { return nil })
	})
	t.Run("http2", func(t *testing.T) {
		checkTunnelClose(t,
			startCloseTestServer(func(t *testing.T) boxtls.ServerConfig { return newTestTLSServer(t) }),
			func(t *testing.T) boxtls.Config { return newTestTLSClient(t, "example.com") })
	})
}
